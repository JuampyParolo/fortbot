"""
FortBot Core — API bridge entre OpenClaw Gateway y las capas de seguridad.

OpenClaw Gateway ──HTTP──► FortBot Core ──► Guardian (evalúa)
                                        ──► Vault (inyecta credentials)
                                        ──► Audit (registra todo)
                                        ──► UI (notifica al usuario)

Cada acción del agente pasa por acá ANTES de ejecutarse.
"""

import json
import os
import asyncio
from datetime import datetime
from typing import Optional
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from guardian.engine import GuardianEngine, ActionContext, Verdict
from vault.credentials import CredentialVault, CredentialBroker, EgressFilter


# =============================================================================
# Models
# =============================================================================

class ActionRequest(BaseModel):
    """Request del OpenClaw gateway pidiendo evaluar una acción."""
    action_type: str          # "exec", "web_fetch", "write", "message", etc.
    action_content: str       # El comando, URL, contenido
    files_involved: list[str] = []
    network_targets: list[str] = []
    agent_id: str = "main"
    session_id: str = ""

class ActionResponse(BaseModel):
    """Respuesta de FortBot al gateway."""
    allowed: bool
    verdict: str              # "safe", "warning", "block"
    explanation: str
    risk_score: float
    requires_approval: bool   # Si True, el UI debe mostrar popup
    approval_id: Optional[str] = None  # ID para aprobar/rechazar

class ApprovalRequest(BaseModel):
    """Usuario aprueba o rechaza una acción desde la UI."""
    approval_id: str
    approved: bool
    user_note: str = ""

class CredentialStoreRequest(BaseModel):
    """Usuario guarda una credencial desde la UI."""
    name: str
    value: str
    description: str = ""
    credential_type: str = "api_key"


# =============================================================================
# State
# =============================================================================

# Pending approvals (actions waiting for user decision)
pending_approvals: dict[str, dict] = {}

# WebSocket connections for real-time UI updates
ui_connections: list[WebSocket] = []

# Audit log buffer
audit_buffer: list[dict] = []


# =============================================================================
# Audit Persistence
# =============================================================================

def _load_audit_from_disk(filepath: str):
    """Load audit entries from disk on startup."""
    global audit_buffer
    if os.path.exists(filepath):
        try:
            with open(filepath) as f:
                for line in f:
                    line = line.strip()
                    if line:
                        audit_buffer.append(json.loads(line))
            # Keep only last 10000 entries in memory
            if len(audit_buffer) > 10000:
                audit_buffer = audit_buffer[-10000:]
        except Exception as e:
            print(f"⚠️  Could not load audit log: {e}")

def _save_audit_to_disk(filepath: str):
    """Persist audit buffer to disk."""
    try:
        with open(filepath, "w") as f:
            for entry in audit_buffer[-10000:]:
                f.write(json.dumps(entry) + "\n")
    except Exception as e:
        print(f"⚠️  Could not save audit log: {e}")

def _append_audit(entry: dict):
    """Add entry to buffer and append to disk. Rotate if too large."""
    audit_buffer.append(entry)
    # Rotate in-memory buffer
    if len(audit_buffer) > 10000:
        audit_buffer[:] = audit_buffer[-10000:]
    try:
        filepath = getattr(app.state, 'audit_file', None)
        if filepath:
            with open(filepath, "a") as f:
                f.write(json.dumps(entry) + "\n")
            # Rotate disk file every 500 appends
            if len(audit_buffer) % 500 == 0:
                try:
                    line_count = sum(1 for _ in open(filepath))
                    if line_count > 12000:
                        _save_audit_to_disk(filepath)  # Rewrites with last 10K
                except Exception:
                    pass
    except Exception:
        pass  # Best-effort disk write


# =============================================================================
# Lifespan
# =============================================================================

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize components on startup."""
    
    # Try to create LLM provider for Guardian
    llm_provider = None
    try:
        from guardian.llm_provider import create_provider
        llm_provider = create_provider("auto")
        print("🧠 Guardian LLM provider: active")
    except RuntimeError as e:
        print(f"⚠️  Guardian LLM not available: {e}")
        print("   Using heuristic-only mode (still secure, less intelligent)")
    
    # Guardian
    app.state.guardian = GuardianEngine(
        llm_provider=llm_provider,
        model="haiku",
        max_history=50,
    )
    
    # Vault — try to load master password from env
    master_pw = os.environ.get("FORTBOT_VAULT_PASSWORD")
    app.state.vault = CredentialVault(
        vault_path="~/.fortbot/vault",
        master_password=master_pw,
    )
    app.state.broker = CredentialBroker(app.state.vault)
    app.state.egress_filter = EgressFilter(app.state.vault)
    
    # Persistent audit log
    app.state.audit_file = os.path.expanduser("~/.fortbot/audit.jsonl")
    os.makedirs(os.path.dirname(app.state.audit_file), exist_ok=True)
    _load_audit_from_disk(app.state.audit_file)
    
    print("🛡️  FortBot Guardian activo")
    print(f"🔐 Credential Vault {'encriptado' if master_pw else 'sin encriptación (set FORTBOT_VAULT_PASSWORD)'}")
    print("📡 Esperando conexiones...")
    
    yield
    
    # Persist audit on shutdown
    _save_audit_to_disk(app.state.audit_file)
    print("FortBot apagándose...")


# =============================================================================
# App
# =============================================================================

app = FastAPI(
    title="FortBot",
    description="Security layer para agentes AI",
    version="0.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://127.0.0.1:18790",   # Self (for UI served from same port)
    ],
    allow_methods=["GET", "POST", "DELETE"],
    allow_headers=["Content-Type"],
    allow_credentials=False,
)


# =============================================================================
# Endpoints — GUARDIAN
# =============================================================================

@app.post("/guardian/evaluate", response_model=ActionResponse)
async def evaluate_action(request: ActionRequest):
    """
    Endpoint principal: OpenClaw pregunta si una acción es segura.
    
    Flow:
    1. OpenClaw quiere ejecutar algo
    2. Llama a este endpoint ANTES de ejecutar
    3. Guardian evalúa y responde
    4. Si SAFE → OpenClaw ejecuta
    5. Si WARNING → UI muestra popup, espera aprobación
    6. Si BLOCK → OpenClaw NO ejecuta
    """
    guardian: GuardianEngine = app.state.guardian
    
    # Construir contexto
    context = ActionContext(
        action_type=request.action_type,
        action_content=request.action_content,
        recent_actions=list(guardian.action_history),
        files_involved=request.files_involved,
        network_targets=request.network_targets,
        agent_id=request.agent_id,
        session_id=request.session_id,
    )
    
    # --- Pre-check: credenciales en el output ---
    cred_detections = CredentialVault.detect_credentials(request.action_content)
    if cred_detections:
        # Si hay credenciales en la acción, el Guardian ni evalúa
        await _notify_ui("block", {
            "action": request.action_content[:200],
            "reason": "Credencial detectada en la acción",
            "detections": cred_detections,
        })
        
        return ActionResponse(
            allowed=False,
            verdict="block",
            explanation=f"Se detectaron {len(cred_detections)} posible(s) credencial(es) en la acción. Las credenciales nunca pueden incluirse en comandos o requests.",
            risk_score=1.0,
            requires_approval=False,
        )
    
    # --- Egress filter: si hay red, verificar que no se fuguen credentials ---
    if request.network_targets:
        egress_ok, egress_reason = app.state.egress_filter.check_outgoing(
            url=request.action_content,
            body=request.action_content,
        )
        if not egress_ok:
            await _notify_ui("block", {
                "action": request.action_content[:200],
                "reason": egress_reason,
            })
            
            return ActionResponse(
                allowed=False,
                verdict="block",
                explanation=egress_reason,
                risk_score=1.0,
                requires_approval=False,
            )
    
    # --- Guardian evaluation ---
    verdict = await guardian.evaluate(context)
    
    # --- Audit ---
    audit_entry = {
        "timestamp": datetime.now().isoformat(),
        "action_type": request.action_type,
        "action_content": request.action_content[:500],
        "verdict": verdict.verdict.value,
        "risk_score": verdict.risk_score,
        "explanation": verdict.explanation,
        "evaluation_ms": verdict.evaluation_ms,
    }
    _append_audit(audit_entry)
    
    # --- Notify UI ---
    await _notify_ui(verdict.verdict.value, {
        "action": request.action_content[:200],
        "explanation": verdict.explanation,
        "risk_score": verdict.risk_score,
    })
    
    # --- Response ---
    if verdict.verdict == Verdict.SAFE:
        return ActionResponse(
            allowed=True,
            verdict="safe",
            explanation=verdict.explanation,
            risk_score=verdict.risk_score,
            requires_approval=False,
        )
    
    elif verdict.verdict == Verdict.WARNING:
        # Crear pending approval
        approval_id = f"ap_{datetime.now().strftime('%Y%m%d%H%M%S')}_{len(pending_approvals)}"
        pending_approvals[approval_id] = {
            "request": request.model_dump(),
            "verdict": verdict.to_dict(),
            "created_at": datetime.now().isoformat(),
            "status": "pending",
        }
        
        return ActionResponse(
            allowed=False,
            verdict="warning",
            explanation=verdict.explanation,
            risk_score=verdict.risk_score,
            requires_approval=True,
            approval_id=approval_id,
        )
    
    else:  # BLOCK
        return ActionResponse(
            allowed=False,
            verdict="block",
            explanation=verdict.explanation,
            risk_score=verdict.risk_score,
            requires_approval=False,
        )


@app.post("/guardian/approve")
async def approve_action(request: ApprovalRequest):
    """Usuario aprueba o rechaza una acción pendiente."""
    if request.approval_id not in pending_approvals:
        raise HTTPException(404, "Approval no encontrado")
    
    approval = pending_approvals[request.approval_id]
    approval["status"] = "approved" if request.approved else "rejected"
    approval["resolved_at"] = datetime.now().isoformat()
    approval["user_note"] = request.user_note
    
    # Audit
    _append_audit({
        "timestamp": datetime.now().isoformat(),
        "action_type": "approval",
        "action_content": f"{'Aprobado' if request.approved else 'Rechazado'}: {request.approval_id}",
        "verdict": approval["status"],
        "risk_score": 0,
        "explanation": request.user_note,
        "evaluation_ms": 0,
    })
    
    await _notify_ui("approval_resolved", {
        "approval_id": request.approval_id,
        "approved": request.approved,
    })
    
    return {"status": approval["status"]}


@app.get("/guardian/pending")
async def get_pending_approvals():
    """Lista de acciones esperando aprobación del usuario."""
    return {
        k: v for k, v in pending_approvals.items() 
        if v["status"] == "pending"
    }


@app.get("/guardian/approval/{approval_id}")
async def get_approval_status(approval_id: str):
    """Estado de una aprobación específica (para polling del bridge TS)."""
    if approval_id not in pending_approvals:
        raise HTTPException(404, "Approval no encontrado")
    return {"status": pending_approvals[approval_id]["status"]}


@app.get("/guardian/stats")
async def get_guardian_stats():
    """Estadísticas del Guardian para la UI."""
    guardian: GuardianEngine = app.state.guardian
    return guardian.get_stats()


# =============================================================================
# Endpoints — CREDENTIAL VAULT
# =============================================================================

@app.get("/vault/list")
async def list_credentials():
    """Lista credenciales (nombres y metadata, NUNCA valores)."""
    vault: CredentialVault = app.state.vault
    return vault.list_credentials()


@app.post("/vault/store")
async def store_credential(request: CredentialStoreRequest):
    """Guarda una nueva credencial. SOLO desde UI."""
    vault: CredentialVault = app.state.vault
    try:
        vault.store(
            name=request.name,
            value=request.value,
            description=request.description,
            credential_type=request.credential_type,
        )
        return {"status": "stored", "name": request.name}
    except ValueError as e:
        raise HTTPException(400, str(e))


@app.delete("/vault/{name}")
async def delete_credential(name: str):
    """Elimina una credencial. SOLO desde UI."""
    vault: CredentialVault = app.state.vault
    if vault.delete(name):
        return {"status": "deleted"}
    raise HTTPException(404, "Credencial no encontrada")


@app.post("/vault/setup")
async def setup_vault(body: dict):
    """
    Configura la master password del vault.
    Solo funciona si el vault no tiene password todavía.
    """
    password = body.get("password", "")
    if not password or len(password) < 8:
        raise HTTPException(400, "Password debe tener al menos 8 caracteres")
    
    vault: CredentialVault = app.state.vault
    if vault._fernet is not None:
        raise HTTPException(400, "Vault ya tiene password configurada")
    
    vault._init_encryption(password)
    vault._save()
    
    return {"status": "configured", "message": "Vault encriptado con AES-256"}


@app.get("/vault/status")
async def vault_status():
    """Estado del vault — si tiene encriptación o no."""
    vault: CredentialVault = app.state.vault
    return {
        "encrypted": vault._fernet is not None,
        "credential_count": len(vault._metadata),
        "has_crypto_lib": HAS_CRYPTO if 'HAS_CRYPTO' in dir() else True,
    }


@app.post("/vault/detect")
async def detect_credentials_in_text(body: dict):
    """Detecta credenciales en un texto (para la UI)."""
    text = body.get("text", "")
    detections = CredentialVault.detect_credentials(text)
    return {"detections": detections}


# =============================================================================
# Endpoints — AUDIT
# =============================================================================

@app.get("/audit/recent")
async def get_recent_audit(limit: int = 50):
    """Últimas N entradas del audit log."""
    return audit_buffer[-limit:]


@app.get("/audit/stats")
async def get_audit_stats():
    """Estadísticas del audit para dashboard."""
    total = len(audit_buffer)
    if total == 0:
        return {"total": 0}
    
    verdicts = {}
    for entry in audit_buffer:
        v = entry.get("verdict", "unknown")
        verdicts[v] = verdicts.get(v, 0) + 1
    
    return {
        "total": total,
        "verdicts": verdicts,
        "avg_evaluation_ms": sum(e.get("evaluation_ms", 0) for e in audit_buffer) / total,
    }


# =============================================================================
# WebSocket — Real-time UI updates
# =============================================================================

@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    """WebSocket para actualizaciones en tiempo real a la UI."""
    await ws.accept()
    ui_connections.append(ws)
    
    try:
        while True:
            # Mantener conexión viva, recibir mensajes del UI
            data = await ws.receive_text()
            # La UI podría mandar approvals por WebSocket también
            msg = json.loads(data)
            if msg.get("type") == "approve":
                await approve_action(ApprovalRequest(**msg["data"]))
    
    except WebSocketDisconnect:
        ui_connections.remove(ws)


async def _notify_ui(event_type: str, data: dict):
    """Envía notificación a todas las UIs conectadas."""
    message = json.dumps({
        "type": event_type,
        "data": data,
        "timestamp": datetime.now().isoformat(),
    })
    
    disconnected = []
    for ws in ui_connections:
        try:
            await ws.send_text(message)
        except Exception:
            disconnected.append(ws)
    
    for ws in disconnected:
        ui_connections.remove(ws)


# =============================================================================
# UI — Security Dashboard
# =============================================================================

@app.get("/", response_class=HTMLResponse)
async def dashboard():
    """Serve the Guardian security dashboard."""
    ui_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "ui", "dashboard.html")
    if os.path.exists(ui_path):
        with open(ui_path) as f:
            return HTMLResponse(content=f.read())
    return HTMLResponse(content="<h1>FortBot Guardian</h1><p>Dashboard not found. Check ui/dashboard.html</p>")


# =============================================================================
# Health
# =============================================================================

@app.get("/health")
async def health():
    return {
        "status": "ok",
        "guardian": "active",
        "vault": "active",
        "pending_approvals": len([p for p in pending_approvals.values() if p["status"] == "pending"]),
        "total_evaluations": len(audit_buffer),
    }


# =============================================================================
# Run
# =============================================================================

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "core.api:app",
        host="127.0.0.1",     # SOLO localhost, nunca expuesto a red
        port=18790,            # Puerto siguiente al gateway de OpenClaw (18789)
        reload=True,
    )
