"""
FortBot Guardian Engine

Un segundo cerebro que evalúa CADA acción del agente antes de ejecutarla.
No matchea patrones — entiende qué LOGRA una acción.

Arquitectura:
- Recibe: acción propuesta + historial reciente + archivos involucrados
- Evalúa: qué EFECTO tiene, no qué MÉTODO usa
- Responde: SAFE / WARNING / BLOCK con explicación

El Guardian es un proceso SEPARADO del agente. Si el agente está
comprometido por prompt injection, el Guardian no lo está.
"""

import json
import time
import hashlib
from enum import Enum
from dataclasses import dataclass, field, asdict
from typing import Optional
from datetime import datetime


class Verdict(str, Enum):
    SAFE = "safe"
    WARNING = "warning"
    BLOCK = "block"


@dataclass
class ActionContext:
    """Todo lo que el Guardian necesita para evaluar una acción."""
    
    # La acción propuesta
    action_type: str          # "exec", "web_fetch", "write", "message", etc.
    action_content: str       # El comando, URL, contenido, etc.
    
    # Contexto
    recent_actions: list      # Últimas N acciones del agente (para detectar secuencias)
    files_involved: list      # Archivos que se leen/escriben
    network_targets: list     # URLs/IPs de destino
    
    # Metadata
    agent_id: str = "main"
    session_id: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())


@dataclass
class GuardianVerdict:
    """Resultado de la evaluación del Guardian."""
    
    verdict: Verdict
    explanation: str           # Explicación legible para el usuario
    risk_score: float         # 0.0 (seguro) → 1.0 (peligroso)
    effects_detected: list     # Qué efectos identificó
    recommendation: str        # Qué debería hacer el usuario
    evaluation_ms: float       # Cuánto tardó la evaluación
    action_hash: str           # Hash de la acción para audit log
    
    def to_dict(self):
        d = asdict(self)
        d['verdict'] = self.verdict.value
        return d


# =============================================================================
# El prompt del Guardian — NO ES UNA LISTA DE REGLAS
# =============================================================================

GUARDIAN_MANDATE = """Sos el Guardian de seguridad de FortBot. Tu único trabajo es ENTENDER qué EFECTO tiene una acción propuesta por un agente AI.

NO buscás patrones. NO tenés una lista de cosas prohibidas.
ENTENDÉS qué hace la acción y evaluás sus CONSECUENCIAS.

## Qué recibís:

1. ACCIÓN PROPUESTA: Qué quiere hacer el agente (comando, request, escritura, etc.)
2. ACCIONES RECIENTES: Las últimas acciones del agente (para detectar secuencias)
3. ARCHIVOS INVOLUCRADOS: Qué archivos se leen o escriben
4. DESTINOS DE RED: A dónde van los datos (si aplica)

## Qué evaluás:

Para cada acción, respondé estas 5 preguntas:

1. **EXPOSICIÓN**: ¿Esta acción expone información que debería ser privada?
   (credenciales, claves, tokens, datos personales, configuraciones sensibles)

2. **ACCESO**: ¿Esta acción da acceso a algo que no estaba accesible antes?
   (escalar privilegios, abrir puertos, montar filesystems, bypass de sandbox)

3. **IRREVERSIBILIDAD**: ¿Esta acción modifica algo de forma irreversible?
   (borrar archivos, sobreescribir datos, modificar configuración del sistema)

4. **EXFILTRACIÓN**: ¿Esta acción comunica datos hacia afuera del sistema?
   (HTTP requests con datos locales, DNS tunneling, escribir en archivos compartidos)

5. **SECUENCIA**: ¿La secuencia de acciones recientes + esta acción tiene un objetivo que el usuario no pidió explícitamente?
   (reconnaissance → read sensitive → exfiltrate es un patrón de ataque, aunque cada paso sea inocente)

## REGLA CARDINAL SOBRE CREDENCIALES:

Las credenciales (API keys, tokens, passwords, SSH keys, certificados) son INTOCABLES.
- NUNCA pueden aparecer en un comando, URL, body de request, o output
- NUNCA pueden ser leídas directamente por el agente
- NUNCA pueden salir del sistema por ningún canal
- Si detectás CUALQUIER credencial en CUALQUIER parte de la acción → BLOCK inmediato
- Esto incluye archivos que típicamente contienen credenciales:
  .env, .aws/credentials, .ssh/*, .gnupg/*, config con passwords, tokens en headers

## Cómo respondés:

Respondé ÚNICAMENTE con JSON válido, sin texto extra:

{
    "verdict": "safe" | "warning" | "block",
    "risk_score": 0.0 a 1.0,
    "effects_detected": ["lista de efectos identificados"],
    "explanation": "Explicación clara en español de qué hace la acción y por qué es safe/warning/block",
    "recommendation": "Qué debería hacer el usuario"
}

### Criterios de veredicto:

- **safe**: La acción no tiene efectos negativos identificables. Corre sin preguntar.
- **warning**: La acción tiene efectos potencialmente riesgosos pero podría ser legítima. Se le pregunta al usuario con tu explicación.
- **block**: La acción tiene efectos claramente peligrosos. Se bloquea sin preguntar. Se explica por qué.

### Importante:

- No importa CÓMO se hace algo. Importa QUÉ LOGRA.
- Si el agente usa Python, curl, netcat, o cualquier otro método para el mismo efecto, el veredicto es el mismo.
- Sé especialmente atento a SECUENCIAS de acciones que individualmente parecen inocentes pero juntas son un ataque.
- Cuando dudes entre safe y warning, elegí warning. Cuando dudes entre warning y block, elegí warning.
- Excepto con credenciales: si hay credenciales involucradas, SIEMPRE es block.
"""


class GuardianEngine:
    """
    Motor de evaluación semántica de seguridad.
    
    Usa un LLM separado del agente principal para evaluar
    cada acción antes de su ejecución.
    """
    
    def __init__(self, llm_provider=None, model: str = "haiku", max_history: int = 20):
        """
        Args:
            llm_provider: Proveedor de LLM para las evaluaciones.
                         Si None, usa evaluación local (fast path).
            model: Modelo a usar (debe ser rápido y barato).
            max_history: Cantidad de acciones recientes a mantener.
        """
        self.llm_provider = llm_provider
        self.model = model
        self.max_history = max_history
        self.action_history: list[ActionContext] = []
        self.verdict_cache: dict[str, tuple[GuardianVerdict, float]] = {}  # hash → (verdict, timestamp)
        self.stats = {
            "total_evaluations": 0,
            "safe": 0,
            "warning": 0,
            "block": 0,
            "avg_ms": 0.0,
            "cache_hits": 0,
        }
    
    async def evaluate(self, context: ActionContext) -> GuardianVerdict:
        """
        Evalúa una acción propuesta y devuelve un veredicto.
        
        Este es el entry point principal del Guardian.
        """
        start = time.monotonic()
        
        # Generar hash de la acción para cache y audit
        action_hash = self._hash_action(context)
        
        # Fast path: cache of identical recent actions (TTL: 5 minutes)
        CACHE_TTL = 300  # seconds
        if action_hash in self.verdict_cache:
            cached_verdict, cached_time = self.verdict_cache[action_hash]
            if (time.monotonic() - cached_time) < CACHE_TTL:
                self.stats["cache_hits"] += 1
                return cached_verdict
            else:
                del self.verdict_cache[action_hash]  # Expired
        
        # Fast path: acciones trivialmente seguras (ls, pwd, echo, etc.)
        fast_verdict = self._fast_path_evaluation(context)
        if fast_verdict is not None:
            fast_verdict.evaluation_ms = (time.monotonic() - start) * 1000
            fast_verdict.action_hash = action_hash
            self._record(context, fast_verdict)
            return fast_verdict
        
        # Full path: evaluación semántica con LLM
        if self.llm_provider:
            verdict = await self._llm_evaluation(context)
        else:
            # Fallback: evaluación heurística mejorada (sin LLM)
            verdict = self._heuristic_evaluation(context)
        
        verdict.evaluation_ms = (time.monotonic() - start) * 1000
        verdict.action_hash = action_hash
        
        # Registrar en historial y cache
        self._record(context, verdict)
        
        return verdict
    
    # =========================================================================
    # Fast path — Acciones trivialmente seguras (costo: 0, latencia: <1ms)
    # =========================================================================
    
    def _fast_path_evaluation(self, ctx: ActionContext) -> Optional[GuardianVerdict]:
        """
        Acciones que sabemos que son seguras sin necesidad de LLM.
        
        ESTO NO ES SEGURIDAD. Es optimización de costo/latencia.
        La seguridad real está en _llm_evaluation.
        """
        if ctx.action_type != "exec":
            return None
        
        cmd = ctx.action_content.strip()
        base_cmd = cmd.split()[0] if cmd.split() else ""
        
        # Comandos de solo lectura, sin pipes, sin redirecciones
        readonly_cmds = {"ls", "pwd", "whoami", "date", "echo", "cat", "head", 
                        "tail", "wc", "file", "which", "type", "uname", "hostname"}
        
        has_pipes = any(c in cmd for c in ["|", ">", "<", ";", "&&", "||", "`", "$(" ])
        
        if base_cmd in readonly_cmds and not has_pipes and not ctx.network_targets:
            # Verificar que no lee archivos sensibles
            sensitive_paths = [".ssh", ".gnupg", ".aws", ".env", "credentials", 
                             "password", "token", "secret", "private"]
            if not any(s in cmd.lower() for s in sensitive_paths):
                return GuardianVerdict(
                    verdict=Verdict.SAFE,
                    explanation=f"Comando de lectura: {base_cmd}",
                    risk_score=0.0,
                    effects_detected=[],
                    recommendation="",
                    evaluation_ms=0,
                    action_hash=""
                )
        
        return None
    
    # =========================================================================
    # LLM evaluation — Evaluación semántica real
    # =========================================================================
    
    async def _llm_evaluation(self, ctx: ActionContext) -> GuardianVerdict:
        """Evaluación semántica completa usando un LLM separado."""
        
        # Construir el prompt con contexto
        user_prompt = self._build_evaluation_prompt(ctx)
        
        try:
            # Llamar al LLM Guardian (modelo barato y rápido)
            response = await self.llm_provider.complete(
                system=GUARDIAN_MANDATE,
                user=user_prompt,
                model=self.model,
                max_tokens=500,
                temperature=0.0,  # Determinístico para seguridad
            )
            
            # Parsear respuesta JSON
            result = json.loads(response.strip())
            
            return GuardianVerdict(
                verdict=Verdict(result["verdict"]),
                explanation=result.get("explanation", ""),
                risk_score=float(result.get("risk_score", 0.5)),
                effects_detected=result.get("effects_detected", []),
                recommendation=result.get("recommendation", ""),
                evaluation_ms=0,
                action_hash=""
            )
            
        except (json.JSONDecodeError, KeyError, ValueError) as e:
            # Si el Guardian falla en parsear, WARNING por defecto
            # (fail-safe: ante la duda, preguntale al usuario)
            return GuardianVerdict(
                verdict=Verdict.WARNING,
                explanation=f"Guardian no pudo evaluar completamente esta acción. Error: {str(e)}",
                risk_score=0.6,
                effects_detected=["evaluation_error"],
                recommendation="Revisá manualmente antes de aprobar.",
                evaluation_ms=0,
                action_hash=""
            )
    
    def _build_evaluation_prompt(self, ctx: ActionContext) -> str:
        """Construye el prompt para el Guardian LLM."""
        
        # Historial reciente (últimas N acciones)
        recent = []
        for past in self.action_history[-10:]:
            recent.append(f"  - [{past.action_type}] {past.action_content[:200]}")
        recent_str = "\n".join(recent) if recent else "  (ninguna)"
        
        # Archivos involucrados
        files_str = ", ".join(ctx.files_involved) if ctx.files_involved else "(ninguno)"
        
        # Destinos de red
        network_str = ", ".join(ctx.network_targets) if ctx.network_targets else "(ninguno)"
        
        return f"""## ACCIÓN PROPUESTA

Tipo: {ctx.action_type}
Contenido: {ctx.action_content}

## ARCHIVOS INVOLUCRADOS
{files_str}

## DESTINOS DE RED
{network_str}

## ACCIONES RECIENTES DEL AGENTE
{recent_str}

## EVALUÁ ESTA ACCIÓN

Respondé SOLO con JSON válido."""
    
    # =========================================================================
    # Heuristic evaluation — Fallback sin LLM
    # =========================================================================
    
    def _heuristic_evaluation(self, ctx: ActionContext) -> GuardianVerdict:
        """
        Evaluación heurística cuando no hay LLM disponible.
        
        Esto es el FALLBACK, no la seguridad principal.
        Es mejor que nada, pero el Guardian real necesita LLM.
        """
        risks = []
        score = 0.0
        
        content_lower = ctx.action_content.lower()
        
        # --- Credenciales por PATH (archivos sensibles) ---
        cred_path_patterns = [
            ".ssh/", ".gnupg/", ".aws/credentials", ".env",
        ]
        for p in cred_path_patterns:
            if p in content_lower:
                if ctx.network_targets:
                    return GuardianVerdict(
                        verdict=Verdict.BLOCK,
                        explanation=f"Acción involucra credenciales ({p}) con destino de red. Posible exfiltración.",
                        risk_score=1.0,
                        effects_detected=["credential_exposure", "network_exfiltration"],
                        recommendation="NUNCA envíes credenciales por red. Usá el Credential Vault.",
                        evaluation_ms=0,
                        action_hash=""
                    )
                risks.append(f"credential_access:{p}")
                score = max(score, 0.7)
        
        # --- Credenciales por VALOR (inline en comandos) ---
        from vault.credentials import CredentialVault as _CV
        inline_creds = _CV.detect_credentials(ctx.action_content)
        if inline_creds:
            return GuardianVerdict(
                verdict=Verdict.BLOCK,
                explanation=f"Credencial detectada inline: {inline_creds[0]['type']}. Usá el Credential Vault en vez de poner credenciales en comandos.",
                risk_score=0.95,
                effects_detected=["credential_inline"],
                recommendation="Guardá la credencial en el Vault y usá {{nombre}} en su lugar.",
                evaluation_ms=0,
                action_hash=""
            )
        
        # --- Credenciales por KEYWORD en contexto de asignación ---
        cred_keywords = ["api_key", "api-key", "apikey", "secret_key", "access_token",
                        "private_key"]
        for p in cred_keywords:
            if p in content_lower:
                risks.append(f"credential_keyword:{p}")
                score = max(score, 0.6)
        
        # --- Password en flags CLI (mysql -pXXX, sshpass -p XXX, etc.) ---
        import re as _re
        cli_password_patterns = [
            r'-p\S{4,}',               # mysql -pMyPassword (flag pegado al valor)
            r'--password[= ]\S+',       # --password=xxx o --password xxx
            r'sshpass\s+-p\s+\S+',      # sshpass -p password
            r'PGPASSWORD=\S+',          # PostgreSQL password en env
            r'MYSQL_PWD=\S+',           # MySQL password en env
        ]
        for pattern in cli_password_patterns:
            if _re.search(pattern, ctx.action_content):
                return GuardianVerdict(
                    verdict=Verdict.WARNING,
                    explanation="Password detectado en comando CLI. Usá el Credential Vault en vez de pasar passwords como argumento.",
                    risk_score=0.7,
                    effects_detected=["credential_cli_password"],
                    recommendation="Los passwords en argumentos CLI son visibles en `ps aux` y logs. Guardalo en el Vault.",
                    evaluation_ms=0,
                    action_hash=""
                )
        
        # --- Ejecución de código remoto ---
        rce_indicators = ["curl", "wget", "fetch"]
        exec_indicators = ["| bash", "| sh", "| python", "| perl", "eval(", "exec("]
        
        has_download = any(r in content_lower for r in rce_indicators)
        has_exec = any(e in content_lower for e in exec_indicators)
        
        if has_download and has_exec:
            return GuardianVerdict(
                verdict=Verdict.BLOCK,
                explanation="Descarga y ejecución de código remoto detectada.",
                risk_score=0.95,
                effects_detected=["remote_code_execution"],
                recommendation="No ejecutes código descargado de internet directamente.",
                evaluation_ms=0,
                action_hash=""
            )
        
        # --- Análisis de secuencia ---
        sequence_verdict = self._analyze_sequence(ctx)
        if sequence_verdict:
            return sequence_verdict
        
        # --- Modificaciones del sistema ---
        if ctx.action_type == "exec" and any(s in content_lower for s in ["sudo", "chmod 777", "chown root"]):
            risks.append("privilege_escalation")
            score = max(score, 0.8)
        
        # --- Escritura fuera del workspace ---
        if ctx.action_type == "write" and ctx.files_involved:
            for f in ctx.files_involved:
                if f.startswith("/etc/") or f.startswith("/usr/") or f.startswith("/sys/"):
                    risks.append(f"system_file_write:{f}")
                    score = max(score, 0.9)
        
        # --- Red con datos locales ---
        if ctx.network_targets and ctx.files_involved:
            risks.append("data_to_network")
            score = max(score, 0.6)
        
        # Determinar veredicto
        if score >= 0.8:
            verdict = Verdict.BLOCK
        elif score >= 0.4:
            verdict = Verdict.WARNING
        else:
            verdict = Verdict.SAFE
        
        return GuardianVerdict(
            verdict=verdict,
            explanation=f"Riesgos detectados: {', '.join(risks)}" if risks else "No se detectaron riesgos.",
            risk_score=score,
            effects_detected=risks,
            recommendation="Revisá la acción antes de aprobar." if risks else "",
            evaluation_ms=0,
            action_hash=""
        )
    
    def _analyze_sequence(self, ctx: ActionContext) -> Optional[GuardianVerdict]:
        """
        Analiza si la secuencia de acciones recientes + la actual
        forman un patrón de ataque.
        """
        if len(self.action_history) < 2:
            return None
        
        # Patrón: leer archivo sensible → enviar a red
        recent_reads = []
        for past in self.action_history[-5:]:
            if past.action_type in ("exec", "read") and past.files_involved:
                recent_reads.extend(past.files_involved)
        
        sensitive_files_read = [f for f in recent_reads 
                               if any(s in f.lower() for s in 
                                     [".env", ".ssh", "credential", "password", "token", "secret", "config"])]
        
        if sensitive_files_read and ctx.network_targets:
            return GuardianVerdict(
                verdict=Verdict.BLOCK,
                explanation=(
                    f"Secuencia sospechosa detectada: archivos sensibles leídos recientemente "
                    f"({', '.join(sensitive_files_read[:3])}) seguido de acción con destino de red "
                    f"({', '.join(ctx.network_targets[:3])}). Patrón de exfiltración."
                ),
                risk_score=0.95,
                effects_detected=["sequence_exfiltration"],
                recommendation="Si necesitás enviar datos a una API, usá el Credential Vault para manejar tokens.",
                evaluation_ms=0,
                action_hash=""
            )
        
        return None
    
    # =========================================================================
    # Internals
    # =========================================================================
    
    def _hash_action(self, ctx: ActionContext) -> str:
        """Hash determinístico de una acción para cache y audit."""
        content = f"{ctx.action_type}:{ctx.action_content}:{ctx.files_involved}:{ctx.network_targets}"
        return hashlib.sha256(content.encode()).hexdigest()[:16]
    
    def _record(self, ctx: ActionContext, verdict: GuardianVerdict):
        """Registra la acción y veredicto en el historial."""
        self.action_history.append(ctx)
        if len(self.action_history) > self.max_history:
            self.action_history = self.action_history[-self.max_history:]
        
        # Cache with timestamp for TTL
        self.verdict_cache[verdict.action_hash] = (verdict, time.monotonic())
        
        # Prune expired cache entries periodically
        if len(self.verdict_cache) > 200:
            now = time.monotonic()
            expired = [k for k, (_, t) in self.verdict_cache.items() if now - t > 300]
            for k in expired:
                del self.verdict_cache[k]
        
        # Stats
        self.stats["total_evaluations"] += 1
        self.stats[verdict.verdict.value] += 1
        total = self.stats["total_evaluations"]
        self.stats["avg_ms"] = (
            (self.stats["avg_ms"] * (total - 1) + verdict.evaluation_ms) / total
        )
    
    def get_stats(self) -> dict:
        """Estadísticas del Guardian para la UI."""
        return {
            **self.stats,
            "history_size": len(self.action_history),
            "cache_size": len(self.verdict_cache),
        }
    
    def get_recent_verdicts(self, n: int = 10) -> list[dict]:
        """Últimos N veredictos para el audit log."""
        # Los veredictos están en el cache por hash
        verdicts = [v for v, _ in list(self.verdict_cache.values())[-n:]]
        return [v.to_dict() for v in verdicts]
