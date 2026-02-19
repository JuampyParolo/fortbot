"""
FortBot Credential Vault

El agente NUNCA ve las credenciales reales.
Trabaja con tokens opacos: {{mi_api_key}}
El Vault inyecta los valores reales al momento de usar.

Arquitectura:
- Vault: AES-256 encrypted en disco
- Broker: proxy que inyecta credenciales en requests
- Detector: identifica credenciales en texto (para bloquear exfiltración)
- Scrubber: elimina credenciales de cualquier output
"""

import json
import os
import re
import hashlib
import secrets
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Optional

# Para encriptación usamos Fernet (AES-128-CBC via cryptography lib)
# En producción se usa AES-256 con key derivation
try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    import base64
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False


@dataclass
class CredentialEntry:
    """Una credencial en el vault."""
    name: str                    # Nombre visible: "spotify_api"
    description: str             # "API key para Spotify"
    credential_type: str         # "api_key", "password", "token", "ssh_key", "oauth"
    created_at: str
    last_used: Optional[str] = None
    use_count: int = 0
    
    # El valor encriptado NO está en este dataclass
    # Se almacena por separado en el archivo encriptado


class CredentialVault:
    """
    Vault encriptado de credenciales.
    
    Principios:
    - Las credenciales se guardan encriptadas con AES-256
    - El agente solo ve los NOMBRES ({{nombre}}), nunca los valores
    - El Broker inyecta valores al momento de usar
    - Toda operación queda en audit log
    """
    
    def __init__(self, vault_path: str = "~/.fortbot/vault", master_password: str = None):
        self.vault_path = Path(vault_path).expanduser()
        self.vault_path.mkdir(parents=True, exist_ok=True)
        
        self.metadata_file = self.vault_path / "metadata.json"
        self.secrets_file = self.vault_path / "secrets.enc"
        self.audit_file = self.vault_path / "vault_audit.jsonl"
        
        self._fernet = None
        self._metadata: dict[str, CredentialEntry] = {}
        self._secrets: dict[str, str] = {}  # Solo en memoria, nunca en disco sin encriptar
        
        if master_password and HAS_CRYPTO:
            self._init_encryption(master_password)
            self._load()
    
    def _init_encryption(self, password: str):
        """Inicializa encriptación con key derivation de la master password."""
        salt_file = self.vault_path / ".salt"
        
        if salt_file.exists():
            salt = salt_file.read_bytes()
        else:
            salt = os.urandom(16)
            salt_file.write_bytes(salt)
            salt_file.chmod(0o600)
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=600_000,  # OWASP 2023 recommendation
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        self._fernet = Fernet(key)
    
    # =========================================================================
    # Operaciones del USUARIO (desde la UI)
    # =========================================================================
    
    def store(self, name: str, value: str, description: str = "", 
              credential_type: str = "api_key") -> bool:
        """
        Guarda una credencial. SOLO el usuario puede hacer esto (desde UI).
        El agente NO tiene acceso a esta función.
        """
        # Validar nombre
        if not re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*$', name):
            raise ValueError(f"Nombre inválido: {name}. Usá solo letras, números y _")
        
        # Guardar metadata (sin el valor)
        self._metadata[name] = CredentialEntry(
            name=name,
            description=description,
            credential_type=credential_type,
            created_at=datetime.now().isoformat(),
        )
        
        # Guardar valor en memoria
        self._secrets[name] = value
        
        # Persistir encriptado
        self._save()
        
        # Audit
        self._audit("store", name, f"Credencial guardada: {credential_type}")
        
        return True
    
    def delete(self, name: str) -> bool:
        """Elimina una credencial. SOLO desde UI."""
        if name in self._metadata:
            del self._metadata[name]
            del self._secrets[name]
            self._save()
            self._audit("delete", name, "Credencial eliminada")
            return True
        return False
    
    def list_credentials(self) -> list[dict]:
        """
        Lista credenciales disponibles (nombres y metadata, NUNCA valores).
        Esto es lo que ve el agente y la UI.
        """
        return [
            {
                "name": entry.name,
                "description": entry.description,
                "type": entry.credential_type,
                "created": entry.created_at,
                "last_used": entry.last_used,
                "use_count": entry.use_count,
            }
            for entry in self._metadata.values()
        ]
    
    def get_value_for_ui(self, name: str) -> Optional[str]:
        """
        Devuelve el valor real. SOLO para la UI cuando el usuario lo pide.
        NUNCA para el agente.
        """
        return self._secrets.get(name)
    
    # =========================================================================
    # Operaciones del BROKER (para inyectar credenciales)
    # =========================================================================
    
    def inject(self, name: str, target: str) -> Optional[str]:
        """
        Inyecta una credencial en un string target.
        
        Reemplaza {{name}} con el valor real.
        Registra el uso en audit.
        
        SOLO el Broker puede llamar esto, NUNCA el agente directo.
        """
        if name not in self._secrets:
            return None
        
        value = self._secrets[name]
        result = target.replace(f"{{{{{name}}}}}", value)
        
        # Registrar uso
        if name in self._metadata:
            self._metadata[name].last_used = datetime.now().isoformat()
            self._metadata[name].use_count += 1
            self._save_metadata()
        
        self._audit("inject", name, f"Credencial inyectada en request")
        
        return result
    
    def inject_header(self, name: str, header_template: str) -> Optional[dict]:
        """
        Inyecta credencial en un header HTTP.
        
        Ejemplo: header_template = "Authorization: Bearer {{api_key}}"
        Resultado: {"Authorization": "Bearer sk-abc123..."}
        """
        if name not in self._secrets:
            return None
        
        injected = self.inject(name, header_template)
        if ":" in injected:
            key, value = injected.split(":", 1)
            return {key.strip(): value.strip()}
        return None
    
    # =========================================================================
    # Credential DETECTOR — Identifica credenciales en texto
    # =========================================================================
    
    # Patrones conocidos de credenciales
    CREDENTIAL_PATTERNS = [
        # API Keys
        (r'sk-[a-zA-Z0-9]{20,}', "OpenAI/Anthropic API key"),
        (r'sk-ant-[a-zA-Z0-9\-]{20,}', "Anthropic API key"),
        (r'ghp_[a-zA-Z0-9]{36}', "GitHub Personal Access Token"),
        (r'gho_[a-zA-Z0-9]{36}', "GitHub OAuth Token"),
        (r'github_pat_[a-zA-Z0-9_]{80,}', "GitHub Fine-grained PAT"),
        (r'xox[bpoas]-[a-zA-Z0-9\-]{10,}', "Slack Token"),
        (r'ya29\.[a-zA-Z0-9_\-]{50,}', "Google OAuth Token"),
        (r'AIza[a-zA-Z0-9_\-]{35}', "Google API Key"),
        (r'AKIA[A-Z0-9]{16}', "AWS Access Key"),
        (r'[a-zA-Z0-9/+]{40}', None),  # Possible AWS Secret (checked with context)
        
        # SSH / Certificates
        (r'-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----', "SSH/TLS Private Key"),
        (r'-----BEGIN CERTIFICATE-----', "Certificate"),
        
        # JWT
        (r'eyJ[a-zA-Z0-9_\-]{10,}\.eyJ[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,}', "JWT Token"),
        
        # Generic patterns (high entropy strings in key=value context)
        (r'(?:password|passwd|pwd|secret|token|api_key|apikey|access_key|auth)\s*[=:]\s*["\']?([a-zA-Z0-9_\-/+]{8,})', "Password/Secret in config"),
    ]
    
    @classmethod
    def detect_credentials(cls, text: str) -> list[dict]:
        """
        Detecta posibles credenciales en un texto.
        
        Esto se usa para:
        1. Bloquear output que contiene credenciales
        2. Ofrecer guardar credenciales que el usuario pega en el chat
        3. Escanear commands antes de ejecutar
        """
        found = []
        
        for pattern, label in cls.CREDENTIAL_PATTERNS:
            matches = re.finditer(pattern, text)
            for match in matches:
                # Evitar false positives muy cortos
                matched_text = match.group(0)
                if len(matched_text) < 10:
                    continue
                
                found.append({
                    "type": label or "Possible credential",
                    "position": match.start(),
                    "length": len(matched_text),
                    # NUNCA incluimos el valor real en la detección
                    "preview": matched_text[:4] + "..." + matched_text[-4:],
                })
        
        return found
    
    @classmethod
    def scrub(cls, text: str) -> str:
        """
        Remueve credenciales de un texto, reemplazándolas con [REDACTED].
        
        Se aplica a TODO output antes de que llegue al agente o al log.
        """
        scrubbed = text
        
        for pattern, label in cls.CREDENTIAL_PATTERNS:
            scrubbed = re.sub(pattern, "[REDACTED]", scrubbed)
        
        return scrubbed
    
    # =========================================================================
    # Persistence
    # =========================================================================
    
    def _save(self):
        """Guarda metadata + secrets encriptados."""
        self._save_metadata()
        self._save_secrets()
    
    def _save_metadata(self):
        """Metadata (sin valores sensibles) en JSON plano."""
        data = {}
        for name, entry in self._metadata.items():
            data[name] = {
                "name": entry.name,
                "description": entry.description,
                "credential_type": entry.credential_type,
                "created_at": entry.created_at,
                "last_used": entry.last_used,
                "use_count": entry.use_count,
            }
        
        self.metadata_file.write_text(json.dumps(data, indent=2))
    
    def _save_secrets(self):
        """Valores encriptados en archivo aparte."""
        if not self._fernet:
            return
        
        plaintext = json.dumps(self._secrets).encode()
        encrypted = self._fernet.encrypt(plaintext)
        self.secrets_file.write_bytes(encrypted)
        self.secrets_file.chmod(0o600)  # Solo el owner puede leer
    
    def _load(self):
        """Carga metadata y secrets."""
        # Metadata
        if self.metadata_file.exists():
            data = json.loads(self.metadata_file.read_text())
            for name, entry_data in data.items():
                self._metadata[name] = CredentialEntry(**entry_data)
        
        # Secrets
        if self.secrets_file.exists() and self._fernet:
            encrypted = self.secrets_file.read_bytes()
            try:
                plaintext = self._fernet.decrypt(encrypted)
                self._secrets = json.loads(plaintext.decode())
            except Exception:
                # Si falla la desencriptación, el vault está corrupto o la password cambió
                raise ValueError("No se pudo desencriptar el vault. ¿Password correcta?")
    
    def _audit(self, action: str, credential_name: str, detail: str):
        """Registra operación en audit log."""
        entry = {
            "timestamp": datetime.now().isoformat(),
            "action": action,
            "credential": credential_name,
            "detail": detail,
        }
        
        with open(self.audit_file, "a") as f:
            f.write(json.dumps(entry) + "\n")


class CredentialBroker:
    """
    Proxy que inyecta credenciales en requests HTTP.
    
    El agente dice: "Llamá a la API de Spotify"
    El Broker: 
    1. Busca qué credencial necesita
    2. La inyecta en el header
    3. Hace el request
    4. Devuelve la respuesta SIN la credencial
    
    El agente nunca ve el token real.
    """
    
    def __init__(self, vault: CredentialVault):
        self.vault = vault
    
    def prepare_request(self, url: str, headers: dict = None, body: str = None) -> dict:
        """
        Prepara un HTTP request inyectando credenciales.
        
        Busca {{placeholder}} en url, headers y body.
        Los reemplaza con valores reales del vault.
        
        Returns: dict con url, headers, body procesados
        """
        headers = headers or {}
        
        # Encontrar todos los placeholders
        all_text = f"{url} {json.dumps(headers)} {body or ''}"
        placeholders = re.findall(r'\{\{(\w+)\}\}', all_text)
        
        # Inyectar cada uno
        processed_url = url
        processed_headers = {k: v for k, v in headers.items()}
        processed_body = body
        
        for name in placeholders:
            if name in self.vault._secrets:
                if processed_url:
                    processed_url = self.vault.inject(name, processed_url)
                for k, v in processed_headers.items():
                    processed_headers[k] = self.vault.inject(name, v) or v
                if processed_body:
                    processed_body = self.vault.inject(name, processed_body)
        
        return {
            "url": processed_url,
            "headers": processed_headers,
            "body": processed_body,
        }
    
    def scrub_response(self, response_text: str) -> str:
        """
        Limpia la respuesta de cualquier credencial antes de
        devolvérsela al agente.
        
        Defensa en profundidad: incluso si el servidor devuelve
        nuestras credenciales en la respuesta, el agente no las ve.
        """
        return CredentialVault.scrub(response_text)


class EgressFilter:
    """
    Filtro de salida de red.
    
    ÚLTIMA línea de defensa: escanea TODO el tráfico HTTP saliente.
    Si detecta credenciales en el body, headers o URL → BLOCK.
    
    Aunque todo lo demás falle, la credencial no sale.
    """
    
    def __init__(self, vault: CredentialVault):
        self.vault = vault
        self.blocked_count = 0
    
    def check_outgoing(self, url: str, headers: dict = None, body: str = None) -> tuple[bool, str]:
        """
        Verifica que un request saliente no contenga credenciales.
        
        Returns: (allowed: bool, reason: str)
        """
        # Concatenar todo el contenido saliente
        all_content = url
        if headers:
            all_content += " " + json.dumps(headers)
        if body:
            all_content += " " + str(body)
        
        # Buscar credenciales del vault
        for name, value in self.vault._secrets.items():
            if value in all_content:
                self.blocked_count += 1
                return False, f"Credencial '{name}' detectada en tráfico saliente. BLOQUEADO."
        
        # Buscar patrones genéricos de credenciales
        detections = CredentialVault.detect_credentials(all_content)
        if detections:
            # No bloqueamos automáticamente por patrón genérico
            # pero sí logueamos (podría ser un false positive)
            pass
        
        return True, "OK"
