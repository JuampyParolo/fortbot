"""
FortBot — LLM Provider for Guardian

Calls Claude via CLI pipe (`claude --print`).
Same auth as the TS side: `claude login` (OAuth, no API key).

Supports multiple backends:
- claude_cli: Uses `claude --print` (default, free with Max subscription)
- anthropic_api: Uses the Anthropic Python SDK (needs API key)
- local_ollama: Uses a local Ollama instance (fully offline)
"""

import asyncio
import json
import os
import shutil
from typing import Optional


class LLMProvider:
    """Abstract LLM provider interface."""
    
    async def complete(
        self,
        system: str,
        user: str,
        model: str = "haiku",
        max_tokens: int = 500,
        temperature: float = 0.0,
    ) -> str:
        """Send a completion request and return the text response."""
        raise NotImplementedError


class ClaudeCLIProvider(LLMProvider):
    """
    Calls Claude via the CLI: `claude --print -m <model> -s <system> <prompt>`
    
    Authentication: Run `claude login` once (OAuth flow).
    Cost: Free with Claude Max subscription.
    Latency: ~500-1500ms (process spawn overhead).
    """
    
    MODEL_MAP = {
        "haiku": "haiku",
        "sonnet": "sonnet", 
        "opus": "opus",
    }
    
    def __init__(self):
        self.claude_path = shutil.which("claude")
        if not self.claude_path:
            raise RuntimeError(
                "Claude CLI not found. Install it with: npm install -g @anthropic-ai/claude-cli\n"
                "Then run: claude login"
            )
    
    async def complete(
        self,
        system: str,
        user: str,
        model: str = "haiku",
        max_tokens: int = 500,
        temperature: float = 0.0,
    ) -> str:
        mapped_model = self.MODEL_MAP.get(model, model)
        
        cmd = [
            self.claude_path, "--print",
            "-m", mapped_model,
            "--max-turns", "1",
        ]
        
        # System prompt via -s flag
        if system:
            cmd.extend(["-s", system])
        
        cmd.append(user)
        
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        
        stdout, stderr = await asyncio.wait_for(
            proc.communicate(), timeout=30.0
        )
        
        if proc.returncode != 0:
            error = stderr.decode().strip() if stderr else "Unknown error"
            raise RuntimeError(f"Claude CLI failed (exit {proc.returncode}): {error}")
        
        return stdout.decode().strip()


class AnthropicAPIProvider(LLMProvider):
    """
    Calls Claude via the Anthropic Python SDK.
    
    Needs: ANTHROPIC_API_KEY env var or passed directly.
    Cost: Pay per token.
    Latency: ~200-800ms (direct API, no process spawn).
    """
    
    MODEL_MAP = {
        "haiku": "claude-haiku-4-5-20251001",
        "sonnet": "claude-sonnet-4-5-20250929",
        "opus": "claude-opus-4-6",
    }
    
    def __init__(self, api_key: Optional[str] = None):
        try:
            import anthropic
            self.client = anthropic.AsyncAnthropic(
                api_key=api_key or os.environ.get("ANTHROPIC_API_KEY")
            )
        except ImportError:
            raise RuntimeError("Install anthropic SDK: pip install anthropic")
    
    async def complete(
        self,
        system: str,
        user: str,
        model: str = "haiku",
        max_tokens: int = 500,
        temperature: float = 0.0,
    ) -> str:
        mapped_model = self.MODEL_MAP.get(model, model)
        
        response = await self.client.messages.create(
            model=mapped_model,
            max_tokens=max_tokens,
            temperature=temperature,
            system=system,
            messages=[{"role": "user", "content": user}],
        )
        
        return response.content[0].text


class OllamaProvider(LLMProvider):
    """
    Calls a local Ollama instance.
    
    Fully offline. No data leaves the network.
    Needs: Ollama running on localhost:11434 with a model pulled.
    """
    
    def __init__(self, endpoint: str = "http://localhost:11434", model: str = "llama3.2"):
        self.endpoint = endpoint.rstrip("/")
        self.default_model = model
    
    async def complete(
        self,
        system: str,
        user: str,
        model: str = "haiku",
        max_tokens: int = 500,
        temperature: float = 0.0,
    ) -> str:
        import aiohttp
        
        payload = {
            "model": self.default_model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "stream": False,
            "options": {
                "temperature": temperature,
                "num_predict": max_tokens,
            },
        }
        
        async with aiohttp.ClientSession() as session:
            async with session.post(
                f"{self.endpoint}/api/chat",
                json=payload,
                timeout=aiohttp.ClientTimeout(total=30),
            ) as resp:
                data = await resp.json()
                return data["message"]["content"]


def create_provider(backend: str = "auto", **kwargs) -> LLMProvider:
    """
    Factory function to create the appropriate LLM provider.
    
    backend options:
    - "auto": Try claude_cli first, then anthropic_api, then ollama
    - "claude_cli": Force Claude CLI
    - "anthropic_api": Force Anthropic API
    - "ollama": Force local Ollama
    """
    if backend == "auto":
        # Try Claude CLI first (free with Max)
        if shutil.which("claude"):
            try:
                return ClaudeCLIProvider()
            except RuntimeError:
                pass
        
        # Try Anthropic API
        if os.environ.get("ANTHROPIC_API_KEY"):
            try:
                return AnthropicAPIProvider()
            except RuntimeError:
                pass
        
        # Try Ollama
        try:
            import aiohttp
            return OllamaProvider(**kwargs)
        except ImportError:
            pass
        
        # Nothing available
        raise RuntimeError(
            "No LLM backend available. Options:\n"
            "  1. Install Claude CLI: npm install -g @anthropic-ai/claude-cli && claude login\n"
            "  2. Set ANTHROPIC_API_KEY env var\n"
            "  3. Install Ollama: https://ollama.com\n"
            "Guardian will use heuristic-only mode."
        )
    
    elif backend == "claude_cli":
        return ClaudeCLIProvider()
    elif backend == "anthropic_api":
        return AnthropicAPIProvider(**kwargs)
    elif backend == "ollama":
        return OllamaProvider(**kwargs)
    else:
        raise ValueError(f"Unknown backend: {backend}")
