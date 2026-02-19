# 🏰 FortBot

**Security-first AI agent for WhatsApp.**

FortBot is a personal AI assistant that runs on your machine and talks to you through WhatsApp. Unlike OpenClaw/Moltbot, it was built from scratch with security as the architecture — not as an afterthought.

**223 tests. 20 vulnerabilities patched. Zero trust by default.**

---

## Why FortBot?

OpenClaw proved there's massive demand for AI agents. It also proved that [giving an LLM shell access without trust boundaries](https://www.paloaltonetworks.com/blog/network-security/why-moltbot-may-signal-ai-crisis/) is a security nightmare — 6 CVEs, 21,000+ exposed instances on Shodan, and 341+ malicious skills in the marketplace.

FortBot takes a different approach: **the security IS the architecture**.

```
OpenClaw:     [Single LLM] ← untrusted data + tools + execution

FortBot:      [Privileged LLM] ← owner messages only → generates plans
                     │
              [Policy Engine] ← deterministic validation + taint tracking
                     │
              [Executor] → sandboxed tools (shell allowlist, Docker, file sandbox)
                     │
              [Quarantined LLM] ← processes untrusted data (no tools, schema output)
```

## Features

- **WhatsApp interface** — chat naturally, execute tasks, schedule actions
- **Task planning** — "send a summary of yesterday's messages to Juan at 9am"
- **File operations** — read, write, search (sandboxed to safe directories)
- **Shell commands** — 40-command allowlist, optional Docker sandbox
- **Web fetch** — with SSRF protection and private IP blocking
- **Voice transcription** — send audio, get text (and task execution)
- **Scheduled tasks** — cron-style or one-shot delays
- **Full audit log** — every action, every decision, every policy check

## Security Architecture

### 7 Layers of Defense

| Layer | What it does |
|-------|-------------|
| **Trust Classification** | Every message tagged: OWNER → KNOWN → UNKNOWN → UNTRUSTED |
| **Privileged / Quarantined LLM** | Planner never sees untrusted data. Quarantine has no tools. |
| **Taint Tracking** | Data carries origin labels. Tainted values can't reach sensitive actions. |
| **Policy Engine** | Deterministic rules block dangerous patterns before execution. |
| **Guardian** | Separate Python process provides semantic second opinion on sensitive actions. Fail-closed. |
| **Executor Sandbox** | Shell allowlist, file path restrictions, Docker isolation, plan timeout + rollback. |
| **Encryption at Rest** | AES-256-GCM for message DB and credential vault. |

### vs OpenClaw CVEs

| Vulnerability | OpenClaw | FortBot |
|--------------|----------|---------|
| CVE-2026-25253 (RCE via WebSocket) | Patched late | N/A — no WebSocket exposed |
| CVE-2026-25157 (Command injection) | Patched | Shell allowlist + Docker sandbox |
| CVE-2026-22708 (Prompt injection) | Unresolved | Privileged/Quarantined LLM separation |
| Localhost auto-approval bypass | Patched in v2.1 | N/A — no web panel |
| Heartbeat arbitrary URL fetch | Still exists | No heartbeat exists |
| Plaintext credentials | Still plaintext | AES-256-GCM vault |
| 341+ malicious skills | No verification | No skill/plugin system |

## Quick Start

### Prerequisites

- Node.js 20+
- Python 3.12+
- An Anthropic API key

### Setup

```bash
git clone https://github.com/YOUR_USERNAME/fortbot.git
cd fortbot
npm install
pip install -r requirements.txt

cp .env.example .env
# Edit .env with your OWNER_NUMBER and ANTHROPIC_API_KEY
```

### Run

```bash
# Terminal 1: Guardian (security layer)
npm run guardian

# Terminal 2: FortBot
npm run dev
# Scan QR code with WhatsApp → ready
```

### Docker

```bash
docker compose up
# Scan QR from fortbot container logs
```

## Commands

| Command | Description |
|---------|-------------|
| `/status` | System stats + LLM metrics |
| `/search <text>` | Full-text search in messages |
| `/audit [n]` | Security audit log |
| `/tasks` | Scheduled tasks |
| `/export [jid]` | Export chat history to CSV |
| `/config [key val]` | View/change runtime config |
| `/pause` / `/resume` | Pause/resume bot |
| `/metrics` | Detailed LLM usage stats |
| `/help` | Command list |
| Kill switch phrase | Emergency shutdown (configurable) |

For natural language, just chat — FortBot classifies intent automatically and either responds conversationally or executes as a task.

## Tests

```bash
npm run test:all     # 223 tests (164 TS + 48 Python + 11 integration)
npm run test:ts      # TypeScript unit tests
npm run test:py      # Python Guardian tests
npm run test:integration  # End-to-end with mock gateway
npm run typecheck    # TypeScript compilation check
```

## Project Structure

```
src/
├── index.ts              # Core bot logic, message routing
├── main.ts               # Entry point with auto-restart
├── types/index.ts        # Type definitions, enums, interfaces
├── planner/privileged.ts # Privileged LLM (plan generation)
├── quarantine/sandboxed.ts # Quarantined LLM (untrusted data)
├── executor/executor.ts  # Plan execution with sandbox
├── policy/
│   ├── engine.ts         # Deterministic policy rules
│   ├── taint.ts          # Data flow taint tracking
│   └── network.ts        # URL validation, SSRF protection
├── gateway/
│   ├── interface.ts      # Gateway abstraction
│   ├── whatsapp.ts       # WhatsApp via Baileys
│   ├── human.ts          # Human emulation layer
│   └── cli.ts            # Terminal gateway for testing
├── guardian/
│   ├── bridge.ts         # TS ↔ Python Guardian bridge
│   └── heartbeat.ts      # Liveness monitoring
├── store/messages.ts     # SQLite store with encryption
├── scheduler/scheduler.ts # Cron + delay task scheduling
├── llm/claude-max.ts     # Claude API with retry + metrics
├── browser/browser.ts    # Playwright automation
├── voice/voice.ts        # STT/TTS
├── doctor.ts             # Self-diagnostics
└── config/security.ts    # Security configuration

guardian/engine.py        # Python Guardian (semantic analysis)
core/api.py               # Guardian FastAPI server
vault/credentials.py      # Encrypted credential vault

tests/
├── test.ts               # 164 unit tests
├── integration.ts        # 11 integration tests
├── test_guardian.py       # 25 Guardian tests
└── test_api.py           # 23 API tests
```

## Environment Variables

See [`.env.example`](.env.example) for the full list. Key variables:

| Variable | Required | Description |
|----------|----------|-------------|
| `OWNER_NUMBER` | ✅ | Your WhatsApp number (with country code) |
| `ANTHROPIC_API_KEY` | ✅ | Claude API key |
| `KNOWN_CONTACTS` | | Comma-separated allowed recipients |
| `FORTBOT_DB_PASSWORD` | | Enables AES-256-GCM DB encryption |
| `KILL_SWITCH` | | Emergency shutdown phrase |

## Security Disclosure

Found a vulnerability? See [SECURITY.md](SECURITY.md) for responsible disclosure.

## License

[MIT](LICENSE)

---

*Built by someone who runs agents in live broadcast production — where a false positive means dead air and a real vulnerability means someone else controls your stream.*
