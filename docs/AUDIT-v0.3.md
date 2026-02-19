# 🏰 FortBot v0.3 — Auditoría Completa

## Estado actual: 28 tests, 0 errores, 3411 líneas, 16 archivos

---

## 🔴 CRÍTICOS (afectan usabilidad core)

### 1. AMNESIA TOTAL — Sin historial de conversación
**Archivo:** `src/index.ts:194-203`, `src/llm/claude-max.ts:36`

`handleChat()` manda a Claude SOLO el mensaje actual. Cero historial.
Cada mensaje es como hablar con un desconocido.

```typescript
// AHORA (malo):
const response = await callClaude(systemPrompt, text, ...);

// DEBERÍA:
const history = this.store.readMessages(msg.from, 20);
const context = history.map(m => `${m.sender_name}: ${m.content}`).join('\n');
const response = await callClaude(systemPrompt, context + '\nUser: ' + text, ...);
```

**Impacto:** El problema #1 que reportan TODOS los usuarios de bots de WA con IA.
Si decís "qué te dije recién?" → no tiene idea.

**Solución:** Sliding window de últimos N mensajes inyectados como contexto.
Con Claude Max (200K tokens) podés meter tranquilamente 50-100 mensajes.

### 2. PLANNER SIN CONTEXTO — No sabe qué es "eso"
**Archivo:** `src/planner/privileged.ts:41`

El planner ve SOLO la query. Si decís "mandá eso a Juan", no sabe qué es "eso"
porque no tiene el historial de la conversación.

**Solución:** Inyectar últimos 5-10 mensajes como contexto al planner también.

### 3. RESPUESTAS DEL BOT NO SE GUARDAN
**Archivo:** `src/index.ts` — no hay store de outgoing

Solo se guardan mensajes entrantes. Las respuestas del bot no se persisten.
Resultado: historial incompleto, el bot no sabe qué dijo él.

**Solución:** Agregar `storeOutgoing(jid, content)` al MessageStore y llamarlo
después de cada `sendMessage`.

---

## 🟡 SEGURIDAD — Defensa en profundidad

### 4. read_file sin restricción de ruta
**Archivo:** `src/executor/executor.ts:175-183`

Puede leer CUALQUIER archivo: `/etc/passwd`, `.env`, `auth_store/creds.json`.
El planner es trusted, pero defense-in-depth dice: restringir.

```typescript
// Agregar:
const ALLOWED_PATHS = ['./data/', './downloads/', '/tmp/fortbot/'];
const BLOCKED_PATTERNS = ['.env', 'auth_store', 'creds', '/etc/', '/proc/'];
```

### 5. write_file puede sobreescribir archivos críticos
**Archivo:** `src/executor/executor.ts:185-194`

Podría sobreescribir `.env`, `SOUL.md`, `auth_store/creds.json`, `fortbot.db`.

**Solución:** Whitelist de directorios escribibles + blacklist de archivos protegidos.

### 6. shell_exec sin filtro de comandos
**Archivo:** `src/executor/executor.ts:196-205`

Timeout de 30s está bien, pero puede ejecutar `rm -rf /`, `curl | sh`,
`cat .env`, etc. Necesita al menos una blacklist.

```typescript
const BLOCKED_COMMANDS = ['rm -rf', 'mkfs', 'dd if=', ':(){', 'curl|sh'];
```

### 7. web_fetch sin protección SSRF
**Archivo:** `src/executor/executor.ts:207-214`

Puede hacer fetch a `http://localhost:11434` (ollama), `http://169.254.169.254`
(AWS metadata), o cualquier IP interna.

**Solución:** Bloquear IPs privadas (10.x, 172.16-31.x, 192.168.x, 127.x, 169.254.x).

---

## 🟡 ROBUSTEZ

### 8. Race condition en confirmaciones
**Archivo:** `src/index.ts:115-125`

Si hay 2 tasks esperando confirmación, un solo "si" aprueba AMBAS.
El `for` loop resuelve todas las promesas pendientes con la misma respuesta.

**Solución:** Cola FIFO de confirmaciones, cada "si/no" resuelve solo la primera.

### 9. isTaskRequest es frágil
**Archivo:** `src/index.ts:175-192`

Pattern matching en verbos conjugados. No catchea:
- "podrías enviarle..." 
- "necesito que busques..."
- "haceme un resumen de..."
- "qué dicen los mensajes de..."

**Solución:** Dos opciones:
a) Usar el LLM para clasificar (chat vs task) — más inteligente
b) Ampliar patterns + fallback: si el planner devuelve steps, era task

### 10. Quarantine model no se pasa desde config
**Archivo:** `src/index.ts:70-74`

```typescript
// AHORA:
this.quarantine = new QuarantinedLLM(
  this.config.quarantineLlmEndpoint,
  this.config.useLocalQuarantine,
  this.taintTracker,
  // ← falta this.config.quarantineModel
);
```

### 11. Sin graceful shutdown
**Archivo:** `src/main.ts`

No hay handler de SIGINT/SIGTERM. Si matás el proceso,
el SQLite podría quedar corrupto (hasta 10s de datos sin flush).

```typescript
process.on('SIGINT', async () => {
  console.log('\n[FortBot] Shutting down...');
  store.close();
  await gateway.disconnect();
  process.exit(0);
});
```

### 12. SQLite flush cada 10s — puede perder datos
**Archivo:** `src/store/messages.ts:65`

Si crashea entre flushes, se pierden hasta 10s de mensajes y audit entries.
Audit entries deberían persistir inmediatamente (son la evidencia de seguridad).

---

## 🔵 MEJORAS UX

### 13. Sin /pause y /resume
Poder pausar el bot sin matarlo. Útil cuando querés usar WA normalmente.

### 14. Sin respuesta a mensajes de grupos
Actualmente ignora todo lo que no sea del OWNER. Podría responder
en grupos si lo mencionan (@FortBot) o con un trigger configurable.

### 15. Sin /export — exportar historial
Exportar conversaciones a JSON/CSV para backup o análisis.

### 16. Sin /config — cambiar settings en runtime
Poder cambiar `maxMessagesPerMinute`, `sleepHour`, etc. sin reiniciar.

### 17. FTS para búsqueda
`LIKE '%query%'` no escala y no matchea parciales bien.
SQLite FTS5 sería mucho mejor para /search.

### 18. Timestamps legibles en /audit
`created_at` muestra datetime SQL puro. Mejor: "hace 5 min", "hoy 14:30".

---

## 🔵 MEJORAS ARQUITECTURA

### 19. Clasificador inteligente (chat vs task)
En vez de regex frágil, usar un micro-prompt al LLM:
"¿Esta frase es una pregunta casual o un pedido de acción? Responde: chat|task"
Es un solo token de output, rápido y barato.

### 20. Conversation summarizer (anti-amnesia avanzado)
Para conversaciones largas (>50 mensajes), comprimir el historial viejo
en un resumen y mantener los últimos 20 mensajes completos.
Esto es exactamente tu concepto de Sistema Breadcrumb de RecluseAI.

### 21. Retry inteligente en LLM calls
Si Claude CLI falla (rate limit, timeout), retry con backoff.
Ahora solo reintenta 2 veces en el planner, pero 0 en chat y quarantine.

### 22. Métricas de uso
Trackear tokens consumidos, latencia promedio, mensajes/hora,
para saber cuánto estás gastando de tu cuota Max.

---

## 📊 PRIORIZACIÓN

| # | Issue | Esfuerzo | Impacto | Prioridad |
|---|-------|----------|---------|-----------|
| 1 | Historial de conversación | 30 min | 🔴 Crítico | P0 |
| 3 | Guardar respuestas del bot | 15 min | 🔴 Crítico | P0 |
| 2 | Contexto al planner | 15 min | 🔴 Crítico | P0 |
| 10 | Fix quarantine model param | 2 min | 🟡 Bug | P1 |
| 8 | Fix confirmation race | 20 min | 🟡 Bug | P1 |
| 11 | Graceful shutdown | 10 min | 🟡 Robustez | P1 |
| 4-7 | Path/command restrictions | 45 min | 🟡 Seguridad | P1 |
| 12 | Flush inmediato audit | 5 min | 🟡 Robustez | P1 |
| 19 | Clasificador inteligente | 30 min | 🔵 UX | P2 |
| 9 | Mejorar task patterns | 15 min | 🔵 UX | P2 |
| 13-18 | Comandos nuevos | 60 min | 🔵 UX | P3 |
| 20-22 | Arquitectura avanzada | 2+ hrs | 🔵 Futuro | P3 |

---

## Meta: WhatsApp Policy 2026

Dato importante: desde el 15 de enero 2026, Meta prohíbe chatbots AI de propósito
general en WhatsApp **Business API**. FortBot usa Baileys (cuenta personal), así que
no aplica directamente. Pero es una señal de que Meta está apretando.

FortBot está OK porque:
- Usa cuenta personal, no Business API
- Es de uso propio, no distribución
- El HumanEmulator reduce la señal de bot

Riesgo residual: Meta podría extender la restricción a cuentas personales detectadas.
