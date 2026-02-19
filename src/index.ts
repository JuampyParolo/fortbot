/**
 * FORTBOT v0.4 - Main Orchestrator
 *
 *   WhatsApp Message
 *        │
 *        ▼
 *   [GATEWAY] → trust assignment + SQLite store
 *        │
 *        ├─ /command → immediate handler
 *        │
 *        ├─ group mention → chat response
 *        │
 *        ├─ LLM classifier → chat|task
 *        │    ├─ chat → [PRIVILEGED LLM + history + summarizer] → response
 *        │    └─ task → [QUEUE] → [PLANNER] → [POLICY ENGINE] → [EXECUTOR]
 *        │                                                          │
 *        │                          ├─ quarantine → [QUARANTINED LLM]
 *        │                          └─ action → exec with capabilities
 *        │
 *        └─ media → acknowledge + store
 */

import {
  IncomingMessage,
  TrustLevel,
  FortBotConfig,
  ExecutionResult,
} from './types/index.js';
import { WhatsAppGateway } from './gateway/whatsapp.js';
import { Gateway } from './gateway/interface.js';
import { PrivilegedPlanner } from './planner/privileged.js';
import { PolicyEngine } from './policy/engine.js';
import { TaintTracker } from './policy/taint.js';
import { QuarantinedLLM } from './quarantine/sandboxed.js';
import { Executor } from './executor/executor.js';
import { MessageStore } from './store/messages.js';
import { TaskQueue } from './store/queue.js';
import { createDefaultConfig } from './config/security.js';
import { callClaude, classifyIntent, summarizeHistory, llmMetrics } from './llm/claude-max.js';
import { GuardianBridge } from './guardian/bridge.js';
import { Heartbeat } from './guardian/heartbeat.js';
import { Scheduler } from './scheduler/scheduler.js';
import { transcribe, synthesize, checkVoiceCapabilities } from './voice/voice.js';
import { readFileSync, writeFileSync, mkdirSync } from 'fs';

export class FortBot {
  private config: FortBotConfig;
  private gateway: Gateway;
  private planner: PrivilegedPlanner;
  private policyEngine: PolicyEngine;
  private taintTracker: TaintTracker;
  private quarantine: QuarantinedLLM;
  private executor: Executor;
  private store: MessageStore;
  private queue: TaskQueue;
  private guardian: GuardianBridge;
  private heartbeat: Heartbeat;
  private scheduler: Scheduler;
  private soul: string;
  private isRunning = false;

  private pendingConfirmations: Map<string, (confirmed: boolean) => void> = new Map();
  private awaitingConfirmation = false;
  private isPaused = false;
  private botName = 'FortBot';

  // Rate limiting: max messages per user per minute
  private rateLimits: Map<string, { count: number; windowStart: number }> = new Map();
  private static readonly MAX_MESSAGES_PER_MINUTE = 15;
  private static readonly MAX_TASKS_PER_MINUTE = 5;

  constructor(config: Partial<FortBotConfig>, gateway?: Gateway) {
    this.config = createDefaultConfig(config);
    if (!this.config.ownerNumber) throw new Error('ownerNumber is required');

    // Load personality
    try {
      this.soul = readFileSync('./SOUL.md', 'utf-8');
    } catch {
      this.soul = 'You are FortBot, a helpful WhatsApp assistant. Be brief. Spanish (rioplatense).';
    }

    // Initialize components
    this.store = new MessageStore(this.config.dbPath);
    this.queue = new TaskQueue(10);
    this.gateway = gateway ?? new WhatsAppGateway(this.config);
    this.planner = new PrivilegedPlanner(this.config);
    this.policyEngine = new PolicyEngine(this.config);
    this.taintTracker = this.policyEngine.getTaintTracker();

    this.quarantine = new QuarantinedLLM(
      this.config.quarantineLlmEndpoint,
      this.config.useLocalQuarantine,
      this.taintTracker,
      this.config.quarantineModel as 'sonnet' | 'opus' | 'haiku',
    );

    this.guardian = new GuardianBridge(18790);

    this.heartbeat = new Heartbeat(this.guardian);
    // Add WhatsApp connection check
    this.heartbeat.addCheck(async () => ({
      name: 'WhatsApp',
      status: this.gateway ? 'ok' : 'down',
      detail: this.gateway ? 'Connected' : 'Not connected',
    }));
    // Add SQLite check
    this.heartbeat.addCheck(async () => {
      try {
        const stats = this.store.stats();
        return { name: 'SQLite', status: 'ok', detail: `${stats.totalMessages} messages` };
      } catch {
        return { name: 'SQLite', status: 'down', detail: 'Database error' };
      }
    });

    this.scheduler = new Scheduler(this.store);
    this.scheduler.onTask(async (task) => this.handleScheduledTask(task));

    this.executor = new Executor(
      this.policyEngine, this.taintTracker, this.quarantine,
      this.gateway, this.store,
      (msg) => this.requestUserConfirmation(msg),
      this.guardian,
      this.scheduler,
      { ownerNumber: this.config.ownerNumber, knownContacts: this.config.knownContacts, useDockerSandbox: this.config.useDockerSandbox },
    );

    this.gateway.onMessage((msg) => this.handleMessage(msg));
    this.gateway.onKillSwitch(() => this.emergencyStop());
  }

  async start(): Promise<void> {
    await this.store.waitReady();
    const stats = this.store.stats();
    console.log('╔══════════════════════════════════════════╗');
    console.log('║  🏰 FORTBOT v0.4 — Secure AI Agent       ║');
    console.log('╠══════════════════════════════════════════╣');
    console.log(`║  Owner:      ${this.config.ownerNumber.padEnd(25)}║`);
    console.log(`║  Kill:       ${this.config.killSwitchPhrase.padEnd(25)}║`);
    console.log(`║  Planner:    ${this.config.plannerModel.padEnd(25)}║`);
    console.log(`║  Quarantine: ${(this.config.useLocalQuarantine ? 'local' : this.config.quarantineModel).padEnd(25)}║`);
    console.log(`║  DB Encrypt: ${(process.env.FORTBOT_DB_PASSWORD ? 'AES-256-GCM' : 'OFF').padEnd(25)}║`);
    console.log(`║  Messages:   ${String(stats.totalMessages).padEnd(25)}║`);
    console.log(`║  Policies:   ${String(this.config.policies.length).padEnd(25)}║`);
    console.log('╚══════════════════════════════════════════╝');

    // Check Guardian API
    const guardianUp = await this.guardian.checkHealth();
    if (guardianUp) {
      console.log('[FortBot] 🛡️  Guardian API connected (port 18790)');
    } else {
      console.log('[FortBot] ⚠️  Guardian API offline — using TS PolicyEngine only');
      console.log('[FortBot]    Start it with: python -m core.api');
    }

    // Start heartbeat (every 60s)
    this.heartbeat.start(60_000);
    console.log('[FortBot] 💓 Heartbeat started (HEARTBEAT.md)');

    // Start scheduler
    this.scheduler.start();
    console.log('[FortBot] ⏰ Scheduler started');

    await this.gateway.connect();
    this.isRunning = true;
    console.log('[FortBot] Ready. Message me on WhatsApp.');
  }

  // ══════════════════════════════════════════
  // MESSAGE ROUTER
  // ══════════════════════════════════════════

  private async handleMessage(msg: IncomingMessage): Promise<void> {
    if (!this.isRunning) return;
    this.store.store(msg);

    // ── Confirmation handler (FIFO) ──
    if (this.awaitingConfirmation && msg.trust === TrustLevel.OWNER) {
      const text = msg.content.trim();
      const isYes = /^(y(es)?|si|sí|dale|ok|confirmo|approve|va|vamo)$/i.test(text);
      const isNo = /^(n(o)?|cancel|cancelar|nah|deny|nel)$/i.test(text);
      if (isYes || isNo) {
        const firstKey = this.pendingConfirmations.keys().next().value;
        if (firstKey !== undefined) {
          const resolve = this.pendingConfirmations.get(firstKey);
          this.pendingConfirmations.delete(firstKey);
          resolve?.(isYes);
        }
        if (this.pendingConfirmations.size === 0) this.awaitingConfirmation = false;
        return;
      }
    }

    // ── Group mention support ──
    if (msg.isGroup && msg.trust !== TrustLevel.OWNER) {
      const mentioned = this.isBotMentioned(msg.content);
      if (mentioned) {
        await this.handleGroupMention(msg);
      }
      // Ignore non-mentioned group messages from non-owner
      return;
    }

    // ── Owner-only for direct messages ──
    if (msg.trust !== TrustLevel.OWNER) {
      console.log(`[FortBot] Ignored ${msg.from} (${msg.trust})`);
      this.store.audit('ignored', { from: msg.from, trust: msg.trust });
      return;
    }

    // ── Rate limiting ──
    if (!this.checkRateLimit(msg.from, FortBot.MAX_MESSAGES_PER_MINUTE)) {
      await this.sendAndStore(msg.from, '⚠️ Demasiados mensajes. Esperá un momento.');
      this.store.audit('rate_limited', { from: msg.from });
      return;
    }

    const text = msg.content.trim();

    // Slash commands — always allowed even when paused
    if (text.startsWith('/')) {
      await this.handleCommand(text, msg);
      return;
    }

    // Pause check
    if (this.isPaused) {
      console.log('[FortBot] Paused — ignoring');
      return;
    }

    // Media messages
    if (msg.type !== 'text') {
      await this.handleMedia(msg);
      return;
    }

    // ── Route: classify → chat or task ──
    try {
      if (this.queue.pending > 0) {
        await this.sendAndStore(msg.from, `📋 En cola (${this.queue.pending} pendientes)...`);
      }

      await this.queue.enqueue(async () => {
        // Get recent context for classifier
        const recentMsgs = this.store.getConversationHistory(msg.from, 5);
        const recentCtx = recentMsgs
          .filter(m => m.type === 'text')
          .slice(-3)
          .map(m => `${m.sender_name}: ${m.content}`)
          .join('\n');

        const intent = await classifyIntent(text, recentCtx);
        console.log(`[FortBot] Intent: ${intent} ← "${text.substring(0, 50)}"`);

        if (intent === 'task') {
          await this.handleTask(text, msg);
        } else {
          await this.handleChat(text, msg);
        }
      });
    } catch (error) {
      if (String(error).includes('Queue full')) {
        await this.sendAndStore(msg.from, '⚠️ Estoy saturado, esperá un momento.');
      } else {
        console.error('[FortBot]', error);
        await this.sendAndStore(msg.from, `❌ ${error instanceof Error ? error.message : 'Error'}`);
      }
      this.store.audit('error', { error: String(error) });
    }
  }

  // ══════════════════════════════════════════
  // CHAT HANDLER (with summarizer)
  // ══════════════════════════════════════════

  private async handleChat(text: string, msg: IncomingMessage): Promise<void> {
    // Get full history
    const history = this.store.getConversationHistory(msg.from, 50);
    const textHistory = history.filter(m => m.type === 'text' && m.content.length > 0);

    // Summarize if conversation is long
    let contextBlock: string;
    if (textHistory.length > 20) {
      const { summary, recentMessages } = await summarizeHistory(
        textHistory,
        15,
        'haiku',
      );
      const recentText = recentMessages
        .map(m => `${m.sender_name}: ${m.content}`)
        .join('\n');
      contextBlock = summary
        ? `--- Summary of earlier conversation ---\n${summary}\n--- Recent messages ---\n${recentText}`
        : `--- Conversation history ---\n${recentText}`;
    } else {
      contextBlock = textHistory.length > 0
        ? `--- Conversation history ---\n${textHistory.map(m => `${m.sender_name}: ${m.content}`).join('\n')}`
        : '';
    }

    const systemPrompt = [
      this.soul,
      '\nYou are chatting with the owner via WhatsApp.',
      'Be brief (max 2-3 sentences). Spanish rioplatense.',
      'If asked about your capabilities: chat, search messages, read/write files, shell commands, web fetch, send messages — all with security confirmation.',
      contextBlock ? `\n${contextBlock}\n--- End ---` : '',
    ].join('\n');

    const response = await callClaude(systemPrompt, text, this.config.plannerModel);
    const reply = response.text.trim() || '🤷';
    await this.sendAndStore(msg.from, reply);
  }

  // ══════════════════════════════════════════
  // TASK HANDLER
  // ══════════════════════════════════════════

  private async handleTask(text: string, msg: IncomingMessage): Promise<void> {
    const startTime = Date.now();
    await this.sendAndStore(msg.from, '🔧 Planificando...');

    // Give planner recent context for reference resolution
    // SECURITY: Only include messages from OWNER or bot itself.
    // External messages (group members, unknown contacts) could inject
    // malicious instructions into the Privileged Planner prompt.
    const recentHistory = this.store.getConversationHistory(msg.from, 10);
    const contextHint = recentHistory
      .filter(m => m.type === 'text' &&
        (m.trust === TrustLevel.OWNER || m.trust === ('system' as TrustLevel) || m.sender_name === 'FortBot'))
      .slice(-5)
      .map(m => `${m.sender_name}: ${m.content}`)
      .join('\n');
    const enrichedQuery = contextHint
      ? `Recent conversation:\n${contextHint}\n\nCurrent request: ${text}`
      : text;

    const plan = await this.planner.generatePlan(enrichedQuery);

    if (plan.steps.length === 0) {
      // Fallback to chat
      await this.handleChat(text, msg);
      return;
    }

    // Validate
    const validated = this.policyEngine.validatePlan(plan);
    if (validated.violations.length > 0) {
      const criticals = validated.violations.filter(v => v.severity === 'critical');
      if (criticals.length > 0) {
        await this.sendAndStore(msg.from,
          '🛡️ Bloqueado:\n' + criticals.map(v => `• ${v.reason}`).join('\n'));
        this.store.audit('plan_blocked', { planId: plan.id, violations: criticals });
        return;
      }
      const warnings = validated.violations.filter(v => v.severity === 'warning');
      if (warnings.length > 0) {
        await this.sendAndStore(msg.from, '⚠️ ' + warnings.map(v => v.reason).join('; '));
      }
    }

    if (!validated.approved) {
      await this.sendAndStore(msg.from, '🛡️ Plan rechazado por política de seguridad.');
      return;
    }

    // Execute
    await this.sendAndStore(msg.from, `⚡ Ejecutando (${validated.steps.length} pasos)...`);
    const results = await this.executor.executePlan(validated);
    const duration = Date.now() - startTime;

    await this.sendAndStore(msg.from, this.formatResults(results, duration));
    this.store.audit('plan_executed', {
      planId: plan.id, steps: results.length,
      ok: results.filter(r => r.success).length,
      fail: results.filter(r => !r.success).length,
      ms: duration,
    });
  }

  // ══════════════════════════════════════════
  // GROUP MENTION HANDLER
  // ══════════════════════════════════════════

  private isBotMentioned(text: string): boolean {
    const lower = text.toLowerCase();
    const triggers = ['@fortbot', '@fort', 'fortbot', 'fort bot'];
    return triggers.some(t => lower.includes(t));
  }

  private async handleGroupMention(msg: IncomingMessage): Promise<void> {
    // Remove the mention from the text
    let text = msg.content.replace(/@?fort\s*bot/gi, '').trim();
    if (!text) text = 'Hola';

    const systemPrompt = [
      this.soul,
      '\nYou are in a WhatsApp group. Someone mentioned you.',
      `The person is: ${msg.fromName}`,
      'Be brief (1-2 sentences). Friendly. Spanish rioplatense.',
      'You cannot execute tasks in group chats — only chat.',
    ].join('\n');

    const response = await callClaude(systemPrompt, text, 'haiku');
    const reply = response.text.trim() || '🤷';
    const jid = msg.groupId ?? msg.from;
    this.store.storeOutgoing(jid, reply);
    await this.gateway.sendMessage(jid, reply);
  }

  // ══════════════════════════════════════════
  // MEDIA HANDLER
  // ══════════════════════════════════════════

  private async handleMedia(msg: IncomingMessage): Promise<void> {
    // ── Audio: transcribe and process as text ──
    if (msg.type === 'audio' && msg.mediaBuffer) {
      try {
        await this.sendAndStore(msg.from, '🎤 Transcribiendo audio...');
        const result = await transcribe(msg.mediaBuffer);

        if (result.backend === 'fallback' || !result.text || result.text.startsWith('[')) {
          // Transcription not available
          await this.sendAndStore(msg.from, result.text || '⚠️ No se pudo transcribir el audio.');
          return;
        }

        console.log(`[FortBot] 🎤 Transcription (${result.backend}): "${result.text.substring(0, 80)}"`);
        this.store.audit('audio_transcribed', { backend: result.backend, length: result.text.length });

        // Re-route as text message
        const textMsg: IncomingMessage = {
          ...msg,
          type: 'text',
          content: result.text,
        };
        await this.sendAndStore(msg.from, `🎤 _"${result.text}"_`);
        await this.handleMessage(textMsg);
        return;
      } catch (err) {
        console.error('[FortBot] Transcription error:', err);
        await this.sendAndStore(msg.from, '⚠️ Error al transcribir audio.');
        return;
      }
    }

    // ── Other media types ──
    const labels: Record<string, string> = {
      image: '🖼️ Imagen', video: '🎥 Video', audio: '🎤 Audio', document: '📄 Documento',
    };
    let reply = `${labels[msg.type] ?? msg.type} recibido y guardado.`;

    if (msg.type === 'image' && msg.content && msg.content !== '[image]') {
      reply += `\nCaption: "${msg.content}"`;
    } else if (msg.type === 'document' && msg.content && msg.content !== '[document]') {
      reply += `\nArchivo: ${msg.content}`;
    } else if (msg.type === 'audio' && !msg.mediaBuffer) {
      reply += '\n\n💡 Para transcribir audio, instalá: ffmpeg + whisper (pip install openai-whisper)';
    }
    await this.sendAndStore(msg.from, reply);
  }

  // ══════════════════════════════════════════
  // COMMANDS
  // ══════════════════════════════════════════

  private async handleCommand(text: string, msg: IncomingMessage): Promise<void> {
    const parts = text.split(/\s+/);
    const cmd = parts[0].toLowerCase();
    const args = parts.slice(1).join(' ');

    switch (cmd) {
      case '/status': {
        const stats = this.store.stats();
        const metrics = llmMetrics.get();
        const uptime = this.formatDuration(metrics.uptimeMs);
        const qi = this.queue.pending > 0 ? `\n⏳ Queue: ${this.queue.pending}` : '';
        const paused = this.isPaused ? '\n⏸️ PAUSADO' : '';
        const guardianStatus = this.guardian.isConnected ? '🛡️ Guardian: ON' : '⚠️ Guardian: OFF';
        const voiceCaps = checkVoiceCapabilities();
        const voiceStatus = voiceCaps.stt ? '🎤 Voice: STT' + (voiceCaps.tts ? '+TTS' : '') : '🎤 Voice: OFF';
        const taskCount = this.scheduler.list().length;
        const schedStatus = taskCount > 0 ? `⏰ Tasks: ${taskCount}` : '⏰ Tasks: 0';
        await this.sendAndStore(msg.from,
          `🏰 FortBot v0.4\n` +
          `📨 ${stats.totalMessages} msgs | 💬 ${stats.uniqueChats} chats\n` +
          `🤖 ${metrics.totalCalls} LLM calls | ⚡ ${metrics.averageDurationMs}ms avg\n` +
          `🔁 ${metrics.totalRetries} retries | ❌ ${metrics.totalErrors} errors\n` +
          `${guardianStatus} | ${voiceStatus}\n` +
          `${schedStatus}\n` +
          `⏱️ Uptime: ${uptime}${qi}${paused}`);
        break;
      }

      case '/search': {
        if (!args) { await this.sendAndStore(msg.from, 'Uso: /search <texto>'); break; }
        const results = this.store.searchMessages(args, undefined, 5);
        if (results.length === 0) {
          await this.sendAndStore(msg.from, `Sin resultados para "${args}".`);
          break;
        }
        const lines = results.map(m => {
          const preview = m.content.length > 60 ? m.content.substring(0, 60) + '…' : m.content;
          return `[${m.sender_name}] ${preview}`;
        });
        await this.sendAndStore(msg.from, `🔍 ${results.length} resultados:\n${lines.join('\n')}`);
        break;
      }

      case '/audit': {
        const limit = Number(args) || 5;
        const entries = this.store.recentAudit(limit);
        if (entries.length === 0) {
          await this.sendAndStore(msg.from, 'Audit log vacío.');
          break;
        }
        const lines = entries.map(e => `[${this.relativeTime(e.created_at)}] ${e.event}`);
        await this.sendAndStore(msg.from, `📋 Últimas ${entries.length}:\n${lines.join('\n')}`);
        break;
      }

      case '/export': {
        const chatJid = args || msg.from;
        const messages = this.store.getConversationHistory(chatJid, 500);
        if (messages.length === 0) {
          await this.sendAndStore(msg.from, 'Sin mensajes para exportar.');
          break;
        }
        const csv = 'timestamp,sender,content\n' +
          messages.map(m =>
            `${m.timestamp},"${m.sender_name}","${m.content.replace(/"/g, '""')}"`
          ).join('\n');
        const exportDir = '/tmp/fortbot';
        try { mkdirSync(exportDir, { recursive: true }); } catch {}
        const exportPath = `${exportDir}/export-${Date.now()}.csv`;
        writeFileSync(exportPath, csv, 'utf-8');
        await this.sendAndStore(msg.from,
          `📤 Exportados ${messages.length} mensajes → ${exportPath}\n(Próximamente: envío como documento)`);
        break;
      }

      case '/metrics': {
        const m = llmMetrics.get();
        const modelBreakdown = Object.entries(m.callsByModel)
          .map(([k, v]) => `  ${k}: ${v}`)
          .join('\n');
        await this.sendAndStore(msg.from,
          `📊 LLM Metrics:\n` +
          `Calls: ${m.totalCalls} | Errors: ${m.totalErrors} | Retries: ${m.totalRetries}\n` +
          `Avg latency: ${m.averageDurationMs}ms\n` +
          `Total time in LLM: ${this.formatDuration(m.totalDurationMs)}\n` +
          `By model:\n${modelBreakdown || '  (none yet)'}`);
        break;
      }

      case '/config': {
        if (!args) {
          await this.sendAndStore(msg.from,
            '⚙️ Config:\n' +
            `Planner: ${this.config.plannerModel}\n` +
            `Quarantine: ${this.config.quarantineModel}\n` +
            `Max steps: ${this.config.maxPlanSteps}\n` +
            `Human wake: ${this.config.humanConfig?.wakeHour ?? 8}h\n` +
            `Human sleep: ${this.config.humanConfig?.sleepHour ?? 23}h\n` +
            '\nUsá /config <key> <value> para cambiar.');
          break;
        }
        const [key, ...valParts] = args.split(/\s+/);
        const value = valParts.join(' ');
        const changed = this.applyRuntimeConfig(key, value);
        await this.sendAndStore(msg.from, changed
          ? `✅ ${key} = ${value}`
          : `❌ Config inválido: ${key}`);
        break;
      }

      case '/pause':
        this.isPaused = true;
        await this.sendAndStore(msg.from, '⏸️ Bot pausado. Usá /resume para reanudar.');
        this.store.audit('paused', {});
        break;

      case '/resume':
        this.isPaused = false;
        await this.sendAndStore(msg.from, '▶️ Bot reanudado.');
        this.store.audit('resumed', {});
        break;

      case '/help':
        await this.sendAndStore(msg.from,
          '🏰 FortBot v0.4 Commands:\n' +
          '/status — stats + métricas LLM\n' +
          '/search <text> — buscar en mensajes\n' +
          '/audit [n] — log de auditoría\n' +
          '/metrics — métricas detalladas del LLM\n' +
          '/tasks — tareas programadas\n' +
          '/export [jid] — exportar historial a CSV\n' +
          '/config [key val] — ver/cambiar config\n' +
          '/pause — pausar bot\n' +
          '/resume — reanudar bot\n' +
          '/help — esto');
        break;

      case '/tasks': {
        const tasks = this.scheduler.list();
        if (tasks.length === 0) {
          await this.sendAndStore(msg.from, '⏰ No hay tareas programadas.');
        } else {
          const lines = tasks.map(t => {
            const when = new Date(t.nextRun).toLocaleString('es-AR');
            const recurring = t.cron ? ` 🔁 ${t.cron}` : '';
            return `• ${t.description}\n  📅 ${when}${recurring}\n  🆔 ${t.id}`;
          });
          await this.sendAndStore(msg.from, `⏰ Tareas programadas (${tasks.length}):\n\n${lines.join('\n\n')}`);
        }
        break;
      }

      default:
        await this.sendAndStore(msg.from, `Comando desconocido: ${cmd}\nUsá /help`);
    }
  }

  // ══════════════════════════════════════════
  // RUNTIME CONFIG
  // ══════════════════════════════════════════

  private applyRuntimeConfig(key: string, value: string): boolean {
    switch (key.toLowerCase()) {
      case 'planner':
      case 'planner_model':
        if (['sonnet', 'opus', 'haiku'].includes(value)) {
          (this.config as unknown as Record<string, unknown>).plannerModel = value;
          return true;
        }
        return false;
      case 'quarantine':
      case 'quarantine_model':
        if (['sonnet', 'opus', 'haiku'].includes(value)) {
          (this.config as unknown as Record<string, unknown>).quarantineModel = value;
          return true;
        }
        return false;
      case 'max_steps':
      case 'maxsteps':
        const n = Number(value);
        if (n > 0 && n <= 20) {
          this.config.maxPlanSteps = n;
          return true;
        }
        return false;
      default:
        return false;
    }
  }

  // ══════════════════════════════════════════
  // CONFIRMATIONS
  // ══════════════════════════════════════════

  private async handleScheduledTask(task: import('./scheduler/scheduler.js').ScheduledTask): Promise<void> {
    try {
      if (task.action === 'reminder') {
        // Send reminder to owner
        const to = String(task.params['to'] ?? this.config.ownerNumber);
        const msg = String(task.params['message'] ?? task.description);
        // SECURITY: Reminders only go to owner
        const jid = `${this.config.ownerNumber}@s.whatsapp.net`;
        await this.sendAndStore(jid, `⏰ Recordatorio: ${msg}`);
      } else if (task.action === 'send_message') {
        const to = String(task.params['to'] ?? '');
        const content = String(task.params['message'] ?? task.params['content'] ?? '');
        if (to && content) {
          // SECURITY: Validate recipient against known contacts (same as Executor)
          const normalizedTo = to.replace(/[^0-9]/g, '');
          const normalizedOwner = this.config.ownerNumber.replace(/[^0-9]/g, '');
          const normalizedKnown = this.config.knownContacts.map(c => c.replace(/[^0-9]/g, ''));
          const isOwner = normalizedTo === normalizedOwner || normalizedTo.endsWith(normalizedOwner) || normalizedOwner.endsWith(normalizedTo);
          const isKnown = normalizedKnown.some(k => normalizedTo === k || normalizedTo.endsWith(k) || k.endsWith(normalizedTo));

          if (!isOwner && !isKnown) {
            this.store.audit('scheduled_send_blocked', { taskId: task.id, to, reason: 'unknown_recipient' });
            console.error(`[Scheduler] BLOCKED send to unknown recipient: ${to}`);
            return;
          }
          await this.sendAndStore(to, content);
        }
      } else {
        // Generic task — log it
        console.log(`[Scheduler] Fired task ${task.id}: ${task.action} — ${task.description}`);
        this.store.audit('scheduled_task_fired', { taskId: task.id, action: task.action });
      }
    } catch (err) {
      console.error(`[Scheduler] Failed to execute task ${task.id}:`, err);
    }
  }

  private async requestUserConfirmation(message: string): Promise<boolean> {
    const id = `confirm_${Date.now()}`;
    await this.sendAndStore(this.config.ownerNumber, message);
    this.awaitingConfirmation = true;
    return new Promise<boolean>((resolve) => {
      this.pendingConfirmations.set(id, resolve);
      setTimeout(() => {
        if (this.pendingConfirmations.has(id)) {
          this.pendingConfirmations.delete(id);
          if (this.pendingConfirmations.size === 0) this.awaitingConfirmation = false;
          resolve(false);
          console.log('[FortBot] Confirmation timeout → denied');
          // Notify owner that the action was auto-denied
          this.sendAndStore(this.config.ownerNumber, '⏱️ Timeout — acción denegada automáticamente (60s sin respuesta).').catch(() => {});
        }
      }, 60000);
    });
  }

  // ══════════════════════════════════════════
  // HELPERS
  // ══════════════════════════════════════════

  /** Send message and persist to store */
  private async sendAndStore(jid: string, content: string): Promise<void> {
    this.store.storeOutgoing(jid, content);
    await this.gateway.sendMessage(jid, content);
  }

  // ══════════════════════════════════════════
  // RATE LIMITING
  // ══════════════════════════════════════════

  private checkRateLimit(userId: string, maxPerMinute: number): boolean {
    const now = Date.now();
    const window = this.rateLimits.get(userId);
    if (!window || now - window.windowStart > 60_000) {
      this.rateLimits.set(userId, { count: 1, windowStart: now });
      return true;
    }
    if (window.count >= maxPerMinute) return false;
    window.count++;
    return true;
  }

  // ══════════════════════════════════════════
  // FORMATTING
  // ══════════════════════════════════════════

  private formatResults(results: ExecutionResult[], totalDuration: number): string {
    const ok = results.filter(r => r.success);
    const fail = results.filter(r => !r.success);
    const lines: string[] = [];

    if (ok.length > 0) {
      lines.push(`✅ ${ok.length}/${results.length} OK`);
      for (const r of ok) {
        if (r.output?.value != null) {
          const val = typeof r.output.value === 'object'
            ? JSON.stringify(r.output.value).substring(0, 300)
            : String(r.output.value).substring(0, 300);
          lines.push(`→ ${val}`);
        }
      }
    }
    if (fail.length > 0) {
      lines.push(`❌ ${fail.length} fallaron:`);
      for (const r of fail) lines.push(`→ ${r.error?.substring(0, 100)}`);
    }
    lines.push(`⏱️ ${totalDuration}ms`);
    return lines.join('\n');
  }

  /** Relative time: "hace 5 min", "hace 2h", "hoy 14:30" */
  private relativeTime(sqlDatetime: string): string {
    try {
      const date = new Date(sqlDatetime + 'Z');
      const now = Date.now();
      const diff = now - date.getTime();
      if (diff < 60000) return 'hace segundos';
      if (diff < 3600000) return `hace ${Math.floor(diff / 60000)} min`;
      if (diff < 86400000) return `hace ${Math.floor(diff / 3600000)}h`;
      return date.toLocaleDateString('es-AR', { day: 'numeric', month: 'short' });
    } catch {
      return sqlDatetime;
    }
  }

  private formatDuration(ms: number): string {
    if (ms < 60000) return `${Math.round(ms / 1000)}s`;
    if (ms < 3600000) return `${Math.floor(ms / 60000)}m ${Math.round((ms % 60000) / 1000)}s`;
    return `${Math.floor(ms / 3600000)}h ${Math.floor((ms % 3600000) / 60000)}m`;
  }

  // ══════════════════════════════════════════
  // EMERGENCY
  // ══════════════════════════════════════════

  private async emergencyStop(): Promise<void> {
    console.log('[FortBot] 🛑 EMERGENCY STOP');
    this.isRunning = false;
    for (const [, resolve] of this.pendingConfirmations) resolve(false);
    this.pendingConfirmations.clear();
    this.store.audit('emergency_stop', { timestamp: Date.now() });
    this.store.close();
    await this.gateway.disconnect();
    process.exit(0);
  }
}
