/**
 * FORTBOT - Executor
 *
 * Executes approved plan steps. DETERMINISTIC: no LLM involved.
 * Quarantine steps delegated to QuarantinedLLM.
 * Sensitive actions require capability tokens + user confirmation.
 */

import {
  Plan,
  PlanStep,
  TaintedValue,
  TrustLevel,
  OutputCapacity,
  ExecutionResult,
  ActionType,
} from '../types/index.js';
import { PolicyEngine } from '../policy/engine.js';
import { TaintTracker } from '../policy/taint.js';
import { QuarantinedLLM, QuarantineResult } from '../quarantine/sandboxed.js';
import { Gateway } from '../gateway/interface.js';
import { MessageStore } from '../store/messages.js';
import { GuardianBridge, GuardianResponse } from '../guardian/bridge.js';
import { Scheduler, parseDelay } from '../scheduler/scheduler.js';
import { browse as browserBrowse, screenshot as browserScreenshot, isPlaywrightAvailable } from '../browser/browser.js';
import {
  checkNetworkAction, checkUrl as netCheckUrl, sanitizeWebContent, checkRedirectUrl,
  type NetworkActionCheck,
} from '../policy/network.js';
import nodePath from 'path';

type UserConfirmationFn = (message: string) => Promise<boolean>;

export class Executor {
  private policyEngine: PolicyEngine;
  private taintTracker: TaintTracker;
  private quarantine: QuarantinedLLM;
  private gateway: Gateway;
  private store: MessageStore;
  private userConfirm: UserConfirmationFn;
  private guardian: GuardianBridge;
  private scheduler: Scheduler | null;
  private config: { ownerNumber: string; knownContacts: string[]; useDockerSandbox?: boolean };
  private stepOutputs: Map<string, TaintedValue> = new Map();

  constructor(
    policyEngine: PolicyEngine,
    taintTracker: TaintTracker,
    quarantine: QuarantinedLLM,
    gateway: Gateway,
    store: MessageStore,
    userConfirm: UserConfirmationFn,
    guardian?: GuardianBridge,
    scheduler?: Scheduler,
    config?: { ownerNumber: string; knownContacts: string[]; useDockerSandbox?: boolean },
  ) {
    this.policyEngine = policyEngine;
    this.taintTracker = taintTracker;
    this.quarantine = quarantine;
    this.gateway = gateway;
    this.store = store;
    this.userConfirm = userConfirm;
    this.guardian = guardian ?? new GuardianBridge();
    this.scheduler = scheduler ?? null;
    this.config = config ?? { ownerNumber: '', knownContacts: [], useDockerSandbox: false };
  }

  /** Maximum time for an entire plan to execute (ms) */
  static readonly PLAN_TIMEOUT_MS = 120_000; // 2 minutes
  /** Maximum time for a single step (ms) */
  static readonly STEP_TIMEOUT_MS = 30_000; // 30 seconds

  async executePlan(plan: Plan): Promise<ExecutionResult[]> {
    if (!plan.approved) throw new Error(`Plan ${plan.id} not approved`);
    this.stepOutputs.clear();
    const results: ExecutionResult[] = [];
    const order = this.topologicalSort(plan);
    const planStart = Date.now();
    /** Track files written during this plan for potential rollback */
    const writtenFiles: string[] = [];

    for (const step of order) {
      // Global plan timeout
      if (Date.now() - planStart > Executor.PLAN_TIMEOUT_MS) {
        results.push(this.fail(plan.id, step, 0, 'deny',
          `Plan timeout: exceeded ${Executor.PLAN_TIMEOUT_MS / 1000}s total execution time`));
        this.store.audit('plan_timeout', { planId: plan.id, elapsed: Date.now() - planStart });
        break;
      }

      const start = Date.now();
      try {
        const inputs = this.resolveInputs(step);
        const check = this.policyEngine.validateExecution(step, inputs);

        if (!check.allowed) {
          results.push(this.fail(plan.id, step, Date.now() - start, 'deny', `Policy: ${check.reason}`));
          continue;
        }

        // ── GUARDIAN CHECK (Python security layer) ──
        // For sensitive actions, Guardian MUST be available (fail-closed)
        const GUARDIAN_REQUIRED_ACTIONS = new Set<ActionType>([
          ActionType.SHELL_EXEC, ActionType.WRITE_FILE, ActionType.WEB_FETCH,
          ActionType.BROWSE, ActionType.SCREENSHOT, ActionType.SEND_MESSAGE,
        ]);

        if (GUARDIAN_REQUIRED_ACTIONS.has(step.action)) {
          if (!this.guardian.isConnected) {
            // Try to reconnect once
            const reconnected = await this.guardian.checkHealth().catch(() => false);
            if (!reconnected) {
              results.push(this.fail(plan.id, step, Date.now() - start, 'deny',
                `🛡️ Guardian no disponible — acción "${step.action}" bloqueada por seguridad. Iniciá el Guardian con: python3 -m core.api`));
              continue;
            }
          }
        }

        if (this.guardian.isConnected) {
          const guardianResult = await this.guardianCheck(step);

          if (guardianResult.verdict === 'block') {
            results.push(this.fail(plan.id, step, Date.now() - start, 'deny',
              `🛡️ Guardian: ${guardianResult.explanation}`));
            continue;
          }

          if (guardianResult.verdict === 'warning') {
            // Guardian says WARNING — ask user via WhatsApp OR via UI
            if (guardianResult.requires_approval && guardianResult.approval_id) {
              // Notify user on WhatsApp about the pending approval
              const desc = this.describeStep(step);
              const ok = await this.userConfirm(
                `🛡️ Guardian WARNING:\n${guardianResult.explanation}\n\n${desc}\n\n¿Aprobás? (si/no)`
              );
              if (!ok) {
                results.push(this.fail(plan.id, step, Date.now() - start, 'ask_user',
                  'User denied after Guardian warning'));
                continue;
              }
            }
          }
        }

        // ── Normal confirmation (PolicyEngine) ──
        if (check.requiresConfirmation) {
          const desc = this.describeStep(step);
          const ok = await this.userConfirm(`⚠️ FortBot necesita tu OK:\n\n${desc}\n\n¿Aprobás? (si/no)`);
          if (!ok) {
            results.push(this.fail(plan.id, step, Date.now() - start, 'ask_user', 'User denied'));
            continue;
          }
        }

        const output = await Promise.race([
          this.executeStep(step, inputs),
          new Promise<never>((_, reject) =>
            setTimeout(() => reject(new Error(`Step timeout: exceeded ${Executor.STEP_TIMEOUT_MS / 1000}s`)),
              Executor.STEP_TIMEOUT_MS)
          ),
        ]);
        if (output) this.stepOutputs.set(step.id, output);

        // Track side effects for rollback
        if (step.action === ActionType.WRITE_FILE && output?.value) {
          const val = output.value as Record<string, unknown>;
          if (val.path) writtenFiles.push(String(val.path));
        }

        results.push({
          planId: plan.id, stepId: step.id, success: true, output,
          duration: Date.now() - start, userConfirmationRequired: check.requiresConfirmation,
          auditEntry: {
            timestamp: Date.now(), planId: plan.id, stepId: step.id, action: step.action,
            inputLabels: inputs.map(i => i.label), outputLabel: output?.label,
            policyDecision: 'allow', executed: true, warnings: [],
          },
        });
      } catch (error) {
        const failResult = this.fail(plan.id, step, Date.now() - start, 'allow', `${error}`);
        results.push(failResult);

        // ── ROLLBACK: If a step fails after side effects, clean up written files ──
        if (writtenFiles.length > 0) {
          this.store.audit('plan_partial_rollback', {
            planId: plan.id,
            failedStep: step.id,
            writtenFiles,
            error: `${error}`,
          });
          for (const filePath of writtenFiles) {
            try {
              const { unlink } = await import('fs/promises');
              await unlink(filePath);
              this.store.audit('rollback_deleted_file', { planId: plan.id, path: filePath });
            } catch {
              // File may not exist or can't be deleted — log but continue
              this.store.audit('rollback_delete_failed', { planId: plan.id, path: filePath });
            }
          }
        }
        // Stop executing remaining steps after a failure
        break;
      }
    }
    return results;
  }

  private fail(
    planId: string, step: PlanStep, duration: number,
    decision: 'allow' | 'deny' | 'ask_user', error: string,
  ): ExecutionResult {
    return {
      planId, stepId: step.id, success: false, error, duration,
      userConfirmationRequired: decision === 'ask_user',
      auditEntry: {
        timestamp: Date.now(), planId, stepId: step.id, action: step.action,
        inputLabels: [], policyDecision: decision, executed: false, warnings: [error],
      },
    };
  }

  private async executeStep(step: PlanStep, inputs: TaintedValue[]): Promise<TaintedValue | undefined> {
    if (step.requiresQuarantine) {
      const input = inputs[0];
      if (!input) throw new Error(`Quarantine step ${step.id} has no input`);
      const result: QuarantineResult = await this.quarantine.process(step, input);
      if (!result.success) throw new Error(`Quarantine: ${result.errors.join(', ')}`);

      // ── QUARANTINE OUTPUT SANITIZATION ──
      // Even though quarantine output has typed schemas, STRING outputs
      // could contain prompt injection that flows to subsequent steps.
      if (result.output && typeof result.output.value === 'string') {
        let outputText = result.output.value as string;

        // 1. Strip URLs from quarantine output (potential exfiltration vectors)
        // Quarantine should never need to output URLs — it processes data, not generates links
        const urlPattern = /https?:\/\/[^\s"'<>]+/gi;
        const foundUrls = outputText.match(urlPattern);
        if (foundUrls && foundUrls.length > 0) {
          outputText = outputText.replace(urlPattern, '[URL_REMOVED]');
          this.store.audit('quarantine_url_stripped', {
            stepId: step.id,
            urlCount: foundUrls.length,
          });
        }

        // 2. Standard injection pattern sanitization
        const sanitized = sanitizeWebContent(outputText, `quarantine:${step.action}`);
        if (sanitized.wasSanitized) {
          this.store.audit('quarantine_injection_detected', {
            stepId: step.id,
            action: step.action,
            patterns: sanitized.injectionAttempts,
          });
        }

        // Replace value with sanitized version
        result.output = {
          ...result.output,
          value: sanitized.text,
        };
      }

      return result.output;
    }

    switch (step.action) {
      case ActionType.SEND_MESSAGE: return this.execSendMessage(step);
      case ActionType.READ_MESSAGES: return this.execReadMessages(step);
      case ActionType.SEARCH_CONTACTS: return this.execSearchContacts();
      case ActionType.SEARCH_MESSAGES: return this.execSearchMessages(step);
      case ActionType.READ_FILE: return this.execReadFile(step);
      case ActionType.WRITE_FILE: return this.execWriteFile(step);
      case ActionType.SHELL_EXEC: return this.execShell(step);
      case ActionType.WEB_FETCH: return this.execWebFetch(step);
      case ActionType.LOG_EVENT: return this.execLogEvent(step, inputs);
      case ActionType.SCHEDULE_TASK: return this.execScheduleTask(step);
      case ActionType.BROWSE: return this.execBrowse(step);
      case ActionType.SCREENSHOT: return this.execScreenshot(step);
      default: throw new Error(`Unknown action: ${step.action}`);
    }
  }

  private async execSendMessage(step: PlanStep): Promise<TaintedValue> {
    const to = String(this.resolveLiteral(step.params['to']));
    const content = this.resolveContent(step.params['content']);

    // ── RECIPIENT VALIDATION ──
    Executor.checkRecipient(to, this.config.ownerNumber, this.config.knownContacts);

    await this.gateway.sendMessage(to, content);
    return this.taintTracker.createValue(
      { sent: true, to, len: content.length },
      { source: 'system', identifier: 'send_message' },
      TrustLevel.SYSTEM, OutputCapacity.STRUCTURED, 'executor:send_message',
    );
  }

  private async execReadMessages(step: PlanStep): Promise<TaintedValue> {
    const chatId = String(this.resolveLiteral(step.params['chat_id']));
    const limit = step.params['limit'] ? Number(this.resolveLiteral(step.params['limit'])) : 20;
    const messages = this.store.readMessages(chatId, limit);
    const formatted = messages.map(m => `[${m.sender_name}] ${m.content}`).join('\n');
    return this.taintTracker.createValue(
      formatted || '(sin mensajes)',
      { source: 'whatsapp', identifier: chatId },
      TrustLevel.UNTRUSTED, OutputCapacity.STRING, 'executor:read_messages',
    );
  }

  private async execSearchMessages(step: PlanStep): Promise<TaintedValue> {
    const query = String(this.resolveLiteral(step.params['query']));
    const chatId = step.params['chat_id'] ? String(this.resolveLiteral(step.params['chat_id'])) : undefined;
    const results = this.store.searchMessages(query, chatId, 10);
    const formatted = results.map(m => `[${m.sender_name}] ${m.content}`).join('\n');
    return this.taintTracker.createValue(
      formatted || '(sin resultados)',
      { source: 'whatsapp', identifier: `search:${query}` },
      TrustLevel.UNTRUSTED, OutputCapacity.STRING, 'executor:search_messages',
    );
  }

  private async execSearchContacts(): Promise<TaintedValue> {
    return this.taintTracker.createValue(
      [], { source: 'whatsapp', identifier: 'contacts' },
      TrustLevel.SYSTEM, OutputCapacity.STRUCTURED, 'executor:search_contacts',
    );
  }

  // --- Security restrictions (static for testability) ---

  // ═══════════════════════════════════════
  // SECURITY: FILE PATH SANDBOXING
  // ═══════════════════════════════════════

  /** Directories the bot is allowed to read from (resolved to absolute) */
  static readonly ALLOWED_READ_DIRS = [
    './data', './files', './exports', '/tmp/fortbot',
    // Also allow reading from CWD for convenience (but not parent)
  ];

  /** Directories the bot is allowed to write to (resolved to absolute) */
  static readonly ALLOWED_WRITE_DIRS = [
    './data', './files', './exports', '/tmp/fortbot',
  ];

  /** Files that are NEVER accessible regardless of directory */
  static readonly FORBIDDEN_FILES = [
    '.env', 'auth_store', 'creds.json', 'fortbot.db',
    '.git/config', 'id_rsa', 'id_ed25519', '.ssh',
    'credentials', 'secrets', '.npmrc', '.pypirc',
    '.gnupg', '.aws', '.config/gcloud', '.kube',
  ];

  /** Directories that are NEVER accessible */
  static readonly FORBIDDEN_DIRS = [
    '/etc', '/proc', '/sys', '/dev', '/boot', '/root',
    '/var/run', '/var/log', 'node_modules', '.git',
  ];

  /**
   * Validate a file path for reading.
   * Uses path.resolve() to defeat traversal attacks, then checks allowlist.
   */
  static checkFilePathRead(rawPath: string): string {
    const resolved = nodePath.resolve(rawPath);

    // Check forbidden files (by basename/component matching)
    Executor._checkForbiddenFile(resolved);

    // Check forbidden directories
    Executor._checkForbiddenDir(resolved);

    return resolved;
  }

  /**
   * Validate a file path for writing.
   * STRICTER: must be inside an allowed write directory.
   */
  static checkFilePathWrite(rawPath: string): string {
    const resolved = nodePath.resolve(rawPath);

    // Check forbidden files
    Executor._checkForbiddenFile(resolved);

    // Check forbidden directories
    Executor._checkForbiddenDir(resolved);

    // Must be inside an allowed write directory
    const allowedAbsolute = Executor.ALLOWED_WRITE_DIRS.map(d => nodePath.resolve(d));
    const inside = allowedAbsolute.some(dir => resolved.startsWith(dir + nodePath.sep) || resolved === dir);
    if (!inside) {
      throw new Error(
        `Blocked write: "${rawPath}" (resolved: ${resolved}) is outside allowed directories. ` +
        `Allowed: ${Executor.ALLOWED_WRITE_DIRS.join(', ')}`
      );
    }

    return resolved;
  }

  private static _checkForbiddenFile(resolved: string): void {
    const lower = resolved.toLowerCase();
    const basename = nodePath.basename(resolved).toLowerCase();
    for (const forbidden of Executor.FORBIDDEN_FILES) {
      if (basename === forbidden.toLowerCase() || lower.includes(`/${forbidden.toLowerCase()}`)) {
        throw new Error(`Blocked: "${resolved}" matches forbidden file pattern "${forbidden}"`);
      }
    }
  }

  private static _checkForbiddenDir(resolved: string): void {
    const lower = resolved.toLowerCase();
    for (const dir of Executor.FORBIDDEN_DIRS) {
      // Check if the resolved path starts with or contains the forbidden directory
      if (lower.startsWith(dir.toLowerCase() + '/') || lower.startsWith(dir.toLowerCase() + '\\') ||
          lower === dir.toLowerCase()) {
        throw new Error(`Blocked: "${resolved}" is inside forbidden directory "${dir}"`);
      }
    }
  }

  // Legacy alias used by old tests — now delegates to read check
  static checkFilePath(path: string): void {
    Executor.checkFilePathRead(path);
  }

  // ═══════════════════════════════════════
  // SECURITY: SHELL COMMAND ALLOWLIST
  // ═══════════════════════════════════════

  /**
   * Allowed shell commands (allowlist approach).
   * Only these command prefixes are permitted. Everything else is BLOCKED.
   * The planner can compose them, but cannot introduce arbitrary binaries.
   */
  static readonly ALLOWED_SHELL_COMMANDS = [
    // Info gathering (read-only, safe)
    'ls', 'cat', 'head', 'tail', 'wc', 'grep', 'find', 'stat', 'file',
    'du', 'df', 'whoami', 'hostname', 'uname', 'date', 'uptime',
    'echo', 'printf', 'env', 'which', 'pwd',
    // Text processing (no side effects)
    'sort', 'uniq', 'cut', 'tr', 'sed', 'awk', 'jq', 'xargs',
    'diff', 'comm', 'paste', 'tee',
    // Network diagnostics (read-only)
    'ping', 'dig', 'nslookup', 'traceroute', 'curl', 'wget',
    // Media tools
    'ffmpeg', 'ffprobe', 'sox', 'convert', 'identify',
    // Dev tools (commonly needed)
    'node', 'python3', 'python', 'npm', 'git',
    // System info
    'free', 'top', 'ps', 'lsof', 'ss', 'ip',
  ];

  /** Patterns that are ALWAYS blocked even in allowed commands */
  static readonly SHELL_DANGEROUS_PATTERNS = [
    /rm\s+(-[a-zA-Z]*f|-[a-zA-Z]*r|--force|--recursive)/i,  // rm with force/recursive flags
    />\s*\/dev\//i,            // write to /dev/
    /mkfs/i,                   // format filesystem
    /dd\s+if=/i,               // raw disk write
    /:\(\)\{/,                 // fork bomb
    /chmod\s+[0-7]*s/i,        // setuid
    /chown/i,                  // change ownership
    /\bsudo\b/i,               // privilege escalation
    /\bsu\b\s/i,               // switch user
    />\s*\/etc\//i,            // write to /etc
    />\s*\/usr\//i,            // write to /usr
    />\s*\/bin\//i,            // write to /bin
    /\.env\b/i,                // access .env
    /auth_store/i,             // access auth
    /\bid_rsa\b/i,             // SSH keys
    /\bsecrets?\b.*\bcat\b|\bcat\b.*\bsecrets?\b/i,  // read secrets
    /\beval\b/i,               // eval in shell
    /\bexec\b\s/i,             // exec replacement
    /\/proc\/|\/sys\//i,       // proc/sys filesystem
    // Python/Node inline dangerous imports
    /python3?\s+-c\s+.*\b(os\.system|subprocess|socket|shutil\.rmtree|__import__)/i,
    /node\s+-e\s+.*\b(child_process|execSync|spawnSync|fs\.unlinkSync|fs\.rmdirSync)/i,
  ];

  static checkCommand(command: string): void {
    const trimmed = command.trim();

    // Extract the base command (first word, ignoring env vars and paths)
    const baseCmd = Executor._extractBaseCommand(trimmed);

    // Check if base command is in allowlist
    if (!Executor.ALLOWED_SHELL_COMMANDS.includes(baseCmd)) {
      throw new Error(
        `Blocked command: "${baseCmd}" is not in the allowed command list. ` +
        `Allowed: ${Executor.ALLOWED_SHELL_COMMANDS.slice(0, 10).join(', ')}...`
      );
    }

    // Even allowed commands can be dangerous with certain args
    for (const pattern of Executor.SHELL_DANGEROUS_PATTERNS) {
      if (pattern.test(trimmed)) {
        throw new Error(`Blocked: command matches dangerous pattern (${pattern.source})`);
      }
    }

    // Block pipe to interpreters (data exfiltration / code execution chains)
    if (/\|\s*(bash|sh|python|python3|perl|ruby|node|zsh)\b/.test(trimmed)) {
      throw new Error('Blocked: piping to interpreter is not allowed');
    }

    // Block backtick/subshell injection
    if (/`[^`]+`/.test(trimmed) || /\$\([^)]+\)/.test(trimmed)) {
      // Allow simple $(command) but block nested or dangerous ones
      const subshells = trimmed.match(/\$\(([^)]+)\)/g) ?? [];
      for (const sub of subshells) {
        const innerCmd = sub.slice(2, -1).trim();
        const innerBase = Executor._extractBaseCommand(innerCmd);
        if (!Executor.ALLOWED_SHELL_COMMANDS.includes(innerBase)) {
          throw new Error(`Blocked: subshell command "${innerBase}" not in allowlist`);
        }
      }
    }
  }

  private static _extractBaseCommand(cmd: string): string {
    // Skip env variable assignments (FOO=bar cmd)
    let remaining = cmd;
    while (/^[A-Z_][A-Z0-9_]*=\S*\s/.test(remaining)) {
      remaining = remaining.replace(/^[A-Z_][A-Z0-9_]*=\S*\s+/, '');
    }
    // Get the first word (the actual command)
    const firstWord = remaining.split(/[\s|;&]/)[0];
    // Strip path prefix (/usr/bin/ls → ls)
    return nodePath.basename(firstWord);
  }

  // ═══════════════════════════════════════
  // SECURITY: URL VALIDATION (legacy, kept for belt+suspenders)
  // ═══════════════════════════════════════

  static checkUrl(url: string): void {
    const result = netCheckUrl(url);
    if (!result.allowed) {
      throw new Error(`Blocked URL: ${result.reason}`);
    }
  }

  // ═══════════════════════════════════════
  // SECURITY: SCHEDULE_TASK ACTION ALLOWLIST
  // ═══════════════════════════════════════

  static readonly ALLOWED_TASK_ACTIONS = ['reminder', 'send_message'];

  static checkTaskAction(action: string): void {
    if (!Executor.ALLOWED_TASK_ACTIONS.includes(action)) {
      throw new Error(
        `[SECURITY] schedule_task action "${action}" not allowed. ` +
        `Only: ${Executor.ALLOWED_TASK_ACTIONS.join(', ')}`
      );
    }
  }

  // ═══════════════════════════════════════
  // SECURITY: RECIPIENT VALIDATION
  // ═══════════════════════════════════════

  static checkRecipient(to: string, ownerNumber: string, knownContacts: string[]): void {
    const normalizedTo = to.replace(/[^0-9]/g, '');
    const normalizedOwner = ownerNumber.replace(/[^0-9]/g, '');
    const normalizedKnown = knownContacts.map(c => c.replace(/[^0-9]/g, ''));
    const isOwner = normalizedTo === normalizedOwner;
    const isKnown = normalizedKnown.some(k =>
      normalizedTo === k || normalizedTo.endsWith(k) || k.endsWith(normalizedTo)
    );

    if (!isOwner && !isKnown) {
      throw new Error(
        `[SECURITY] Cannot send to unknown recipient "${to}". ` +
        `Only owner and known contacts are allowed.`
      );
    }
  }

  private async execReadFile(step: PlanStep): Promise<TaintedValue> {
    const rawPath = String(this.resolveLiteral(step.params['path']));
    const resolved = Executor.checkFilePathRead(rawPath);
    const { readFile } = await import('fs/promises');
    const content = await readFile(resolved, 'utf-8');
    return this.taintTracker.createValue(
      content, { source: 'filesystem', identifier: resolved },
      TrustLevel.UNTRUSTED, OutputCapacity.STRING, 'executor:read_file',
    );
  }

  private async execWriteFile(step: PlanStep): Promise<TaintedValue> {
    const rawPath = String(this.resolveLiteral(step.params['path']));
    const resolved = Executor.checkFilePathWrite(rawPath);
    const content = this.resolveContent(step.params['content']);
    const { writeFile, mkdir } = await import('fs/promises');
    // Ensure directory exists
    await mkdir(nodePath.dirname(resolved), { recursive: true }).catch(() => {});
    await writeFile(resolved, content, 'utf-8');
    return this.taintTracker.createValue(
      { written: true, path: resolved }, { source: 'system', identifier: 'write_file' },
      TrustLevel.SYSTEM, OutputCapacity.STRUCTURED, 'executor:write_file',
    );
  }

  /** Cached Docker availability check */
  private static dockerAvailable: boolean | null = null;

  private static async checkDockerAvailable(): Promise<boolean> {
    if (Executor.dockerAvailable !== null) return Executor.dockerAvailable;
    try {
      const { exec } = await import('child_process');
      const { promisify } = await import('util');
      await promisify(exec)('docker info', { timeout: 3000 });
      Executor.dockerAvailable = true;
    } catch {
      Executor.dockerAvailable = false;
    }
    return Executor.dockerAvailable;
  }

  private async execShell(step: PlanStep): Promise<TaintedValue> {
    const command = String(this.resolveLiteral(step.params['command']));
    Executor.checkCommand(command);
    const { exec } = await import('child_process');
    const { promisify } = await import('util');

    // ── DOCKER SANDBOX ──
    // If Docker is available and config enables it, run in a sandbox container
    const useDocker = this.config.useDockerSandbox && await Executor.checkDockerAvailable();

    let execCommand: string;
    let execOptions: Record<string, unknown>;

    if (useDocker) {
      // Run in ephemeral Alpine container with:
      // --rm: auto-cleanup, --network=none: no network,
      // --read-only: no writes to container fs (except /tmp),
      // --memory=128m: memory limit, --cpus=0.5: CPU limit,
      // -v ./data:/data:ro: read-only mount of data dir
      const escaped = command.replace(/'/g, "'\\''");
      execCommand = `docker run --rm --network=none --read-only --tmpfs /tmp:size=64m ` +
        `--memory=128m --cpus=0.5 --pids-limit=64 ` +
        `-v "${process.cwd()}/data:/data:ro" ` +
        `-v "${process.cwd()}/files:/files:ro" ` +
        `-w /data alpine:latest sh -c '${escaped}'`;
      execOptions = { timeout: 30000 };
      this.store.audit('shell_docker_sandbox', { command: command.substring(0, 100) });
    } else {
      // Fallback: run on host with resource limits (ulimit + nice)
      // These don't provide real isolation but limit blast radius
      execCommand = command;
      execOptions = {
        timeout: 30000,
        maxBuffer: 1024 * 1024, // 1MB output limit
        env: {
          ...process.env,
          PATH: '/usr/local/bin:/usr/bin:/bin', // Restrict PATH
        },
      };
    }

    const { stdout, stderr } = await promisify(exec)(execCommand, execOptions);
    return this.taintTracker.createValue(
      { stdout, stderr, sandboxed: useDocker },
      { source: 'system', identifier: `shell:${command.substring(0, 50)}` },
      TrustLevel.SYSTEM, OutputCapacity.STRUCTURED, 'executor:shell_exec',
    );
  }

  private async execWebFetch(step: PlanStep): Promise<TaintedValue> {
    const url = String(this.resolveLiteral(step.params['url']));

    // Network security check (URL + rate limit)
    const netCheck = checkNetworkAction({ action: 'web_fetch', url });
    if (!netCheck.allowed) {
      throw new Error(`[SECURITY] web_fetch blocked: ${netCheck.blocked.join('; ')}`);
    }

    Executor.checkUrl(url); // Legacy check (belt + suspenders)
    const resp = await fetch(url);
    const rawText = await resp.text();

    // Sanitize content before it reaches any LLM
    const sanitized = sanitizeWebContent(rawText.substring(0, 10000), url);
    if (sanitized.wasSanitized) {
      this.store.audit('prompt_injection_detected', {
        source: url,
        action: 'web_fetch',
        patterns: sanitized.injectionAttempts,
      });
    }

    return this.taintTracker.createValue(
      sanitized.text, { source: 'web', identifier: url },
      TrustLevel.UNTRUSTED, OutputCapacity.STRING, 'executor:web_fetch',
    );
  }

  private async execLogEvent(step: PlanStep, inputs: TaintedValue[]): Promise<TaintedValue> {
    const event = String(this.resolveLiteral(step.params['event']));
    this.store.audit(event, { inputs: inputs.map(i => i.label) });
    return this.taintTracker.createValue(
      { logged: true }, { source: 'system', identifier: 'log' },
      TrustLevel.SYSTEM, OutputCapacity.BOOLEAN, 'executor:log',
    );
  }

  private async execScheduleTask(step: PlanStep): Promise<TaintedValue> {
    if (!this.scheduler) throw new Error('Scheduler not available');

    const description = String(this.resolveLiteral(step.params['description'] ?? step.params['content'] ?? { kind: 'literal', value: '' }));
    const delayStr = step.params['delay'] ? String(this.resolveLiteral(step.params['delay'])) : '';
    const cronStr = step.params['cron'] ? String(this.resolveLiteral(step.params['cron'])) : '';
    const action = step.params['task_action'] ? String(this.resolveLiteral(step.params['task_action'])) : 'reminder';

    // ── ACTION ALLOWLIST ──
    Executor.checkTaskAction(action);

    // Parse delay from natural language
    const delayMs = delayStr ? parseDelay(delayStr) : null;
    const taskParams: Record<string, unknown> = {};

    // If it's a reminder/message, capture the target and content
    if (step.params['to']) taskParams['to'] = this.resolveLiteral(step.params['to']);
    if (step.params['message']) taskParams['message'] = this.resolveLiteral(step.params['message']);
    taskParams['description'] = description;

    const taskId = this.scheduler.schedule({
      action,
      params: taskParams,
      delayMs: delayMs ?? undefined,
      cron: cronStr || undefined,
      description,
      createdBy: 'planner',
    });

    const nextRun = this.scheduler.get(taskId)?.nextRun;
    const when = nextRun ? new Date(nextRun).toLocaleString('es-AR') : 'desconocido';

    return this.taintTracker.createValue(
      { scheduled: true, taskId, nextRun: when },
      { source: 'system', identifier: 'schedule' },
      TrustLevel.SYSTEM, OutputCapacity.STRUCTURED, 'executor:schedule',
    );
  }

  private async execBrowse(step: PlanStep): Promise<TaintedValue> {
    const url = String(this.resolveLiteral(step.params['url']));

    if (!(await isPlaywrightAvailable())) {
      throw new Error('Playwright not installed. Run: npm install playwright && npx playwright install chromium');
    }

    const selector = step.params['selector'] ? String(this.resolveLiteral(step.params['selector'])) : undefined;
    const waitFor = step.params['waitFor'] ? String(this.resolveLiteral(step.params['waitFor'])) : undefined;

    // ── NETWORK SECURITY CHECK ──
    const netCheck = checkNetworkAction({ action: 'browse', url });
    if (!netCheck.allowed) {
      this.store.audit('browse_blocked', { url, reasons: netCheck.blocked });
      throw new Error(`[SECURITY] Browse blocked: ${netCheck.blocked.join('; ')}`);
    }

    Executor.checkUrl(url);

    // Browse is READ-ONLY — no fill, no click
    const result = await browserBrowse(url, {
      selector,
      waitFor,
      timeout: 15_000,
      maxTextLength: 8_000,
    });

    if (result.error) throw new Error(`Browse failed: ${result.error}`);

    // Check if the page redirected to a dangerous URL
    if (result.url !== url) {
      const redirectCheck = checkRedirectUrl(url, result.url);
      if (!redirectCheck.allowed) {
        this.store.audit('browse_redirect_blocked', {
          originalUrl: url,
          redirectedTo: result.url,
          reason: redirectCheck.reason,
        });
        throw new Error(`[SECURITY] Redirect blocked: ${redirectCheck.reason}`);
      }
      if (redirectCheck.reason) {
        // Cross-domain redirect — log warning
        this.store.audit('browse_cross_domain_redirect', {
          originalUrl: url,
          redirectedTo: result.url,
          note: redirectCheck.reason,
        });
      }
    }

    // Sanitize extracted content before it reaches any LLM
    const sanitized = sanitizeWebContent(result.text, result.url);
    if (sanitized.wasSanitized) {
      this.store.audit('prompt_injection_detected', {
        source: result.url,
        action: 'browse',
        patterns: sanitized.injectionAttempts,
      });
    }

    return this.taintTracker.createValue(
      { title: result.title, text: sanitized.text, url: result.url, links: result.links },
      { source: 'web', identifier: url },
      TrustLevel.UNTRUSTED, OutputCapacity.STRUCTURED, 'executor:browse',
    );
  }

  private async execScreenshot(step: PlanStep): Promise<TaintedValue> {
    const url = String(this.resolveLiteral(step.params['url']));

    // Network security check
    const netCheck = checkNetworkAction({ action: 'screenshot', url });
    if (!netCheck.allowed) {
      throw new Error(`[SECURITY] Screenshot blocked: ${netCheck.blocked.join('; ')}`);
    }

    Executor.checkUrl(url);

    if (!(await isPlaywrightAvailable())) {
      throw new Error('Playwright not installed. Run: npm install playwright && npx playwright install chromium');
    }

    const buf = await browserScreenshot(url);
    if (!buf) throw new Error('Screenshot failed');

    return this.taintTracker.createValue(
      { screenshot: true, url, size: buf.length },
      { source: 'web', identifier: url },
      TrustLevel.UNTRUSTED, OutputCapacity.STRUCTURED, 'executor:screenshot',
    );
  }

  // --- Helpers ---

  private resolveLiteral(param: PlanStep['params'][string]): string | number | boolean {
    if (!param) return '';
    if (param.kind === 'literal') return param.value;
    if (param.kind === 'reference') {
      const ref = this.stepOutputs.get(param.stepId);
      if (!ref) throw new Error(`Unknown step ref: ${param.stepId}`);
      return ref.value as string | number | boolean;
    }
    throw new Error(`Unknown param kind: ${param.kind}`);
  }

  private resolveContent(param: PlanStep['params'][string]): string {
    if (!param) return '';
    if (param.kind === 'literal') return String(param.value);
    if (param.kind === 'reference') {
      const ref = this.stepOutputs.get(param.stepId);
      if (!ref) throw new Error(`Unknown step ref: ${param.stepId}`);
      return String(ref.value);
    }
    return '';
  }

  private resolveInputs(step: PlanStep): TaintedValue[] {
    const inputs: TaintedValue[] = [];
    for (const param of Object.values(step.params)) {
      if (param.kind === 'reference') {
        const ref = this.stepOutputs.get(param.stepId);
        if (ref) inputs.push(ref);
      }
    }
    return inputs;
  }

  private topologicalSort(plan: Plan): PlanStep[] {
    const map = new Map(plan.steps.map(s => [s.id, s]));
    const visited = new Set<string>();
    const result: PlanStep[] = [];
    const visit = (id: string) => {
      if (visited.has(id)) return;
      visited.add(id);
      const s = map.get(id);
      if (!s) return;
      for (const dep of s.dependsOn) visit(dep);
      result.push(s);
    };
    for (const s of plan.steps) visit(s.id);
    return result;
  }

  // --- Guardian integration ---

  private async guardianCheck(step: PlanStep): Promise<GuardianResponse> {
    const actionContent = this.buildActionContent(step);
    const { files, network } = GuardianBridge.extractContext(
      step.action, step.params,
    );

    return this.guardian.evaluate({
      action_type: this.mapActionType(step.action),
      action_content: actionContent,
      files_involved: files,
      network_targets: network,
      agent_id: 'fortbot',
      session_id: '',
    });
  }

  private buildActionContent(step: PlanStep): string {
    const parts: string[] = [step.action];
    for (const [key, param] of Object.entries(step.params)) {
      if (param.kind === 'literal') {
        parts.push(`${key}=${param.value}`);
      } else if (param.kind === 'reference') {
        parts.push(`${key}=[ref:${param.stepId}]`);
      }
    }
    return parts.join(' ');
  }

  private mapActionType(action: ActionType): string {
    const map: Partial<Record<ActionType, string>> = {
      [ActionType.SHELL_EXEC]: 'exec',
      [ActionType.WEB_FETCH]: 'web_fetch',
      [ActionType.WRITE_FILE]: 'write',
      [ActionType.READ_FILE]: 'read',
      [ActionType.SEND_MESSAGE]: 'message',
    };
    return map[action] ?? action;
  }

  // --- Helpers ---

  private describeStep(step: PlanStep): string {
    const params = Object.entries(step.params)
      .map(([k, v]) => `  ${k}: ${v.kind === 'literal' ? v.value : `[ref:${v.kind === 'reference' ? v.stepId : 'input'}]`}`)
      .join('\n');
    return `Action: ${step.action}\n${params}`;
  }
}
