/**
 * FORTBOT - Claude Max LLM Adapter
 *
 * Uses Claude via CLI pipe (claude --print).
 * Authentication: `claude login` (OAuth) — no API key needed.
 *
 * v0.4: retry with exponential backoff + usage metrics + intent classifier
 */

export interface ClaudeResponse {
  text: string;
  inputTokens: number;
  outputTokens: number;
  durationMs: number;
}

const MODEL_MAP: Record<string, string> = {
  sonnet: 'claude-sonnet-4-5-20250929',
  opus: 'claude-opus-4-6',
  haiku: 'claude-haiku-4-5-20251001',
};

// ── Usage Metrics ──────────────────────────────────

export interface LLMMetrics {
  totalCalls: number;
  totalErrors: number;
  totalRetries: number;
  totalDurationMs: number;
  callsByModel: Record<string, number>;
  averageDurationMs: number;
  lastCallAt: number | null;
  uptimeMs: number;
}

class MetricsTracker {
  private calls = 0;
  private errors = 0;
  private retries = 0;
  private totalDuration = 0;
  private modelCalls: Record<string, number> = {};
  private lastCall: number | null = null;
  private startTime = Date.now();

  record(model: string, durationMs: number, retried: boolean): void {
    this.calls++;
    this.totalDuration += durationMs;
    this.modelCalls[model] = (this.modelCalls[model] ?? 0) + 1;
    if (retried) this.retries++;
    this.lastCall = Date.now();
  }

  recordError(): void { this.errors++; }

  get(): LLMMetrics {
    return {
      totalCalls: this.calls,
      totalErrors: this.errors,
      totalRetries: this.retries,
      totalDurationMs: this.totalDuration,
      callsByModel: { ...this.modelCalls },
      averageDurationMs: this.calls > 0 ? Math.round(this.totalDuration / this.calls) : 0,
      lastCallAt: this.lastCall,
      uptimeMs: Date.now() - this.startTime,
    };
  }
}

export const llmMetrics = new MetricsTracker();

// ── Claude CLI ──────────────────────────────────────

const MAX_RETRIES = 3;
const BASE_DELAY_MS = 2000;

/**
 * Call Claude via CLI pipe. Retries with exponential backoff.
 */
export async function callClaude(
  systemPrompt: string,
  userMessage: string,
  model: 'sonnet' | 'opus' | 'haiku' = 'sonnet',
): Promise<ClaudeResponse> {
  const start = Date.now();
  let lastError: Error | null = null;
  let retried = false;

  for (let attempt = 0; attempt < MAX_RETRIES; attempt++) {
    try {
      if (attempt > 0) {
        retried = true;
        const delay = BASE_DELAY_MS * Math.pow(2, attempt - 1) + Math.random() * 1000;
        console.log(`[LLM] Retry ${attempt}/${MAX_RETRIES} in ${Math.round(delay)}ms...`);
        await new Promise(r => setTimeout(r, delay));
      }

      const result = await callClaudeOnce(systemPrompt, userMessage, model);
      llmMetrics.record(model, Date.now() - start, retried);
      return result;
    } catch (error) {
      lastError = error instanceof Error ? error : new Error(String(error));
      if (lastError.message.includes('ENOENT') || lastError.message.includes('login')) {
        llmMetrics.recordError();
        throw lastError;
      }
      console.warn(`[LLM] Attempt ${attempt + 1} failed: ${lastError.message.substring(0, 100)}`);
    }
  }

  llmMetrics.recordError();
  throw lastError ?? new Error('All retry attempts failed');
}

async function callClaudeOnce(
  systemPrompt: string, userMessage: string, model: string,
): Promise<ClaudeResponse> {
  const start = Date.now();
  const { execFile } = await import('child_process');
  const { promisify } = await import('util');
  const execFileAsync = promisify(execFile);

  const fullPrompt = `${systemPrompt}\n\nUser: ${userMessage}`;
  try {
    const { stdout } = await execFileAsync('claude', [
      '--model', MODEL_MAP[model] ?? model,
      '--print', '--output-format', 'text', '-p', fullPrompt,
    ], { timeout: 120000, maxBuffer: 1024 * 1024 });

    return { text: stdout.trim(), inputTokens: 0, outputTokens: 0, durationMs: Date.now() - start };
  } catch (error) {
    const errMsg = error instanceof Error ? error.message : String(error);
    if (errMsg.includes('ENOENT')) {
      throw new Error('Claude CLI not found. Run: npm install -g @anthropic-ai/claude-code && claude login');
    }
    throw new Error(`Claude call failed: ${errMsg.substring(0, 200)}`);
  }
}

// ── Local LLM ──────────────────────────────────────

export async function callLocalLLM(
  endpoint: string, systemPrompt: string, userMessage: string,
): Promise<ClaudeResponse> {
  const start = Date.now();
  let lastError: Error | null = null;

  for (let attempt = 0; attempt < MAX_RETRIES; attempt++) {
    if (attempt > 0) await new Promise(r => setTimeout(r, BASE_DELAY_MS * Math.pow(2, attempt - 1)));
    try {
      const response = await fetch(`${endpoint}/v1/chat/completions`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          messages: [{ role: 'system', content: systemPrompt }, { role: 'user', content: userMessage }],
          temperature: 0.1, max_tokens: 2048,
        }),
      });
      if (!response.ok) throw new Error(`Local LLM ${response.status}: ${await response.text()}`);

      const data = await response.json() as {
        choices: Array<{ message: { content: string } }>;
        usage?: { prompt_tokens?: number; completion_tokens?: number };
      };

      const result: ClaudeResponse = {
        text: data.choices[0]?.message?.content ?? '',
        inputTokens: data.usage?.prompt_tokens ?? 0,
        outputTokens: data.usage?.completion_tokens ?? 0,
        durationMs: Date.now() - start,
      };
      llmMetrics.record('local', result.durationMs, attempt > 0);
      return result;
    } catch (error) {
      lastError = error instanceof Error ? error : new Error(String(error));
    }
  }
  llmMetrics.recordError();
  throw lastError ?? new Error('Local LLM: all retries failed');
}

// ── Intent Classifier ──────────────────────────────

/**
 * LLM-based classification: task or chat?
 * Uses haiku for speed. Falls back to regex on failure.
 */
export async function classifyIntent(
  text: string, recentContext: string,
): Promise<'task' | 'chat'> {
  const prompt = `Classify this WhatsApp message as "task" (user wants an action: send, search, read, write, fetch, translate, summarize, run command, etc.) or "chat" (casual conversation, question, opinion, greeting).

Context: ${recentContext || '(none)'}
Message: "${text}"

Respond with ONLY: task or chat`;

  try {
    const result = await callClaude(prompt, text, 'haiku');
    return result.text.trim().toLowerCase().includes('task') ? 'task' : 'chat';
  } catch {
    return fallbackClassify(text);
  }
}

function fallbackClassify(text: string): 'task' | 'chat' {
  const lower = text.toLowerCase();
  const patterns = [
    /^(mandá|manda|enviá|envia|send)(\s|$)/,
    /^(leé|lee|read)(\s|$)/,
    /^(buscá|busca|search|fijate)(\s|$)/,
    /^(resumí|resume|summarize)(\s|$)/,
    /^(traducí|traduce|translate)(\s|$)/,
    /^(clasificá|clasifica|classify)(\s|$)/,
    /^(escribí|escribi|write|guardá|guarda|save)(\s|$)/,
    /^(ejecutá|ejecuta|run|shell)(\s|$)/,
    /^(descargá|fetch|abrí|abri|open)(\s|$)/,
    /los mensajes de/,
    /buscá en la web/,
    /fijate (en|el|la|los)/,
    /^(necesito que|podrías|podrias|haceme|dame)(\s|$)/,
    /que (busque|mande|lea|escriba|descargue|traduzca|resuma)/,
  ];
  return patterns.some(p => p.test(lower)) ? 'task' : 'chat';
}

// ── Conversation Summarizer ────────────────────────

/**
 * Compress old conversation history into a summary.
 * Keeps recent messages intact, summarizes the rest.
 */
export async function summarizeHistory(
  messages: Array<{ sender_name: string; content: string }>,
  keepRecent = 15,
  model: 'sonnet' | 'opus' | 'haiku' = 'haiku',
): Promise<{ summary: string; recentMessages: typeof messages }> {
  if (messages.length <= keepRecent) {
    return { summary: '', recentMessages: messages };
  }

  const oldMessages = messages.slice(0, messages.length - keepRecent);
  const recentMessages = messages.slice(messages.length - keepRecent);

  const oldText = oldMessages.map(m => `${m.sender_name}: ${m.content}`).join('\n');
  const prompt = `Summarize this WhatsApp conversation history in 3-5 bullet points.
Focus on: key facts discussed, decisions made, pending tasks, important context.
Be concise. Spanish.`;

  try {
    const result = await callClaude(prompt, oldText.substring(0, 8000), model);
    return { summary: result.text.trim(), recentMessages };
  } catch {
    // On failure, just truncate
    return { summary: '', recentMessages };
  }
}
