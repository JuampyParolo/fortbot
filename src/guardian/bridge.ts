/**
 * FORTBOT — Guardian Bridge
 *
 * Connects the TypeScript executor to the Python Guardian API.
 * Every action passes through here BEFORE execution.
 *
 * TS Executor → HTTP → Python Guardian (port 18790)
 *            ← verdict (safe/warning/block)
 *
 * If Guardian is unreachable → FAIL CLOSED (deny by default).
 */

export interface GuardianRequest {
  action_type: string;
  action_content: string;
  files_involved: string[];
  network_targets: string[];
  agent_id: string;
  session_id: string;
}

export interface GuardianResponse {
  allowed: boolean;
  verdict: 'safe' | 'warning' | 'block';
  explanation: string;
  risk_score: number;
  requires_approval: boolean;
  approval_id?: string;
}

export class GuardianBridge {
  private baseUrl: string;
  private timeout: number;
  private connected: boolean = false;
  private sessionId: string;

  constructor(port: number = 18790, timeout: number = 10000) {
    this.baseUrl = `http://127.0.0.1:${port}`;
    this.timeout = timeout;
    this.sessionId = `ts_${Date.now()}`;
  }

  /**
   * Check if the Guardian API is reachable.
   * Called on startup — if Guardian is down, FortBot warns but continues
   * with TS-only security (PolicyEngine).
   */
  async checkHealth(): Promise<boolean> {
    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 3000);
      const resp = await fetch(`${this.baseUrl}/health`, {
        signal: controller.signal,
      });
      clearTimeout(timer);
      this.connected = resp.ok;
      return this.connected;
    } catch {
      this.connected = false;
      return false;
    }
  }

  get isConnected(): boolean {
    return this.connected;
  }

  /**
   * Ask the Guardian whether an action is safe to execute.
   *
   * Returns the verdict. On network failure → returns BLOCK (fail closed).
   */
  async evaluate(request: GuardianRequest): Promise<GuardianResponse> {
    request.session_id = this.sessionId;

    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), this.timeout);

      const resp = await fetch(`${this.baseUrl}/guardian/evaluate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(request),
        signal: controller.signal,
      });

      clearTimeout(timer);

      if (!resp.ok) {
        // Guardian returned an error — fail closed
        return this.failClosed(`Guardian HTTP ${resp.status}`);
      }

      const data = (await resp.json()) as GuardianResponse;
      return data;
    } catch (err) {
      // Network error, timeout, etc. — FAIL CLOSED
      console.error('[GuardianBridge] Error:', err);
      return this.failClosed(`Guardian unreachable: ${err}`);
    }
  }

  /**
   * Poll for approval resolution (when Guardian returned WARNING).
   * The user approves/rejects via the Web UI, and we poll until resolved.
   */
  async waitForApproval(approvalId: string, timeoutMs: number = 120000): Promise<boolean> {
    const start = Date.now();
    const pollInterval = 1500;

    while (Date.now() - start < timeoutMs) {
      try {
        const resp = await fetch(`${this.baseUrl}/guardian/pending`);
        if (resp.ok) {
          const pending = await resp.json() as Record<string, { status: string }>;
          const entry = pending[approvalId];
          // If it's no longer in pending, it was resolved
          if (!entry) {
            // Check if it was approved by fetching the specific approval
            // For now, if it disappeared from pending, check audit
            return await this.checkApprovalResult(approvalId);
          }
        }
      } catch {
        // Guardian might be temporarily unavailable — keep polling
      }

      await new Promise((r) => setTimeout(r, pollInterval));
    }

    // Timeout — deny
    return false;
  }

  private async checkApprovalResult(approvalId: string): Promise<boolean> {
    try {
      const resp = await fetch(`${this.baseUrl}/guardian/approval/${approvalId}`);
      if (resp.ok) {
        const data = (await resp.json()) as { status: string };
        return data.status === 'approved';
      }
    } catch {
      // Can't verify — deny
    }
    return false;
  }

  /**
   * Fail-closed response: when Guardian is unreachable, block everything.
   * This is a security principle — unknown state = deny.
   */
  private failClosed(reason: string): GuardianResponse {
    return {
      allowed: false,
      verdict: 'block',
      explanation: `Guardian no disponible — acción bloqueada por seguridad. (${reason})`,
      risk_score: 1.0,
      requires_approval: false,
    };
  }

  /**
   * Extract file paths and network targets from an action for Guardian context.
   */
  static extractContext(
    actionType: string,
    params: Record<string, { kind: string; value?: string | number | boolean; stepId?: string }>,
  ): { files: string[]; network: string[] } {
    const files: string[] = [];
    const network: string[] = [];

    // Extract file paths
    if (params['path']?.kind === 'literal') {
      files.push(String(params['path'].value));
    }

    // Extract URLs
    if (params['url']?.kind === 'literal') {
      const url = String(params['url'].value);
      network.push(url);
      try {
        const parsed = new URL(url);
        network.push(parsed.hostname);
      } catch {
        // Not a valid URL
      }
    }

    // Extract command content for file/network hints
    if (params['command']?.kind === 'literal') {
      const cmd = String(params['command'].value);
      // Detect file references in commands
      const filePatterns = cmd.match(/(?:\/[\w./\-~]+|\.\/[\w./\-]+|~\/[\w./\-]+)/g);
      if (filePatterns) files.push(...filePatterns);
      // Detect URLs in commands
      const urlPatterns = cmd.match(/https?:\/\/[^\s'"]+/g);
      if (urlPatterns) network.push(...urlPatterns);
    }

    return { files, network };
  }
}
