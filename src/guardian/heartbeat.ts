/**
 * FORTBOT — Heartbeat System
 *
 * Periodic health monitoring of all components:
 * - WhatsApp connection (baileys socket)
 * - Guardian API (Python side)
 * - LLM availability (claude CLI)
 * - SQLite database
 * - Memory/uptime
 *
 * Writes HEARTBEAT.md for external monitoring.
 */

import { writeFileSync, existsSync, mkdirSync } from 'fs';
import { GuardianBridge } from './bridge.js';

export interface ComponentHealth {
  name: string;
  status: 'ok' | 'degraded' | 'down';
  latency_ms?: number;
  detail?: string;
}

export interface HeartbeatReport {
  timestamp: string;
  overall: 'healthy' | 'degraded' | 'critical';
  uptime_seconds: number;
  components: ComponentHealth[];
}

export class Heartbeat {
  private startTime: number;
  private interval: ReturnType<typeof setInterval> | null = null;
  private lastReport: HeartbeatReport | null = null;
  private guardian: GuardianBridge;
  private checks: (() => Promise<ComponentHealth>)[] = [];

  constructor(guardian: GuardianBridge) {
    this.startTime = Date.now();
    this.guardian = guardian;
  }

  /**
   * Register a health check function.
   * Each returns a ComponentHealth object.
   */
  addCheck(check: () => Promise<ComponentHealth>): void {
    this.checks.push(check);
  }

  /**
   * Start periodic heartbeat checks.
   * @param intervalMs Check interval (default: 60 seconds)
   */
  start(intervalMs: number = 60_000): void {
    // Run immediately
    this.runChecks();
    // Then periodically
    this.interval = setInterval(() => this.runChecks(), intervalMs);
  }

  stop(): void {
    if (this.interval) {
      clearInterval(this.interval);
      this.interval = null;
    }
  }

  async runChecks(): Promise<HeartbeatReport> {
    const components: ComponentHealth[] = [];

    // Built-in: Guardian API
    const guardianStart = Date.now();
    const guardianOk = await this.guardian.checkHealth();
    components.push({
      name: 'Guardian API',
      status: guardianOk ? 'ok' : 'degraded',
      latency_ms: Date.now() - guardianStart,
      detail: guardianOk ? 'Connected' : 'Offline — using TS PolicyEngine only',
    });

    // Built-in: Process memory
    const mem = process.memoryUsage();
    const heapMb = Math.round(mem.heapUsed / 1024 / 1024);
    components.push({
      name: 'Memory',
      status: heapMb > 500 ? 'degraded' : 'ok',
      detail: `${heapMb}MB heap used`,
    });

    // Custom checks
    for (const check of this.checks) {
      try {
        const result = await check();
        components.push(result);
      } catch (err) {
        components.push({
          name: 'Unknown',
          status: 'down',
          detail: `Check failed: ${err}`,
        });
      }
    }

    // Determine overall status
    const hasDown = components.some((c) => c.status === 'down');
    const hasDegraded = components.some((c) => c.status === 'degraded');
    const overall = hasDown ? 'critical' : hasDegraded ? 'degraded' : 'healthy';

    const report: HeartbeatReport = {
      timestamp: new Date().toISOString(),
      overall,
      uptime_seconds: Math.floor((Date.now() - this.startTime) / 1000),
      components,
    };

    this.lastReport = report;
    this.writeHeartbeatFile(report);

    return report;
  }

  getLastReport(): HeartbeatReport | null {
    return this.lastReport;
  }

  private writeHeartbeatFile(report: HeartbeatReport): void {
    const emoji = { healthy: '🟢', degraded: '🟡', critical: '🔴' };
    const uptime = this.formatUptime(report.uptime_seconds);

    const lines = [
      `# 🏰 FortBot Heartbeat`,
      ``,
      `**Status:** ${emoji[report.overall]} ${report.overall.toUpperCase()}`,
      `**Last check:** ${report.timestamp}`,
      `**Uptime:** ${uptime}`,
      ``,
      `## Components`,
      ``,
      ...report.components.map((c) => {
        const icon = c.status === 'ok' ? '✅' : c.status === 'degraded' ? '⚠️' : '❌';
        const lat = c.latency_ms !== undefined ? ` (${c.latency_ms}ms)` : '';
        return `- ${icon} **${c.name}**${lat}: ${c.detail || c.status}`;
      }),
      ``,
      `---`,
      `*Auto-generated every 60s*`,
    ];

    try {
      try { mkdirSync('./data', { recursive: true }); } catch {}
      writeFileSync('./data/HEARTBEAT.md', lines.join('\n'));
    } catch {
      // Best-effort — might not have write permissions
    }
  }

  private formatUptime(seconds: number): string {
    const d = Math.floor(seconds / 86400);
    const h = Math.floor((seconds % 86400) / 3600);
    const m = Math.floor((seconds % 3600) / 60);
    if (d > 0) return `${d}d ${h}h ${m}m`;
    if (h > 0) return `${h}h ${m}m`;
    return `${m}m`;
  }
}
