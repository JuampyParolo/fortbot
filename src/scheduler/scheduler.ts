/**
 * FORTBOT — Task Scheduler
 *
 * Handles scheduled/recurring tasks:
 *   - One-shot: "recordame en 30 minutos"
 *   - Recurring: "todos los lunes a las 9"
 *   - Cron-style: for programmatic scheduling
 *
 * Persists to SQLite so tasks survive restarts.
 * Executor calls schedule() → creates a task → scheduler fires it later.
 */

import { MessageStore } from '../store/messages.js';

export interface ScheduledTask {
  id: string;
  /** What to do: 'send_message', 'shell_exec', 'reminder', etc. */
  action: string;
  /** Action parameters (JSON-serializable) */
  params: Record<string, unknown>;
  /** When to fire (epoch ms). For recurring: next fire time. */
  nextRun: number;
  /** Cron expression for recurring (null = one-shot) */
  cron: string | null;
  /** Human-readable description */
  description: string;
  /** Who requested it */
  createdBy: string;
  /** Creation timestamp */
  createdAt: number;
  /** Is it active? */
  active: boolean;
}

type TaskCallback = (task: ScheduledTask) => Promise<void>;

export class Scheduler {
  private tasks: Map<string, ScheduledTask> = new Map();
  private timer: ReturnType<typeof setInterval> | null = null;
  private callback: TaskCallback | null = null;
  private store: MessageStore;
  private checkIntervalMs: number;

  constructor(store: MessageStore, checkIntervalMs: number = 15_000) {
    this.store = store;
    this.checkIntervalMs = checkIntervalMs;
  }

  /** Register the callback that fires when a task is due. */
  onTask(cb: TaskCallback): void {
    this.callback = cb;
  }

  /** Start the scheduler loop. */
  start(): void {
    this.loadFromDb();
    this.timer = setInterval(() => this.tick(), this.checkIntervalMs);
    console.log(`[Scheduler] Started — ${this.tasks.size} tasks loaded, checking every ${this.checkIntervalMs / 1000}s`);
  }

  stop(): void {
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
    }
  }

  /**
   * Schedule a new task.
   * Returns the task ID.
   */
  schedule(opts: {
    action: string;
    params: Record<string, unknown>;
    delayMs?: number;
    runAt?: number;
    cron?: string;
    description: string;
    createdBy: string;
  }): string {
    const id = `task_${Date.now()}_${Math.random().toString(36).substring(2, 6)}`;

    let nextRun: number;
    if (opts.runAt) {
      nextRun = opts.runAt;
    } else if (opts.delayMs) {
      nextRun = Date.now() + opts.delayMs;
    } else if (opts.cron) {
      nextRun = this.nextCronRun(opts.cron);
    } else {
      nextRun = Date.now() + 60_000; // Default: 1 minute
    }

    const task: ScheduledTask = {
      id,
      action: opts.action,
      params: opts.params,
      nextRun,
      cron: opts.cron ?? null,
      description: opts.description,
      createdBy: opts.createdBy,
      createdAt: Date.now(),
      active: true,
    };

    this.tasks.set(id, task);
    this.saveToDb(task);

    return id;
  }

  /** Cancel a scheduled task. */
  cancel(taskId: string): boolean {
    const task = this.tasks.get(taskId);
    if (!task) return false;
    task.active = false;
    this.saveToDb(task);
    this.tasks.delete(taskId);
    return true;
  }

  /** List all active tasks. */
  list(): ScheduledTask[] {
    return Array.from(this.tasks.values()).filter(t => t.active);
  }

  /** Get a specific task. */
  get(taskId: string): ScheduledTask | undefined {
    return this.tasks.get(taskId);
  }

  // ── Tick loop ───────────────────────────

  private async tick(): Promise<void> {
    const now = Date.now();

    for (const task of this.tasks.values()) {
      if (!task.active || task.nextRun > now) continue;

      try {
        if (this.callback) {
          await this.callback(task);
        }
      } catch (err) {
        console.error(`[Scheduler] Task ${task.id} failed:`, err);
      }

      if (task.cron) {
        // Recurring — compute next run
        task.nextRun = this.nextCronRun(task.cron);
        this.saveToDb(task);
      } else {
        // One-shot — deactivate
        task.active = false;
        this.saveToDb(task);
        this.tasks.delete(task.id);
      }
    }
  }

  // ── Simplified cron parser ──────────────
  // Supports: "every Xm", "every Xh", "daily HH:MM", "weekly DAY HH:MM"

  private nextCronRun(cron: string): number {
    const now = new Date();
    const lower = cron.toLowerCase().trim();

    // "every 30m" / "every 2h"
    const intervalMatch = lower.match(/^every\s+(\d+)(m|h|s)$/);
    if (intervalMatch) {
      const amount = parseInt(intervalMatch[1]);
      const unit = intervalMatch[2];
      const ms = unit === 'h' ? amount * 3600_000 : unit === 'm' ? amount * 60_000 : amount * 1000;
      return Date.now() + ms;
    }

    // "daily 09:00"
    const dailyMatch = lower.match(/^daily\s+(\d{1,2}):(\d{2})$/);
    if (dailyMatch) {
      const target = new Date(now);
      target.setHours(parseInt(dailyMatch[1]), parseInt(dailyMatch[2]), 0, 0);
      if (target.getTime() <= now.getTime()) {
        target.setDate(target.getDate() + 1);
      }
      return target.getTime();
    }

    // "weekly monday 09:00"
    const weeklyMatch = lower.match(/^weekly\s+(monday|tuesday|wednesday|thursday|friday|saturday|sunday)\s+(\d{1,2}):(\d{2})$/);
    if (weeklyMatch) {
      const dayMap: Record<string, number> = {
        sunday: 0, monday: 1, tuesday: 2, wednesday: 3,
        thursday: 4, friday: 5, saturday: 6,
      };
      const targetDay = dayMap[weeklyMatch[1]];
      const target = new Date(now);
      target.setHours(parseInt(weeklyMatch[2]), parseInt(weeklyMatch[3]), 0, 0);

      let daysUntil = targetDay - now.getDay();
      if (daysUntil < 0) daysUntil += 7;
      if (daysUntil === 0 && target.getTime() <= now.getTime()) daysUntil = 7;
      target.setDate(target.getDate() + daysUntil);

      return target.getTime();
    }

    // Fallback: 1 hour from now
    console.warn(`[Scheduler] Unknown cron format "${cron}", defaulting to 1h`);
    return Date.now() + 3600_000;
  }

  // ── SQLite persistence ──────────────────

  private loadFromDb(): void {
    try {
      const db = (this.store as any).db;
      if (!db) return;

      // Create table if not exists
      db.run(`
        CREATE TABLE IF NOT EXISTS scheduled_tasks (
          id TEXT PRIMARY KEY,
          action TEXT NOT NULL,
          params TEXT NOT NULL,
          next_run INTEGER NOT NULL,
          cron TEXT,
          description TEXT,
          created_by TEXT,
          created_at INTEGER,
          active INTEGER DEFAULT 1
        )
      `);

      const stmt = db.prepare('SELECT * FROM scheduled_tasks WHERE active = 1');
      while (stmt.step()) {
        const row = stmt.getAsObject() as Record<string, unknown>;
        const task: ScheduledTask = {
          id: String(row['id']),
          action: String(row['action']),
          params: JSON.parse(String(row['params'])),
          nextRun: Number(row['next_run']),
          cron: row['cron'] ? String(row['cron']) : null,
          description: String(row['description'] ?? ''),
          createdBy: String(row['created_by'] ?? ''),
          createdAt: Number(row['created_at'] ?? 0),
          active: true,
        };
        this.tasks.set(task.id, task);
      }
      stmt.free();
    } catch (err) {
      console.warn('[Scheduler] Could not load tasks from DB:', err);
    }
  }

  private saveToDb(task: ScheduledTask): void {
    try {
      const db = (this.store as any).db;
      if (!db) return;

      db.run(`
        INSERT OR REPLACE INTO scheduled_tasks
          (id, action, params, next_run, cron, description, created_by, created_at, active)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
      `, [
        task.id,
        task.action,
        JSON.stringify(task.params),
        task.nextRun,
        task.cron,
        task.description,
        task.createdBy,
        task.createdAt,
        task.active ? 1 : 0,
      ]);
    } catch (err) {
      console.warn('[Scheduler] Could not save task to DB:', err);
    }
  }
}

// ── Parsing helpers for natural language delays ──

export function parseDelay(text: string): number | null {
  const lower = text.toLowerCase().trim();

  // "30 minutos", "2 horas", "1 hora", "45 segundos"
  const match = lower.match(/(\d+)\s*(segundos?|seg|s|minutos?|min|m|horas?|h|días?|d)/);
  if (!match) return null;

  const amount = parseInt(match[1]);
  const unit = match[2];

  if (unit.startsWith('seg') || unit === 's') return amount * 1000;
  if (unit.startsWith('min') || unit === 'm') return amount * 60_000;
  if (unit.startsWith('hora') || unit === 'h') return amount * 3600_000;
  if (unit.startsWith('día') || unit.startsWith('dia') || unit === 'd') return amount * 86400_000;

  return null;
}
