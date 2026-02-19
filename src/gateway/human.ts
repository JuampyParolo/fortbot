/**
 * FORTBOT - Human Emulation Layer
 *
 * Makes FortBot behave like a human on WhatsApp to avoid detection.
 * Based on known WhatsApp detection signals:
 *
 * 1. Missing "typing..." indicator → we simulate composing
 * 2. Uniform response speed → randomized delays
 * 3. Always online 24/7 → presence schedule (sleep/wake)
 * 4. Instant read receipts → delayed reads
 * 5. Default browser fingerprint → realistic browser config
 * 6. No pauses between messages → jitter on everything
 *
 * Philosophy: every action has variance. Nothing is exactly the same twice.
 */

export interface HumanConfig {
  /** Active hours (24h format). Outside these, bot queues and waits. */
  wakeHour: number;    // default 8
  sleepHour: number;   // default 23

  /** Typing speed in chars per second (human average: 5-8 cps) */
  typingSpeedMin: number;  // default 4
  typingSpeedMax: number;  // default 7

  /** Base delay before starting to "type" (ms) */
  readDelayMin: number;   // default 800
  readDelayMax: number;   // default 3000

  /** Extra random delay after typing, before sending (ms) */
  sendJitterMin: number;  // default 200
  sendJitterMax: number;  // default 1500

  /** Probability of going briefly "unavailable" between messages (0-1) */
  offlineFlickerChance: number;  // default 0.15

  /** How long to stay "unavailable" during flicker (ms) */
  offlineFlickerMin: number;  // default 5000
  offlineFlickerMax: number;  // default 30000

  /** Max messages per minute before self-throttling */
  maxMessagesPerMinute: number;  // default 4

  /** Max messages per hour */
  maxMessagesPerHour: number;    // default 30
}

export const DEFAULT_HUMAN_CONFIG: HumanConfig = {
  wakeHour: 8,
  sleepHour: 23,
  typingSpeedMin: 4,
  typingSpeedMax: 7,
  readDelayMin: 800,
  readDelayMax: 3000,
  sendJitterMin: 200,
  sendJitterMax: 1500,
  offlineFlickerChance: 0.15,
  offlineFlickerMin: 5000,
  offlineFlickerMax: 30000,
  maxMessagesPerMinute: 4,
  maxMessagesPerHour: 30,
};

// Types for Baileys socket methods we need
interface PresenceSocket {
  sendPresenceUpdate: (presence: string, jid?: string) => Promise<void>;
  readMessages: (keys: Array<{ remoteJid: string; id: string; participant?: string }>) => Promise<void>;
}

export class HumanEmulator {
  private config: HumanConfig;
  private socket: PresenceSocket | null = null;
  private sentTimestamps: number[] = [];
  private sleeping = false;
  private sleepQueue: Array<() => void> = [];
  private presenceTimer: ReturnType<typeof setInterval> | null = null;

  constructor(config: Partial<HumanConfig> = {}) {
    this.config = { ...DEFAULT_HUMAN_CONFIG, ...config };
  }

  /**
   * Bind to a Baileys socket. Call after connection is open.
   */
  bind(socket: PresenceSocket): void {
    this.socket = socket;
    this.startPresenceSchedule();
  }

  /**
   * Unbind and stop timers.
   */
  unbind(): void {
    this.socket = null;
    if (this.presenceTimer) {
      clearInterval(this.presenceTimer);
      this.presenceTimer = null;
    }
  }

  // ══════════════════════════════════════════
  // CORE: Simulate human before sending
  // ══════════════════════════════════════════

  /**
   * Full human simulation pipeline before sending a message.
   * Call this INSTEAD of directly sending.
   *
   * Returns false if rate-limited (caller should retry later).
   */
  async beforeSend(jid: string, messageLength: number): Promise<boolean> {
    if (!this.socket) return true;

    // Check sleep schedule
    if (this.isSleepTime()) {
      console.log('[Human] 😴 Sleep hours — queueing');
      return false;
    }

    // Rate limit check
    if (!this.checkRateLimit()) {
      console.log('[Human] 🐌 Rate limited — slow down');
      return false;
    }

    // Step 1: "Read" delay — human takes time to read incoming message
    const readDelay = this.random(this.config.readDelayMin, this.config.readDelayMax);
    await this.sleep(readDelay);

    // Step 2: Mark as available (might have been "unavailable")
    await this.socket.sendPresenceUpdate('available', jid);
    await this.sleep(this.random(100, 400));

    // Step 3: Start typing — duration proportional to message length
    const typingSpeed = this.random(this.config.typingSpeedMin, this.config.typingSpeedMax);
    const typingDuration = Math.min(
      (messageLength / typingSpeed) * 1000,  // chars / (chars/sec) * 1000
      25000  // WhatsApp composing indicator max ~25s
    );

    // Send composing in chunks (WhatsApp expires it after ~10s)
    const chunks = Math.ceil(typingDuration / 8000);
    for (let i = 0; i < chunks; i++) {
      await this.socket.sendPresenceUpdate('composing', jid);
      const chunkTime = Math.min(typingDuration - (i * 8000), 8000);
      await this.sleep(chunkTime);
    }

    // Step 4: Brief pause after "finishing typing" (human reviews before hitting send)
    await this.socket.sendPresenceUpdate('paused', jid);
    const sendJitter = this.random(this.config.sendJitterMin, this.config.sendJitterMax);
    await this.sleep(sendJitter);

    // Track for rate limiting
    this.sentTimestamps.push(Date.now());

    return true;
  }

  /**
   * After sending: maybe go briefly offline (humans don't stare at chat 24/7)
   */
  async afterSend(jid: string): Promise<void> {
    if (!this.socket) return;

    // Random chance to go "unavailable" briefly
    if (Math.random() < this.config.offlineFlickerChance) {
      const duration = this.random(this.config.offlineFlickerMin, this.config.offlineFlickerMax);
      console.log(`[Human] 📱 Going offline for ${Math.round(duration / 1000)}s`);

      await this.socket.sendPresenceUpdate('unavailable');
      await this.sleep(duration);
      await this.socket.sendPresenceUpdate('available', jid);
    }
  }

  /**
   * Simulate reading a message with human-like delay.
   * Call when receiving a message before processing.
   */
  async simulateRead(
    jid: string,
    messageKey: { remoteJid: string; id: string; participant?: string },
  ): Promise<void> {
    if (!this.socket) return;

    // Humans don't read instantly — delay 1-5 seconds
    const delay = this.random(1000, 5000);
    await this.sleep(delay);

    // Mark as read (sends blue ticks)
    await this.socket.readMessages([messageKey]);
  }

  // ══════════════════════════════════════════
  // PRESENCE SCHEDULE
  // ══════════════════════════════════════════

  /**
   * Periodically toggle presence to look natural.
   * Humans go online/offline throughout the day.
   */
  private startPresenceSchedule(): void {
    if (this.presenceTimer) clearInterval(this.presenceTimer);

    // Check every 5-15 minutes (randomized)
    const scheduleNext = () => {
      const interval = this.random(5 * 60_000, 15 * 60_000);
      this.presenceTimer = setTimeout(async () => {
        await this.presenceTick();
        scheduleNext();
      }, interval);
    };

    scheduleNext();
  }

  private async presenceTick(): Promise<void> {
    if (!this.socket) return;

    const hour = new Date().getHours();

    if (hour >= this.config.sleepHour || hour < this.config.wakeHour) {
      // Sleep time
      if (!this.sleeping) {
        console.log('[Human] 😴 Going to sleep');
        this.sleeping = true;
        await this.socket.sendPresenceUpdate('unavailable');
      }
    } else {
      // Awake time
      if (this.sleeping) {
        console.log('[Human] ☀️ Waking up');
        this.sleeping = false;
        await this.socket.sendPresenceUpdate('available');

        // Process sleep queue
        const queue = [...this.sleepQueue];
        this.sleepQueue = [];
        for (const fn of queue) fn();
      } else {
        // Random presence flicker during the day
        if (Math.random() < 0.3) {
          await this.socket.sendPresenceUpdate('unavailable');
          await this.sleep(this.random(30_000, 120_000));
          await this.socket.sendPresenceUpdate('available');
        }
      }
    }
  }

  // ══════════════════════════════════════════
  // RATE LIMITING
  // ══════════════════════════════════════════

  private checkRateLimit(): boolean {
    const now = Date.now();

    // Clean old timestamps
    this.sentTimestamps = this.sentTimestamps.filter(t => now - t < 3600_000);

    // Per-minute check
    const lastMinute = this.sentTimestamps.filter(t => now - t < 60_000);
    if (lastMinute.length >= this.config.maxMessagesPerMinute) return false;

    // Per-hour check
    if (this.sentTimestamps.length >= this.config.maxMessagesPerHour) return false;

    return true;
  }

  // ══════════════════════════════════════════
  // BROWSER CONFIG
  // ══════════════════════════════════════════

  /**
   * Returns realistic browser config for makeWASocket.
   * Rotates between common browsers to avoid fingerprint lock.
   */
  static getBrowserConfig(): [string, string, string] {
    const browsers: Array<[string, string, string]> = [
      ['Ubuntu', 'Chrome', '122.0.6261.94'],
      ['Windows', 'Chrome', '122.0.6261.94'],
      ['macOS', 'Safari', '17.3.1'],
      ['Windows', 'Edge', '122.0.2365.66'],
      ['Ubuntu', 'Firefox', '123.0'],
    ];

    // Pick one deterministically per day (don't rotate mid-session)
    const dayIndex = Math.floor(Date.now() / 86400_000) % browsers.length;
    return browsers[dayIndex];
  }

  // ══════════════════════════════════════════
  // HELPERS
  // ══════════════════════════════════════════

  isSleepTime(): boolean {
    const hour = new Date().getHours();
    if (this.config.sleepHour > this.config.wakeHour) {
      return hour >= this.config.sleepHour || hour < this.config.wakeHour;
    }
    return hour >= this.config.sleepHour && hour < this.config.wakeHour;
  }

  private random(min: number, max: number): number {
    // Use gaussian-ish distribution for more human-like variance
    const u1 = Math.random();
    const u2 = Math.random();
    const normal = Math.sqrt(-2 * Math.log(u1)) * Math.cos(2 * Math.PI * u2);
    // Map to range with center bias
    const mid = (min + max) / 2;
    const range = (max - min) / 2;
    const value = mid + normal * range * 0.4; // 0.4 = tightness
    return Math.max(min, Math.min(max, Math.round(value)));
  }

  private sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}
