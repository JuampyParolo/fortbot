/**
 * FORTBOT - WhatsApp Gateway
 *
 * Handles WhatsApp connection via Baileys.
 * Assigns trust levels, routes messages, implements kill switch.
 * v0.3.1: HumanEmulator integration for anti-detection.
 */

import {
  IncomingMessage,
  TrustLevel,
  FortBotConfig,
} from '../types/index.js';
import { HumanEmulator } from './human.js';
import { Gateway, GatewayStats, MessageHandler, KillHandler } from './interface.js';

// Type stubs for Baileys
interface BaileysSocket {
  ev: { on: (event: string, handler: (...args: unknown[]) => void | Promise<void>) => void };
  sendMessage: (jid: string, content: Record<string, unknown>) => Promise<void>;
  sendPresenceUpdate: (presence: string, jid?: string) => Promise<void>;
  readMessages: (keys: Array<{ remoteJid: string; id: string; participant?: string }>) => Promise<void>;
  end: (error?: Error) => void;
}

export class WhatsAppGateway implements Gateway {
  readonly channelId = 'whatsapp';
  readonly channelName = 'WhatsApp (Baileys)';

  private config: FortBotConfig;
  private socket: BaileysSocket | null = null;
  private messageHandler: MessageHandler | null = null;
  private killHandler: KillHandler | null = null;
  private human: HumanEmulator;
  private _isRunning = false;
  private reconnectAttempts = 0;
  private maxReconnects = 10;
  private startedAt = 0;
  private _messagesSent = 0;
  private _messagesReceived = 0;
  private _errors = 0;

  constructor(config: FortBotConfig) {
    this.config = config;
    this.human = new HumanEmulator(config.humanConfig);
  }

  onMessage(handler: MessageHandler): void { this.messageHandler = handler; }
  onKillSwitch(handler: KillHandler): void { this.killHandler = handler; }

  async connect(): Promise<void> {
    const {
      default: makeWASocket,
      DisconnectReason,
      useMultiFileAuthState,
    } = await import('@whiskeysockets/baileys');

    const { state, saveCreds } = await useMultiFileAuthState('./auth_store');

    const browserConfig = HumanEmulator.getBrowserConfig();

    this.socket = makeWASocket({
      auth: state,
      printQRInTerminal: true,
      browser: browserConfig,
      markOnlineOnConnect: false,  // Don't auto-mark as online
    }) as unknown as BaileysSocket;

    this.socket.ev.on('creds.update', saveCreds as () => void);

    this.socket.ev.on('connection.update', (update: unknown) => {
      const { connection, lastDisconnect, qr } = update as {
        connection?: string;
        lastDisconnect?: { error?: { output?: { statusCode?: number } } };
        qr?: string;
      };

      if (qr) {
        console.log('[Gateway] QR code generated — scan with bot WhatsApp');
        this.reconnectAttempts = 0;
      }

      if (connection === 'close') {
        const code = lastDisconnect?.error?.output?.statusCode;
        const isLoggedOut = code === DisconnectReason.loggedOut;
        const isBanned = code === 405 || code === 403;

        if (isLoggedOut || isBanned) {
          console.error(`[Gateway] ${isLoggedOut ? 'Logged out' : 'Banned'}. Cannot reconnect.`);
          console.error('[Gateway] Delete ./auth_store and restart to re-scan QR.');
          this._isRunning = false;
          this.human.unbind();
          return;
        }

        this.reconnectAttempts++;
        if (this.reconnectAttempts > this.maxReconnects) {
          console.error(`[Gateway] Max reconnect attempts (${this.maxReconnects}) reached.`);
          this._isRunning = false;
          this.human.unbind();
          return;
        }

        const delay = Math.min(3000 * this.reconnectAttempts, 30000);
        console.log(`[Gateway] Reconnecting in ${delay}ms (${this.reconnectAttempts}/${this.maxReconnects})`);
        setTimeout(() => this.connect(), delay);

      } else if (connection === 'open') {
        console.log('[Gateway] ✅ Connected to WhatsApp');
        console.log(`[Gateway] 🧬 Browser: ${browserConfig.join(' / ')}`);
        this._isRunning = true;
        this.startedAt = Date.now();
        this.reconnectAttempts = 0;

        // Bind human emulator to socket
        this.human.bind(this.socket!);

        // Don't immediately go online — wait a bit like a human opening their laptop
        setTimeout(async () => {
          await this.socket!.sendPresenceUpdate('available');
        }, this.randomDelay(2000, 5000));
      }
    });

    this.socket.ev.on('messages.upsert', async (update: unknown) => {
      const { messages } = update as { messages: Array<Record<string, unknown>> };
      for (const msg of messages) {
        if ((msg.key as { fromMe?: boolean })?.fromMe) continue;
        const processed = await this.processMessage(msg);
        if (!processed) continue;

        // Kill switch — bypass human emulation
        if (processed.content.trim() === this.config.killSwitchPhrase) {
          console.log('[Gateway] ⚠️ KILL SWITCH ACTIVATED');
          this.killHandler?.();
          this.sendMessageRaw(processed.from, '🛑 FortBot: Emergency stop.').catch(() => {});
          return;
        }

        // Simulate reading the message like a human
        const key = msg.key as { remoteJid?: string; id?: string; participant?: string };
        if (key.remoteJid && key.id) {
          this.human.simulateRead(key.remoteJid, {
            remoteJid: key.remoteJid,
            id: key.id,
            participant: key.participant,
          }).catch(() => {});
        }

        this._messagesReceived++;
        this.messageHandler?.(processed).catch(err => {
          console.error('[Gateway] Handler error:', err);
          this._errors++;
        });
      }
    });
  }

  private async processMessage(raw: Record<string, unknown>): Promise<IncomingMessage | null> {
    const key = raw.key as { remoteJid?: string; participant?: string } | undefined;
    const message = raw.message as Record<string, unknown> | undefined;
    if (!key?.remoteJid || !message) return null;

    const jid = key.remoteJid;
    const isGroup = jid.endsWith('@g.us');
    const senderJid = isGroup ? (key.participant ?? jid) : jid;

    let content = '';
    let type: IncomingMessage['type'] = 'text';
    let mediaUrl: string | undefined;
    let mediaBuffer: Buffer | undefined;

    if (message.conversation) {
      content = message.conversation as string;
    } else if (message.extendedTextMessage) {
      content = (message.extendedTextMessage as { text?: string }).text ?? '';
    } else if (message.imageMessage) {
      type = 'image';
      content = (message.imageMessage as { caption?: string }).caption ?? '[image]';
      mediaUrl = (message.imageMessage as { url?: string }).url;
    } else if (message.videoMessage) {
      type = 'video';
      content = (message.videoMessage as { caption?: string }).caption ?? '[video]';
    } else if (message.audioMessage) {
      type = 'audio';
      content = '[audio]';
      // Download audio buffer for transcription
      mediaUrl = (message.audioMessage as { url?: string }).url;
      // Try to download audio for transcription
      mediaBuffer = await this.downloadMedia(raw, 'audio');
    } else if (message.documentMessage) {
      type = 'document';
      content = (message.documentMessage as { fileName?: string }).fileName ?? '[document]';
      mediaUrl = (message.documentMessage as { url?: string }).url;
    } else if (message.stickerMessage) {
      type = 'image';
      content = '[sticker]';
    } else {
      return null;
    }

    return {
      from: senderJid,
      fromName: (raw.pushName as string) ?? senderJid,
      isGroup,
      groupId: isGroup ? jid : undefined,
      content,
      type,
      mediaUrl,
      mediaBuffer,
      timestamp: (raw.messageTimestamp as number) ?? Math.floor(Date.now() / 1000),
      trust: this.assignTrust(senderJid),
    };
  }

  /**
   * Download media from a WhatsApp message.
   * Returns Buffer or undefined if download fails.
   */
  private async downloadMedia(raw: Record<string, unknown>, _type: string): Promise<Buffer | undefined> {
    try {
      const { downloadMediaMessage } = await import('@whiskeysockets/baileys');
      const buf = await downloadMediaMessage(raw as any, 'buffer', {}, undefined as any);
      return buf as Buffer;
    } catch (err) {
      console.warn(`[Gateway] Could not download media:`, err instanceof Error ? err.message : err);
      return undefined;
    }
  }

  private assignTrust(senderJid: string): TrustLevel {
    const normalized = senderJid.split('@')[0];
    const ownerNormalized = this.config.ownerNumber.replace(/[^0-9]/g, '');

    if (normalized === ownerNormalized) return TrustLevel.OWNER;

    const knownNormalized = this.config.knownContacts.map(c => c.replace(/[^0-9]/g, ''));
    if (knownNormalized.includes(normalized)) return TrustLevel.KNOWN_CONTACT;

    return TrustLevel.UNKNOWN;
  }

  /**
   * Send message WITH human emulation (typing indicator, delays, etc.)
   */
  async sendMessage(to: string, content: string): Promise<void> {
    if (!this.socket || !this._isRunning) {
      throw new Error('WhatsApp not connected');
    }
    const jid = to.includes('@') ? to : `${to}@s.whatsapp.net`;

    // Split long messages
    if (content.length > 1500) {
      const chunks = this.splitMessage(content, 1500);
      for (const chunk of chunks) {
        // Human emulation before each chunk
        const ok = await this.human.beforeSend(jid, chunk.length);
        if (!ok) {
          console.log('[Gateway] Human emulator blocked send (rate limit or sleep)');
          // Wait and retry once
          await new Promise(r => setTimeout(r, 5000));
          await this.human.beforeSend(jid, chunk.length);
        }
        await this.socket.sendMessage(jid, { text: chunk });
      }
      // After all chunks sent
      await this.human.afterSend(jid);
    } else {
      const ok = await this.human.beforeSend(jid, content.length);
      if (!ok) {
        await new Promise(r => setTimeout(r, 5000));
        await this.human.beforeSend(jid, content.length);
      }
      await this.socket.sendMessage(jid, { text: content });
      await this.human.afterSend(jid);
    }
    this._messagesSent++;
  }

  isConnected(): boolean {
    return this._isRunning && this.socket !== null;
  }

  stats(): GatewayStats {
    return {
      connected: this.isConnected(),
      uptime: this.startedAt ? Date.now() - this.startedAt : 0,
      messagesSent: this._messagesSent,
      messagesReceived: this._messagesReceived,
      errors: this._errors,
    };
  }

  /**
   * Send message WITHOUT human emulation (for kill switch, system alerts)
   */
  private async sendMessageRaw(to: string, content: string): Promise<void> {
    if (!this.socket) return;
    const jid = to.includes('@') ? to : `${to}@s.whatsapp.net`;
    await this.socket.sendMessage(jid, { text: content });
  }

  /**
   * Send an audio voice note to a WhatsApp JID.
   * Buffer should be OGG/Opus format.
   */
  async sendAudio(to: string, audioBuffer: Buffer): Promise<void> {
    if (!this.socket) return;
    const jid = to.includes('@') ? to : `${to}@s.whatsapp.net`;
    await this.socket.sendMessage(jid, {
      audio: audioBuffer,
      mimetype: 'audio/ogg; codecs=opus',
      ptt: true, // voice note (not audio file)
    });
  }

  private splitMessage(text: string, maxLen: number): string[] {
    const chunks: string[] = [];
    const lines = text.split('\n');
    let current = '';

    for (const line of lines) {
      if ((current + '\n' + line).length > maxLen && current.length > 0) {
        chunks.push(current);
        current = line;
      } else {
        current = current ? current + '\n' + line : line;
      }
    }
    if (current) chunks.push(current);
    return chunks;
  }

  private randomDelay(min: number, max: number): number {
    return Math.floor(Math.random() * (max - min)) + min;
  }

  async disconnect(): Promise<void> {
    if (this.socket) {
      this.human.unbind();
      this.socket.end();
      this._isRunning = false;
      console.log('[Gateway] Disconnected');
    }
  }
}
