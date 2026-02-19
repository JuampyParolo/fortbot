/**
 * FORTBOT — CLI Gateway
 *
 * For testing/development: chat with FortBot from the terminal.
 * No WhatsApp needed. Messages go to stdin/stdout.
 *
 * Usage: FORTBOT_GATEWAY=cli npm run dev
 */

import { createInterface } from 'readline';
import { IncomingMessage, TrustLevel, FortBotConfig } from '../types/index.js';
import { Gateway, GatewayStats, MessageHandler, KillHandler } from './interface.js';

export class CLIGateway implements Gateway {
  readonly channelId = 'cli';
  readonly channelName = 'CLI (Terminal)';

  private config: FortBotConfig;
  private messageHandler: MessageHandler | null = null;
  private killHandler: KillHandler | null = null;
  private _connected = false;
  private startedAt = 0;
  private _sent = 0;
  private _received = 0;
  private rl: ReturnType<typeof createInterface> | null = null;

  constructor(config: FortBotConfig) {
    this.config = config;
  }

  onMessage(handler: MessageHandler): void { this.messageHandler = handler; }
  onKillSwitch(handler: KillHandler): void { this.killHandler = handler; }

  async connect(): Promise<void> {
    this.rl = createInterface({
      input: process.stdin,
      output: process.stdout,
      prompt: '\n🏰 > ',
    });

    this._connected = true;
    this.startedAt = Date.now();

    console.log('\n╔═══════════════════════════════════════╗');
    console.log('║  🏰 FortBot CLI Mode                  ║');
    console.log('║  Type messages to chat with the bot    ║');
    console.log('║  /help for commands — Ctrl+C to exit   ║');
    console.log('╚═══════════════════════════════════════╝\n');

    this.rl.prompt();

    this.rl.on('line', async (line) => {
      const text = line.trim();
      if (!text) { this.rl?.prompt(); return; }

      // Kill switch
      if (text === this.config.killSwitchPhrase) {
        this.killHandler?.();
        return;
      }

      this._received++;

      const msg: IncomingMessage = {
        from: `${this.config.ownerNumber}@s.whatsapp.net`,
        fromName: 'Owner (CLI)',
        isGroup: false,
        content: text,
        type: 'text',
        timestamp: Math.floor(Date.now() / 1000),
        trust: TrustLevel.OWNER,
      };

      try {
        await this.messageHandler?.(msg);
      } catch (err) {
        console.error('\n❌ Error:', err instanceof Error ? err.message : err);
      }

      this.rl?.prompt();
    });

    this.rl.on('close', () => {
      console.log('\n👋 Chau!');
      process.exit(0);
    });
  }

  async disconnect(): Promise<void> {
    this._connected = false;
    this.rl?.close();
  }

  async sendMessage(_to: string, text: string): Promise<void> {
    this._sent++;
    // Format bot responses nicely
    const lines = text.split('\n');
    console.log('\n┌─ 🏰 FortBot ─────────────────────');
    for (const line of lines) {
      console.log(`│ ${line}`);
    }
    console.log('└──────────────────────────────────');
  }

  async sendAudio(_to: string, _buf: Buffer): Promise<void> {
    console.log('\n┌─ 🏰 FortBot ─────────────────────');
    console.log('│ 🎤 [audio message - no playback in CLI]');
    console.log('└──────────────────────────────────');
    this._sent++;
  }

  isConnected(): boolean {
    return this._connected;
  }

  stats(): GatewayStats {
    return {
      connected: this._connected,
      uptime: this.startedAt ? Date.now() - this.startedAt : 0,
      messagesSent: this._sent,
      messagesReceived: this._received,
      errors: 0,
    };
  }
}
