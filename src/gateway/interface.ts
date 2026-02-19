/**
 * FORTBOT — Gateway Interface
 *
 * Abstract channel interface that all messaging gateways must implement.
 * This allows the core (FortBot, Executor, Planner) to work with any
 * messaging platform without knowing the details.
 *
 * Current implementations:
 *   - WhatsAppGateway (Baileys)
 *
 * Planned:
 *   - TelegramGateway (grammy/telegraf)
 *   - WebGateway (WebSocket server)
 *   - CLIGateway (for testing)
 */

import { IncomingMessage, TrustLevel } from '../types/index.js';

export type MessageHandler = (msg: IncomingMessage) => Promise<void>;
export type KillHandler = () => void;

/**
 * All gateways must implement this interface.
 */
export interface Gateway {
  /** Unique channel identifier */
  readonly channelId: string;

  /** Human-readable name */
  readonly channelName: string;

  /** Connect to the messaging service */
  connect(): Promise<void>;

  /** Disconnect cleanly */
  disconnect(): Promise<void>;

  /** Register the incoming message handler */
  onMessage(handler: MessageHandler): void;

  /** Register the kill switch handler */
  onKillSwitch(handler: KillHandler): void;

  /** Send a text message */
  sendMessage(to: string, text: string): Promise<void>;

  /** Send an audio message (optional — not all channels support it) */
  sendAudio?(to: string, audioBuffer: Buffer): Promise<void>;

  /** Send an image message (optional) */
  sendImage?(to: string, imageBuffer: Buffer, caption?: string): Promise<void>;

  /** Send a file/document (optional) */
  sendDocument?(to: string, fileBuffer: Buffer, filename: string): Promise<void>;

  /** Is the gateway currently connected? */
  isConnected(): boolean;

  /** Get connection stats */
  stats(): GatewayStats;
}

export interface GatewayStats {
  connected: boolean;
  uptime: number;
  messagesSent: number;
  messagesReceived: number;
  errors: number;
}

/**
 * Multi-gateway router.
 * Dispatches messages from multiple channels to a single handler.
 * Routes outgoing messages to the correct channel.
 */
export class GatewayRouter {
  private gateways: Map<string, Gateway> = new Map();
  private handler: MessageHandler | null = null;
  private killHandler: KillHandler | null = null;

  /** Register a gateway */
  addGateway(gw: Gateway): void {
    this.gateways.set(gw.channelId, gw);

    gw.onMessage(async (msg) => {
      // Tag message with channel info
      (msg as any)._channel = gw.channelId;
      if (this.handler) await this.handler(msg);
    });

    gw.onKillSwitch(() => {
      if (this.killHandler) this.killHandler();
    });
  }

  /** Set the unified message handler */
  onMessage(handler: MessageHandler): void {
    this.handler = handler;
  }

  /** Set the kill switch handler */
  onKillSwitch(handler: KillHandler): void {
    this.killHandler = handler;
  }

  /** Connect all gateways */
  async connectAll(): Promise<void> {
    const results = await Promise.allSettled(
      Array.from(this.gateways.values()).map(gw => gw.connect())
    );
    for (const [i, result] of results.entries()) {
      const gw = Array.from(this.gateways.values())[i];
      if (result.status === 'rejected') {
        console.error(`[GatewayRouter] Failed to connect ${gw.channelName}:`, result.reason);
      } else {
        console.log(`[GatewayRouter] ✅ ${gw.channelName} connected`);
      }
    }
  }

  /** Disconnect all gateways */
  async disconnectAll(): Promise<void> {
    await Promise.allSettled(
      Array.from(this.gateways.values()).map(gw => gw.disconnect())
    );
  }

  /** Send a message through a specific channel */
  async sendMessage(channelId: string, to: string, text: string): Promise<void> {
    const gw = this.gateways.get(channelId);
    if (!gw) throw new Error(`Unknown channel: ${channelId}`);
    await gw.sendMessage(to, text);
  }

  /** Send through the default (first) gateway */
  async sendDefault(to: string, text: string): Promise<void> {
    const first = this.gateways.values().next().value;
    if (!first) throw new Error('No gateways registered');
    await first.sendMessage(to, text);
  }

  /** Get a specific gateway */
  getGateway(channelId: string): Gateway | undefined {
    return this.gateways.get(channelId);
  }

  /** List all gateways with their status */
  status(): Array<{ channelId: string; name: string; connected: boolean }> {
    return Array.from(this.gateways.values()).map(gw => ({
      channelId: gw.channelId,
      name: gw.channelName,
      connected: gw.isConnected(),
    }));
  }
}
