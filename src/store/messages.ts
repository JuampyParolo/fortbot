/**
 * FORTBOT - Message Store
 *
 * Persists all WhatsApp messages locally in SQLite.
 * Uses sql.js (pure JS, no native bindings needed).
 *
 * Tables:
 *   messages: id, jid, sender_jid, sender_name, content, type, trust, timestamp, created_at
 *   audit_log: id, event, data, created_at
 */

import initSqlJs, { Database as SqlJsDatabase } from 'sql.js';
import { IncomingMessage, TrustLevel } from '../types/index.js';
import { readFileSync, writeFileSync, existsSync } from 'fs';
import { createCipheriv, createDecipheriv, randomBytes, scryptSync } from 'crypto';

/**
 * Encrypt a buffer using AES-256-GCM with key derived from password.
 * Format: [16 bytes salt][12 bytes iv][16 bytes authTag][...ciphertext]
 */
function encryptBuffer(data: Buffer, password: string): Buffer {
  const salt = randomBytes(16);
  const key = scryptSync(password, salt, 32);
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  const encrypted = Buffer.concat([cipher.update(data), cipher.final()]);
  const authTag = cipher.getAuthTag();
  return Buffer.concat([salt, iv, authTag, encrypted]);
}

/**
 * Decrypt a buffer encrypted with encryptBuffer.
 */
function decryptBuffer(data: Buffer, password: string): Buffer {
  const salt = data.subarray(0, 16);
  const iv = data.subarray(16, 28);
  const authTag = data.subarray(28, 44);
  const ciphertext = data.subarray(44);
  const key = scryptSync(password, salt, 32);
  const decipher = createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(authTag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}

export class MessageStore {
  private db: SqlJsDatabase | null = null;
  private dbPath: string;
  private ready: Promise<void>;
  private dirty = false;
  private hasFts = false;
  private saveInterval: ReturnType<typeof setInterval> | null = null;
  private auditRotationCounter = 0;
  /** Password for at-rest encryption. If set, DB file is AES-256-GCM encrypted. */
  private encryptionPassword: string | null = null;

  constructor(dbPath: string, encryptionPassword?: string) {
    this.dbPath = dbPath;
    this.encryptionPassword = encryptionPassword ?? process.env.FORTBOT_DB_PASSWORD ?? null;
    this.ready = this.init();
  }

  private async init(): Promise<void> {
    const SQL = await initSqlJs();

    if (existsSync(this.dbPath) && this.dbPath !== ':memory:') {
      const raw = readFileSync(this.dbPath);
      let buffer: Buffer;

      if (this.encryptionPassword && raw.length > 44) {
        // Try to decrypt — if it fails, it might be an unencrypted legacy DB
        try {
          buffer = decryptBuffer(raw, this.encryptionPassword);
        } catch {
          // Legacy unencrypted DB — load as-is, will encrypt on next persist
          console.log('[Store] Loading unencrypted DB (will encrypt on next save)');
          buffer = raw;
        }
      } else {
        buffer = raw;
      }

      this.db = new SQL.Database(buffer);
    } else if (this.dbPath === ':memory:') {
      this.db = new SQL.Database();
    } else {
      this.db = new SQL.Database();
    }

    this.db.run(`
      CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        jid TEXT NOT NULL,
        sender_jid TEXT NOT NULL,
        sender_name TEXT NOT NULL,
        content TEXT NOT NULL,
        type TEXT NOT NULL DEFAULT 'text',
        trust TEXT NOT NULL,
        timestamp INTEGER NOT NULL,
        created_at TEXT NOT NULL DEFAULT (datetime('now'))
      )
    `);
    this.db.run(`CREATE INDEX IF NOT EXISTS idx_messages_jid ON messages(jid)`);
    this.db.run(`CREATE INDEX IF NOT EXISTS idx_messages_ts ON messages(timestamp)`);
    this.db.run(`CREATE INDEX IF NOT EXISTS idx_messages_sender ON messages(sender_jid)`);

    // FTS virtual table for fast search (optional — sql.js may not have fts5)
    try {
      this.db.run(`
        CREATE VIRTUAL TABLE IF NOT EXISTS messages_fts USING fts5(
          content, sender_name,
          content='messages', content_rowid='id'
        )
      `);
      this.db.run(`
        CREATE TRIGGER IF NOT EXISTS messages_ai AFTER INSERT ON messages BEGIN
          INSERT INTO messages_fts(rowid, content, sender_name) VALUES (new.id, new.content, new.sender_name);
        END
      `);
      this.hasFts = true;
    } catch {
      console.log('[Store] FTS5 not available — using LIKE search fallback');
      this.hasFts = false;
    }

    this.db.run(`
      CREATE TABLE IF NOT EXISTS audit_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        event TEXT NOT NULL,
        data TEXT,
        created_at TEXT NOT NULL DEFAULT (datetime('now'))
      )
    `);

    // Auto-save every 10 seconds if dirty
    this.saveInterval = setInterval(() => this.persist(), 10000);
  }

  private persist(): void {
    if (!this.dirty || !this.db) return;
    if (this.dbPath === ':memory:') { this.dirty = false; return; }
    const data = Buffer.from(this.db.export());
    if (this.encryptionPassword) {
      writeFileSync(this.dbPath, encryptBuffer(data, this.encryptionPassword));
    } else {
      writeFileSync(this.dbPath, data);
    }
    this.dirty = false;
  }

  private ensureDb(): SqlJsDatabase {
    if (!this.db) throw new Error('Database not initialized. Await store.waitReady()');
    return this.db;
  }

  async waitReady(): Promise<void> {
    await this.ready;
  }

  store(msg: IncomingMessage): void {
    const db = this.ensureDb();
    const chatJid = msg.isGroup ? (msg.groupId ?? msg.from) : msg.from;
    const normalized = chatJid.split('@')[0];
    const senderNorm = msg.from.split('@')[0];

    db.run(
      `INSERT INTO messages (jid, sender_jid, sender_name, content, type, trust, timestamp)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [normalized, senderNorm, msg.fromName, msg.content, msg.type, msg.trust, msg.timestamp]
    );
    this.dirty = true;
  }

  /**
   * Store a message sent BY the bot.
   */
  storeOutgoing(toJid: string, content: string): void {
    const db = this.ensureDb();
    const normalized = toJid.split('@')[0].replace(/[^0-9]/g, '');
    db.run(
      `INSERT INTO messages (jid, sender_jid, sender_name, content, type, trust, timestamp)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [normalized, 'fortbot', 'FortBot', content, 'text', 'system', Math.floor(Date.now() / 1000)]
    );
    this.dirty = true;
  }

  /**
   * Get conversation history for context injection (both incoming and outgoing).
   */
  getConversationHistory(chatJid: string, limit = 30): StoredMessage[] {
    const db = this.ensureDb();
    const normalized = chatJid.replace(/[^0-9]/g, '');
    const stmt = db.prepare(
      `SELECT sender_name, content, type, trust, timestamp
       FROM messages WHERE jid = ? ORDER BY timestamp DESC, id DESC LIMIT ?`
    );
    stmt.bind([normalized, limit]);

    const rows: StoredMessage[] = [];
    while (stmt.step()) {
      const r = stmt.getAsObject() as Record<string, unknown>;
      rows.push({
        sender_name: String(r.sender_name),
        content: String(r.content),
        type: String(r.type),
        trust: String(r.trust) as TrustLevel,
        timestamp: Number(r.timestamp),
      });
    }
    stmt.free();
    return rows.reverse(); // chronological
  }

  readMessages(chatJid: string, limit = 20): StoredMessage[] {
    const db = this.ensureDb();
    const normalized = chatJid.replace(/[^0-9]/g, '');
    const stmt = db.prepare(
      `SELECT sender_name, content, type, trust, timestamp
       FROM messages WHERE jid = ? ORDER BY timestamp DESC LIMIT ?`
    );
    stmt.bind([normalized, limit]);

    const rows: StoredMessage[] = [];
    while (stmt.step()) {
      const r = stmt.getAsObject() as Record<string, unknown>;
      rows.push({
        sender_name: String(r.sender_name),
        content: String(r.content),
        type: String(r.type),
        trust: String(r.trust) as TrustLevel,
        timestamp: Number(r.timestamp),
      });
    }
    stmt.free();
    return rows.reverse(); // chronological
  }

  searchMessages(query: string, chatJid?: string, limit = 10): StoredMessage[] {
    const db = this.ensureDb();
    const normalizedJid = chatJid?.replace(/[^0-9]/g, '');

    // Try FTS first if available
    if (this.hasFts) {
      try {
        const ftsRows = this.searchFts(db, query, normalizedJid, limit);
        if (ftsRows.length > 0) return ftsRows;
      } catch { /* FTS can fail on special chars — fall through */ }
    }

    // Fallback: LIKE search
    let sql = `SELECT sender_name, content, type, trust, timestamp FROM messages WHERE content LIKE ?`;
    const params: (string | number)[] = [`%${query}%`];
    if (normalizedJid) { sql += ` AND jid = ?`; params.push(normalizedJid); }
    sql += ` ORDER BY timestamp DESC LIMIT ?`;
    params.push(limit);

    const stmt = db.prepare(sql);
    stmt.bind(params);
    const rows: StoredMessage[] = [];
    while (stmt.step()) {
      const r = stmt.getAsObject() as Record<string, unknown>;
      rows.push({
        sender_name: String(r.sender_name), content: String(r.content),
        type: String(r.type), trust: String(r.trust) as TrustLevel, timestamp: Number(r.timestamp),
      });
    }
    stmt.free();
    return rows;
  }

  private searchFts(db: SqlJsDatabase, query: string, jid: string | undefined, limit: number): StoredMessage[] {
    const sql = jid
      ? `SELECT m.sender_name, m.content, m.type, m.trust, m.timestamp
         FROM messages_fts f JOIN messages m ON f.rowid = m.id
         WHERE messages_fts MATCH ? AND m.jid = ? ORDER BY rank LIMIT ?`
      : `SELECT m.sender_name, m.content, m.type, m.trust, m.timestamp
         FROM messages_fts f JOIN messages m ON f.rowid = m.id
         WHERE messages_fts MATCH ? ORDER BY rank LIMIT ?`;
    const params = jid ? [query, jid, limit] : [query, limit];

    const stmt = db.prepare(sql);
    stmt.bind(params);
    const rows: StoredMessage[] = [];
    while (stmt.step()) {
      const r = stmt.getAsObject() as Record<string, unknown>;
      rows.push({
        sender_name: String(r.sender_name), content: String(r.content),
        type: String(r.type), trust: String(r.trust) as TrustLevel, timestamp: Number(r.timestamp),
      });
    }
    stmt.free();
    return rows;
  }

  audit(event: string, data?: Record<string, unknown>): void {
    const db = this.ensureDb();
    db.run(
      `INSERT INTO audit_log (event, data) VALUES (?, ?)`,
      [event, data ? JSON.stringify(data) : null]
    );
    this.dirty = true;
    this.persist(); // Audit entries persist immediately — they're security evidence

    // ── LOG ROTATION: keep last 10,000 entries ──
    this.auditRotationCounter = (this.auditRotationCounter ?? 0) + 1;
    if (this.auditRotationCounter % 100 === 0) { // Check every 100 inserts
      try {
        const countResult = db.exec('SELECT COUNT(*) FROM audit_log');
        const count = countResult[0]?.values[0]?.[0] as number ?? 0;
        if (count > 10000) {
          db.run(
            `DELETE FROM audit_log WHERE id IN (SELECT id FROM audit_log ORDER BY id ASC LIMIT ?)`,
            [count - 10000]
          );
          this.dirty = true;
        }
      } catch { /* rotation failure is non-critical */ }
    }
  }

  recentAudit(limit = 10): AuditRow[] {
    const db = this.ensureDb();
    const stmt = db.prepare('SELECT event, data, created_at FROM audit_log ORDER BY id DESC LIMIT ?');
    stmt.bind([limit]);

    const rows: AuditRow[] = [];
    while (stmt.step()) {
      const r = stmt.getAsObject() as Record<string, unknown>;
      rows.push({
        event: String(r.event),
        data: String(r.data ?? ''),
        created_at: String(r.created_at),
      });
    }
    stmt.free();
    return rows;
  }

  stats(): { totalMessages: number; uniqueChats: number; lastMessage: string | null } {
    const db = this.ensureDb();
    const total = db.exec('SELECT COUNT(*) FROM messages');
    const chats = db.exec('SELECT COUNT(DISTINCT jid) FROM messages');
    const last = db.exec('SELECT created_at FROM messages ORDER BY id DESC LIMIT 1');

    return {
      totalMessages: total[0]?.values[0]?.[0] as number ?? 0,
      uniqueChats: chats[0]?.values[0]?.[0] as number ?? 0,
      lastMessage: last[0]?.values[0]?.[0] as string ?? null,
    };
  }

  close(): void {
    this.persist(); // Final save
    if (this.saveInterval) clearInterval(this.saveInterval);
    if (this.db) this.db.close();
    this.db = null;
  }
}

export interface StoredMessage {
  sender_name: string;
  content: string;
  type: string;
  trust: TrustLevel;
  timestamp: number;
}

export interface AuditRow {
  event: string;
  data: string;
  created_at: string;
}
