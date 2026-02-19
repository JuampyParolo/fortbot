/**
 * FORTBOT v0.4 - Entry Point
 */

import 'dotenv/config';
import { FortBot } from './index.js';

const config = {
  ownerNumber: process.env.OWNER_NUMBER ?? '',
  knownContacts: (process.env.KNOWN_CONTACTS ?? '').split(',').filter(Boolean),
  plannerModel: (process.env.PLANNER_MODEL as 'sonnet' | 'opus' | 'haiku') ?? 'sonnet',
  quarantineModel: (process.env.QUARANTINE_MODEL as 'sonnet' | 'opus' | 'haiku') ?? 'haiku',
  useLocalQuarantine: process.env.USE_LOCAL_QUARANTINE === 'true',
  quarantineLlmEndpoint: process.env.LOCAL_LLM_ENDPOINT ?? 'http://localhost:11434',
  killSwitchPhrase: process.env.KILL_SWITCH ?? '/fortbot-stop',
  dbPath: process.env.DB_PATH ?? './fortbot.db',
  humanConfig: {
    wakeHour: Number(process.env.HUMAN_WAKE_HOUR ?? 8),
    sleepHour: Number(process.env.HUMAN_SLEEP_HOUR ?? 23),
    maxMessagesPerMinute: Number(process.env.HUMAN_MAX_MSG_MIN ?? 4),
    maxMessagesPerHour: Number(process.env.HUMAN_MAX_MSG_HOUR ?? 30),
  },
};

// Gateway selection: cli for terminal testing, whatsapp (default) for production
const gatewayType = process.env.FORTBOT_GATEWAY ?? 'whatsapp';

async function main() {
  let gateway;

  if (gatewayType === 'cli') {
    const { CLIGateway } = await import('./gateway/cli.js');
    gateway = new CLIGateway(config as any);
  } else {
    const { WhatsAppGateway } = await import('./gateway/whatsapp.js');
    gateway = new WhatsAppGateway(config as any);
  }

  const fortbot = new FortBot(config, gateway);
  await fortbot.start();
}

// ── AUTO-RESTART WITH BACKOFF ──
const MAX_RESTARTS = 5;
const BASE_BACKOFF_MS = 3000;
let restartCount = 0;
let lastCrash = 0;

async function startWithRestart() {
  while (restartCount < MAX_RESTARTS) {
    try {
      await main();
      // If main() returns normally, exit cleanly
      break;
    } catch (err) {
      const now = Date.now();
      // Reset counter if last crash was >5 min ago (stable period)
      if (now - lastCrash > 300_000) restartCount = 0;
      lastCrash = now;
      restartCount++;

      const backoff = BASE_BACKOFF_MS * Math.pow(2, restartCount - 1);
      console.error(`[FortBot] Fatal crash #${restartCount}/${MAX_RESTARTS}:`, (err as Error).message);
      console.error(`[FortBot] Restarting in ${backoff / 1000}s...`);

      // Write crash info for external monitoring
      try {
        const { writeFileSync, mkdirSync } = await import('fs');
        mkdirSync('./data', { recursive: true });
        writeFileSync('./data/CRASH.log', JSON.stringify({
          timestamp: new Date().toISOString(),
          error: (err as Error).message,
          stack: (err as Error).stack,
          restartCount,
        }) + '\n', { flag: 'a' });
      } catch { /* best effort */ }

      await new Promise(r => setTimeout(r, backoff));
    }
  }

  if (restartCount >= MAX_RESTARTS) {
    console.error(`[FortBot] 🛑 Max restarts (${MAX_RESTARTS}) reached. Giving up.`);
    process.exit(1);
  }
}

startWithRestart();

// Graceful shutdown
for (const signal of ['SIGINT', 'SIGTERM'] as const) {
  process.on(signal, () => {
    console.log(`\n[FortBot] Received ${signal}, shutting down...`);
    process.exit(0);
  });
}

// Catch unhandled errors
process.on('uncaughtException', (err) => {
  console.error('[FortBot] Uncaught exception:', err.message);
  console.error(err.stack);
  // Don't exit — try to keep running
});

process.on('unhandledRejection', (reason) => {
  console.error('[FortBot] Unhandled rejection:', reason);
  // Don't exit — try to keep running
});
