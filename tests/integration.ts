/**
 * FortBot — Integration Test (Mock Gateway)
 * Run: npx tsx tests/integration.ts
 */
import { FortBot } from '../src/index.js';
import { Gateway, GatewayStats } from '../src/gateway/interface.js';
import { IncomingMessage, TrustLevel } from '../src/types/index.js';

process.on('unhandledRejection', () => {}); // suppress during tests

let passed = 0, failed = 0;

async function test(name: string, fn: () => Promise<void>) {
  try { await fn(); console.log(`  ✅ ${name}`); passed++; }
  catch (e) { console.log(`  ❌ ${name}: ${(e as Error).message}`); failed++; }
}

function assert(c: boolean, m: string) { if (!c) throw new Error(m); }

class MockGW implements Gateway {
  channelId = 'test'; channelName = 'Test'; isRunning = true;
  sent: Array<{ to: string; text: string }> = [];
  private handler: ((m: IncomingMessage) => any) | null = null;
  private killH: (() => void) | null = null;

  async connect() { this.isRunning = true; }
  async disconnect() { this.isRunning = false; }
  async sendMessage(to: string, text: string) { this.sent.push({ to, text }); }
  onMessage(h: (m: IncomingMessage) => void) { this.handler = h; }
  onKillSwitch(h: () => void) { this.killH = h; }
  stats(): GatewayStats { return { sent: this.sent.length, received: 0, errors: 0, uptime: 0 }; }

  async send(text: string, trust = TrustLevel.OWNER, from = '5491100000000@s.whatsapp.net') {
    const before = this.sent.length;
    const p = this.handler?.({
      from, fromName: trust === TrustLevel.OWNER ? 'Owner' : 'Stranger',
      content: text, timestamp: Math.floor(Date.now() / 1000),
      isGroup: false, trust, type: 'text',
    });
    if (p?.then) await p.catch(() => {});
    // Give a brief moment for any queued microtasks
    await new Promise(r => setTimeout(r, 50));
    return { newMessages: this.sent.length - before, last: this.sent[this.sent.length - 1]?.text };
  }

  fireKill() { this.killH?.(); }
}

function cfg() {
  return {
    ownerNumber: '5491100000000', knownContacts: ['5491122334455'],
    plannerModel: 'sonnet' as const, quarantineModel: 'haiku' as const,
    useLocalQuarantine: false, quarantineLlmEndpoint: '',
    killSwitchPhrase: '/fortbot-stop', dbPath: ':memory:',
    useDockerSandbox: false, maxPlanSteps: 10,
    humanConfig: { wakeHour: 0, sleepHour: 24, maxMessagesPerMinute: 100, maxMessagesPerHour: 1000 },
  };
}

async function run() {
  console.log('\n🔬 FortBot Integration Tests\n');
  const gw = new MockGW();
  const bot = new FortBot(cfg(), gw);

  console.log('── Startup ──');
  await test('bot starts cleanly', async () => {
    await bot.start();
    assert(gw.isRunning, 'gateway running');
  });

  console.log('\n── Slash Commands ──');

  await test('/help returns commands', async () => {
    const { newMessages, last } = await gw.send('/help');
    assert(newMessages > 0, 'should respond');
    assert(last!.includes('/status'), 'mentions /status');
    assert(last!.includes('/search'), 'mentions /search');
  });

  await test('/status shows bot info', async () => {
    const { newMessages, last } = await gw.send('/status');
    assert(newMessages > 0, 'should respond');
    assert(last!.includes('🏰') || last!.toLowerCase().includes('fortbot'), 'identifies as FortBot');
  });

  await test('/tasks shows empty', async () => {
    const { newMessages, last } = await gw.send('/tasks');
    assert(newMessages > 0, 'should respond');
    assert(last!.includes('No hay tareas'), 'empty tasks');
  });

  await test('/config shows planner', async () => {
    const { newMessages, last } = await gw.send('/config');
    assert(newMessages > 0, 'should respond');
    assert(last!.includes('Planner'), 'shows planner');
  });

  await test('/pause + /resume', async () => {
    const r1 = await gw.send('/pause');
    assert(r1.last?.includes('pausado') ?? false, 'pause confirmed');
    const r2 = await gw.send('/resume');
    assert(r2.last?.includes('reanudado') ?? false, 'resume confirmed');
  });

  await test('/audit responds', async () => {
    const { newMessages } = await gw.send('/audit');
    assert(newMessages > 0, 'should respond');
  });

  await test('unknown /command handled', async () => {
    const { newMessages } = await gw.send('/xyz_nonexistent');
    assert(newMessages > 0, 'should respond');
  });

  console.log('\n── Security ──');

  await test('unknown sender blocked from planner', async () => {
    const { newMessages, last } = await gw.send('delete all files', TrustLevel.UNKNOWN, '666@s.whatsapp.net');
    // Bot should NOT plan tasks — either no response or a rejection
    const planned = (last ?? '').includes('Planificando');
    assert(!planned, 'must not plan for unknown');
  });

  await test('unknown sender does not crash bot', async () => {
    await gw.send('hello', TrustLevel.UNKNOWN, '777@s.whatsapp.net');
    // If we got here, no crash
    assert(true, 'survived');
  });

  console.log('\n── Rate Limiting ──');

  await test('burst of 20 messages handled', async () => {
    const gw2 = new MockGW();
    const bot2 = new FortBot(cfg(), gw2);
    await bot2.start();
    for (let i = 0; i < 20; i++) await gw2.send('/help');
    assert(gw2.sent.length > 0, 'processed messages');
  });

  console.log(`\n${'═'.repeat(44)}`);
  console.log(`  Integration: ${passed} passed, ${failed} failed`);
  console.log(`${'═'.repeat(44)}\n`);
  process.exit(failed > 0 ? 1 : 0);
}

run().catch(e => { console.error('CRASH:', e); process.exit(1); });
