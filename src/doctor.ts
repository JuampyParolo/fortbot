/**
 * FORTBOT v0.4 - Doctor
 *
 * Pre-flight health check. Verifies everything needed to run.
 * Run: npm run check
 */

import { execSync } from 'child_process';
import { existsSync, readFileSync } from 'fs';

let ok = 0;
let warn = 0;
let fail = 0;

function check(name: string, fn: () => string | null) {
  try {
    const issue = fn();
    if (issue === null) {
      ok++;
      console.log(`  ✅ ${name}`);
    } else {
      warn++;
      console.log(`  ⚠️  ${name}: ${issue}`);
    }
  } catch (err) {
    fail++;
    console.log(`  ❌ ${name}: ${err instanceof Error ? err.message : err}`);
  }
}

console.log('\n🏰 FortBot v0.4 Doctor — Pre-flight Check\n');

// Node version
check('Node.js >= 20', () => {
  const ver = process.version.match(/v(\d+)/)?.[1];
  if (!ver || Number(ver) < 20) throw new Error(`Need Node 20+, got ${process.version}`);
  console.log(`     (${process.version})`);
  return null;
});

// Claude CLI
check('Claude CLI installed', () => {
  try {
    const out = execSync('claude --version 2>&1', { timeout: 5000 }).toString().trim();
    console.log(`     (${out})`);
    return null;
  } catch {
    throw new Error('Not found. Run: npm install -g @anthropic-ai/claude-code');
  }
});

// Claude authenticated
check('Claude authenticated', () => {
  try {
    execSync('claude --print -p "ping" --max-turns 1 2>&1', { timeout: 15000 });
    return null;
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    if (msg.includes('not authenticated') || msg.includes('login')) {
      throw new Error('Not authenticated. Run: claude login');
    }
    return 'Could not verify (may be OK)';
  }
});

// .env file
check('.env file', () => {
  if (!existsSync('.env')) throw new Error('Not found. Run: cp .env.example .env && edit it');
  const content = readFileSync('.env', 'utf-8');
  if (!content.includes('OWNER_NUMBER=') || content.includes('OWNER_NUMBER=5491123456789')) {
    return 'OWNER_NUMBER looks like the example. Set your real number.';
  }
  return null;
});

// OWNER_NUMBER format
check('OWNER_NUMBER format', () => {
  if (!existsSync('.env')) throw new Error('No .env file');
  const content = readFileSync('.env', 'utf-8');
  const match = content.match(/OWNER_NUMBER=(\S+)/);
  if (!match) throw new Error('OWNER_NUMBER not set');
  const num = match[1];
  if (num.startsWith('+')) return 'Remove the + prefix (use 5491100000000 format)';
  if (num.length < 10) return `Number "${num}" seems too short. Use full international format.`;
  return null;
});

// PLANNER_MODEL
check('PLANNER_MODEL valid', () => {
  if (!existsSync('.env')) return null; // checked above
  const content = readFileSync('.env', 'utf-8');
  const match = content.match(/PLANNER_MODEL=(\S+)/);
  if (!match) return 'Not set (default: sonnet)';
  if (!['sonnet', 'opus', 'haiku'].includes(match[1])) {
    return `Invalid model "${match[1]}". Use: sonnet, opus, or haiku`;
  }
  return null;
});

// sql.js
check('sql.js module', () => {
  if (existsSync('node_modules/sql.js')) return null;
  throw new Error('Not installed. Run: npm install');
});

// Baileys
check('Baileys module', () => {
  if (existsSync('node_modules/@whiskeysockets/baileys')) return null;
  throw new Error('Not installed. Run: npm install');
});

// TypeScript build
check('TypeScript build', () => {
  if (existsSync('dist/main.js')) return null;
  return 'Not built yet. Run: npm run build';
});

// Auth store
check('WhatsApp auth store', () => {
  if (existsSync('auth_store/creds.json')) return null;
  return 'No session yet. Will create on first start (QR scan).';
});

// SOUL.md
check('SOUL.md personality', () => {
  if (!existsSync('SOUL.md')) return 'Missing. Will use default personality.';
  const content = readFileSync('SOUL.md', 'utf-8');
  if (content.length < 50) return 'SOUL.md seems too short. Add some personality!';
  return null;
});

// Disk space
check('Disk space', () => {
  try {
    const df = execSync('df -h . 2>/dev/null', { timeout: 5000 }).toString();
    const lines = df.trim().split('\n');
    if (lines.length >= 2) {
      const parts = lines[1].split(/\s+/);
      const usePercent = parseInt(parts[4] ?? '0');
      if (usePercent > 90) return `Disk ${usePercent}% full — SQLite needs space`;
    }
    return null;
  } catch {
    return null; // Can't check, probably fine
  }
});

// Local LLM (if configured)
check('Local LLM (if enabled)', () => {
  if (!existsSync('.env')) return null;
  const content = readFileSync('.env', 'utf-8');
  if (!content.includes('USE_LOCAL_QUARANTINE=true')) return null; // Not enabled
  const match = content.match(/LOCAL_LLM_ENDPOINT=(\S+)/);
  const endpoint = match?.[1] ?? 'http://localhost:11434';
  try {
    execSync(`curl -s --max-time 3 ${endpoint}/v1/models 2>&1`, { timeout: 5000 });
    return null;
  } catch {
    return `Cannot reach local LLM at ${endpoint}. Is ollama running?`;
  }
});

// Summary
console.log(`\n${'─'.repeat(40)}`);
console.log(`  ✅ ${ok} OK  ⚠️  ${warn} warnings  ❌ ${fail} failed`);

if (fail > 0) {
  console.log('\n  Fix the ❌ issues above before starting.\n');
  process.exit(1);
} else if (warn > 0) {
  console.log('\n  Warnings are non-blocking. Start with: npm start\n');
} else {
  console.log('\n  All good! Start with: npm start\n');
}
