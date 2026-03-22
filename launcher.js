#!/usr/bin/env node
/**
 * NetRecon Native Messaging Host
 * ─────────────────────────────────────────────────────────────────────────────
 * Registered with Chrome via install.js. Receives a message from the extension
 * and starts companion-server.js as a detached background process.
 *
 * Do not run this directly — it speaks the Chrome Native Messaging protocol
 * (4-byte LE length-prefixed JSON on stdin/stdout).
 */

'use strict';

const path  = require('path');
const http  = require('http');
const os    = require('os');
const fs    = require('fs');
const { spawn } = require('child_process');

const LOG_FILE = path.join(os.tmpdir(), 'netrecon-server.log');

// ── Native Messaging protocol helpers ────────────────────────────────────────

function readMessage() {
  return new Promise((resolve) => {
    let needed = null;
    process.stdin.on('readable', function read() {
      if (needed === null) {
        const header = process.stdin.read(4);
        if (!header) return;
        needed = header.readUInt32LE(0);
      }
      const body = process.stdin.read(needed);
      if (!body) return;
      process.stdin.removeListener('readable', read);
      try { resolve(JSON.parse(body.toString('utf8'))); }
      catch { resolve(null); }
    });
  });
}

function sendMessage(obj) {
  const json   = Buffer.from(JSON.stringify(obj), 'utf8');
  const header = Buffer.alloc(4);
  header.writeUInt32LE(json.length, 0);
  process.stdout.write(Buffer.concat([header, json]));
}

function checkAlive() {
  return new Promise((resolve) => {
    const req = http.get('http://127.0.0.1:31337/health', (res) => {
      res.resume();
      resolve(res.statusCode === 200);
    });
    req.on('error', () => resolve(false));
    req.setTimeout(800, () => { req.destroy(); resolve(false); });
  });
}

function delay(ms) { return new Promise(r => setTimeout(r, ms)); }

// ── Main ──────────────────────────────────────────────────────────────────────

// ── Force-kill whatever is on port 31337 ─────────────────────────────────────

function killPort() {
  return new Promise((resolve) => {
    const { exec } = require('child_process');
    const cmd = process.platform === 'win32'
      ? `for /f "tokens=5" %a in ('netstat -aon ^| findstr ":31337 "') do @taskkill /f /pid %a`
      : `lsof -ti tcp:31337 | xargs kill -9 2>/dev/null; true`;
    exec(cmd, () => resolve());
  });
}

async function main() {
  const msg = await readMessage();

  if (!msg || (msg.action !== 'start' && msg.action !== 'stop')) {
    sendMessage({ ok: false, error: 'Unknown action' });
    process.exit(0);
  }

  // ── Stop action ────────────────────────────────────────────────────────────
  if (msg.action === 'stop') {
    await killPort();
    await delay(400);
    const stillAlive = await checkAlive();
    sendMessage({ ok: !stillAlive, alive: stillAlive });
    process.exit(0);
  }

  // If server is already running, report success immediately
  if (await checkAlive()) {
    sendMessage({ ok: true, already: true });
    process.exit(0);
  }

  const serverScript = path.join(__dirname, 'companion-server.js');
  if (!fs.existsSync(serverScript)) {
    sendMessage({ ok: false, error: 'companion-server.js not found' });
    process.exit(0);
  }

  // Redirect server stdout/stderr to a log file for debugging
  const logFd = fs.openSync(LOG_FILE, 'w');

  let spawnError = null;
  const child = spawn(process.execPath, [serverScript], {
    cwd:         __dirname,
    detached:    true,
    stdio:       ['ignore', logFd, logFd],
    windowsHide: true,
  });

  child.on('error', (err) => { spawnError = err.message; });
  child.unref();
  fs.closeSync(logFd);

  // Give it up to 4 seconds to bind and respond
  for (let i = 0; i < 8; i++) {
    await delay(500);
    if (spawnError) break;
    if (await checkAlive()) {
      sendMessage({ ok: true, pid: child.pid, log: LOG_FILE });
      process.exit(0);
    }
  }

  // Server didn't come up — read the last few lines of the log for a hint
  let logTail = '';
  try {
    const lines = fs.readFileSync(LOG_FILE, 'utf8').trim().split('\n');
    logTail = lines.slice(-3).join(' | ');
  } catch { /* no log */ }

  sendMessage({
    ok:    false,
    error: spawnError || 'Server did not respond within 4 s',
    log:   LOG_FILE,
    hint:  logTail || undefined,
  });
  process.exit(0);
}

main().catch((err) => {
  sendMessage({ ok: false, error: err.message });
  process.exit(0);
});
