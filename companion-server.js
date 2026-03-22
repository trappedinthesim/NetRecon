/**
 * NetRecon Companion Agent
 * ────────────────────────────────────────────────────────────────────────────
 * Runs on http://127.0.0.1:31337
 * Handles all OS-level operations (nmap, whois, DNS, SSL, subdomains).
 * Only accepts connections from chrome-extension:// origins.
 *
 * ⚠  YOU ARE RESPONSIBLE for ensuring you have written authorisation
 *    before scanning any system you do not own.
 *
 * Requires: Node.js >= 18, nmap installed and in PATH
 * Install:  npm install
 * Run:      node companion-server.js
 */

'use strict';

// Augment PATH for shells that don't inherit the user's full environment
// (Chrome native messaging passes a minimal PATH)
if (process.platform === 'darwin') {
  process.env.PATH = `/opt/homebrew/bin:/usr/local/bin:${process.env.PATH || '/usr/bin:/bin:/usr/sbin:/sbin'}`;
} else if (process.platform === 'linux') {
  process.env.PATH = `/usr/local/bin:${process.env.PATH || '/usr/bin:/bin:/usr/sbin:/sbin'}`;
}

const express  = require('express');
const { WebSocketServer } = require('ws');
const http     = require('http');
const dns      = require('dns').promises;
const tls      = require('tls');
const { spawn } = require('child_process');
const fs       = require('fs');
const whois    = require('whois');
const util     = require('util');

const whoisLookup = util.promisify(whois.lookup);

// ── Nmap binary resolution ────────────────────────────────────────────────────
// Locate nmap by checking known install paths directly — more reliable than
// relying on PATH inheritance from Chrome's minimal environment.

const NMAP_CANDIDATES = [
  '/opt/homebrew/bin/nmap',   // macOS Apple Silicon (Homebrew)
  '/usr/local/bin/nmap',      // macOS Intel (Homebrew) / Linux
  '/usr/bin/nmap',            // Linux (apt/yum/pacman)
  '/snap/bin/nmap',           // Linux (snap)
  'C:\\Program Files (x86)\\Nmap\\nmap.exe', // Windows
  'C:\\Program Files\\Nmap\\nmap.exe',
];

let NMAP_BIN = null;

function resolveNmap() {
  for (const p of NMAP_CANDIDATES) {
    try { if (fs.existsSync(p)) { NMAP_BIN = p; return; } } catch {}
  }
  // Fall back to bare name and hope PATH has it
  NMAP_BIN = 'nmap';
}

const PORT          = 31337;
const AGENT_VERSION = '1.0.3';

// ── Input validation ─────────────────────────────────────────────────────────

// Allows hostnames, IPv4 (with optional CIDR), IPv6
const RE_HOSTNAME = /^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$/;
const RE_IPV4     = /^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$/;
const RE_IPV6     = /^[0-9a-fA-F:]+$/;

function isValidTarget(t) {
  if (!t || typeof t !== 'string' || t.length > 255) return false;
  const clean = t.trim().replace(/:\d+$/, ''); // strip port suffix
  return RE_HOSTNAME.test(clean) || RE_IPV4.test(clean) || RE_IPV6.test(clean);
}

function isValidPort(p) {
  const n = parseInt(p, 10);
  return Number.isInteger(n) && n > 0 && n <= 65535;
}

// ── Express app ──────────────────────────────────────────────────────────────

const app = express();
app.use(express.json({ limit: '512kb' }));

// CORS: only accept requests from Chrome extension pages
app.use((req, res, next) => {
  const origin = req.headers.origin || '';
  if (origin && !origin.startsWith('chrome-extension://')) {
    return res.status(403).json({ error: 'Forbidden' });
  }
  if (origin) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    res.setHeader('Vary', 'Origin');
  }
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

// ── Health ───────────────────────────────────────────────────────────────────

app.get('/health', (req, res) => {
  res.json({ ok: true, version: AGENT_VERSION, timestamp: Date.now(), nmap: NMAP_BIN });
});

// ── Shutdown ─────────────────────────────────────────────────────────────────

app.post('/shutdown', (req, res) => {
  res.json({ ok: true });
  setTimeout(() => process.exit(0), 150); // let response flush, then exit
});

// ── DNS Recon ────────────────────────────────────────────────────────────────

app.post('/dns', async (req, res) => {
  const { target } = req.body;
  if (!isValidTarget(target)) return res.status(400).json({ error: 'Invalid target' });

  const results = {};
  const lookups = [
    ['A',     () => dns.resolve4(target)],
    ['AAAA',  () => dns.resolve6(target)],
    ['MX',    () => dns.resolveMx(target)],
    ['TXT',   () => dns.resolveTxt(target)],
    ['NS',    () => dns.resolveNs(target)],
    ['CNAME', () => dns.resolveCname(target)],
    ['SOA',   () => dns.resolveSoa(target)],
  ];

  await Promise.allSettled(lookups.map(async ([type, fn]) => {
    try { results[type] = await fn(); }
    catch (e) { results[type] = { error: e.code || e.message }; }
  }));

  // Zone transfer attempt — expected to fail on most domains
  try {
    const { stdout } = await execSafe('dig', ['axfr', target], 8000);
    results.AXFR = stdout.trim() || 'No data returned';
  } catch {
    results.AXFR = 'AXFR refused — expected for most public domains';
  }

  res.json(results);
});

// ── WHOIS ────────────────────────────────────────────────────────────────────

app.post('/whois', async (req, res) => {
  const { target } = req.body;
  if (!isValidTarget(target)) return res.status(400).json({ error: 'Invalid target' });
  try {
    const raw = await whoisLookup(target);
    res.json({ raw, parsed: parseWhoisData(raw) });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

function parseWhoisData(raw) {
  const extract = (...patterns) => {
    for (const p of patterns) {
      const m = raw.match(p);
      if (m) return m[1].trim();
    }
    return null;
  };
  return {
    registrar:   extract(/registrar:\s*(.+)/i,            /registrar name:\s*(.+)/i),
    created:     extract(/creation date:\s*(.+)/i,        /registered:\s*(.+)/i),
    expires:     extract(/expir(?:y|ation|es) date:\s*(.+)/i, /registry expiry date:\s*(.+)/i),
    updated:     extract(/updated date:\s*(.+)/i,         /last updated:\s*(.+)/i),
    status:      extract(/domain status:\s*(.+)/i),
    nameservers: [...raw.matchAll(/name server:\s*(.+)/gi)].map(m => m[1].trim()),
    abuse:       extract(/abuse(?:-contact|-email)?:\s*(.+)/i),
    registrant:  extract(/registrant(?:\s+name|\s+org(?:anization)?)?:\s*(.+)/i),
    country:     extract(/registrant country:\s*(.+)/i,   /country:\s*(.+)/i),
  };
}

// ── SSL / TLS Inspector ──────────────────────────────────────────────────────

app.post('/ssl', async (req, res) => {
  const { target } = req.body;
  const host = target?.replace(/:\d+$/, '');
  const port = parseInt(target?.match(/:(\d+)$/)?.[1] || '443', 10);
  if (!isValidTarget(host) || !isValidPort(port)) {
    return res.status(400).json({ error: 'Invalid target. Use host or host:port' });
  }
  try {
    res.json(await inspectSSL(host, port));
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

function inspectSSL(host, port = 443) {
  return new Promise((resolve, reject) => {
    const socket = tls.connect(
      { host, port, rejectUnauthorized: false, servername: host, timeout: 8000 },
      () => {
        const cert   = socket.getPeerCertificate(true);
        const proto  = socket.getProtocol();
        const cipher = socket.getCipher();
        socket.end();

        if (!cert || !cert.subject) {
          return reject(new Error('No certificate returned'));
        }

        const now      = Date.now();
        const expiry   = cert.valid_to ? new Date(cert.valid_to).getTime() : null;
        const daysLeft = expiry ? Math.floor((expiry - now) / 86400000) : null;

        const vulns = [];
        if (proto === 'SSLv3')                     vulns.push({ id: 'POODLE',     severity: 'critical', detail: 'SSLv3 is enabled — vulnerable to POODLE' });
        if (proto === 'TLSv1' || proto === 'TLSv1.1') vulns.push({ id: 'OLD_TLS',   severity: 'high',     detail: `${proto} is deprecated — upgrade to TLS 1.2+` });
        if (daysLeft !== null && daysLeft < 0)     vulns.push({ id: 'EXPIRED',    severity: 'critical', detail: 'Certificate is EXPIRED' });
        else if (daysLeft !== null && daysLeft < 14) vulns.push({ id: 'EXPIRING',  severity: 'high',     detail: `Certificate expires in ${daysLeft} days` });
        else if (daysLeft !== null && daysLeft < 30) vulns.push({ id: 'EXPIRING',  severity: 'medium',   detail: `Certificate expires in ${daysLeft} days` });
        if (cert.subject?.CN === cert.issuer?.CN)  vulns.push({ id: 'SELF_SIGNED', severity: 'medium',  detail: 'Certificate appears to be self-signed' });

        const san = cert.subjectaltname
          ? cert.subjectaltname.split(', ').map(s => s.replace(/^DNS:/, ''))
          : [];

        resolve({
          subject:      cert.subject,
          issuer:       cert.issuer,
          validFrom:    cert.valid_from,
          validTo:      cert.valid_to,
          daysLeft,
          serialNumber: cert.serialNumber,
          fingerprint:  cert.fingerprint,
          fingerprint256: cert.fingerprint256,
          san,
          protocol:     proto,
          cipher,
          chain:        buildCertChain(cert),
          vulnerabilities: vulns,
        });
      }
    );
    socket.on('error', reject);
    socket.on('timeout', () => { socket.destroy(); reject(new Error('Connection timed out')); });
  });
}

function buildCertChain(cert) {
  const chain = [];
  let cur = cert;
  const seen = new Set();
  while (cur && !seen.has(cur.fingerprint)) {
    seen.add(cur.fingerprint);
    chain.push({
      subject: cur.subject?.CN || JSON.stringify(cur.subject),
      issuer:  cur.issuer?.CN  || JSON.stringify(cur.issuer),
      validTo: cur.valid_to,
    });
    cur = (cur.issuerCertificate && cur.issuerCertificate !== cur)
      ? cur.issuerCertificate
      : null;
  }
  return chain;
}

// ── HTTP Headers ─────────────────────────────────────────────────────────────

app.post('/headers', async (req, res) => {
  const { target } = req.body;
  const url = target?.startsWith('http') ? target : `https://${target}`;
  try { new URL(url); } catch { return res.status(400).json({ error: 'Invalid URL' }); }
  try {
    res.json(await fetchHeaders(url));
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

const SECURITY_HEADER_CHECKS = [
  { name: 'strict-transport-security',     label: 'HSTS',                   risk: 'high',   desc: 'Enforces HTTPS; missing allows SSL stripping attacks' },
  { name: 'content-security-policy',       label: 'CSP',                    risk: 'high',   desc: 'Prevents XSS, injection, and data exfiltration' },
  { name: 'x-frame-options',               label: 'X-Frame-Options',        risk: 'medium', desc: 'Prevents clickjacking via iframes' },
  { name: 'x-content-type-options',        label: 'X-Content-Type-Options', risk: 'medium', desc: 'Prevents MIME-type sniffing' },
  { name: 'referrer-policy',               label: 'Referrer-Policy',        risk: 'low',    desc: 'Controls what referrer info is sent' },
  { name: 'permissions-policy',            label: 'Permissions-Policy',     risk: 'low',    desc: 'Controls access to browser APIs' },
  { name: 'cross-origin-opener-policy',    label: 'COOP',                   risk: 'medium', desc: 'Isolates browsing context from cross-origin windows' },
  { name: 'cross-origin-resource-policy',  label: 'CORP',                   risk: 'low',    desc: 'Prevents cross-origin reads of resources' },
];

function fetchHeaders(url) {
  return new Promise((resolve, reject) => {
    const mod = url.startsWith('https') ? require('https') : require('http');
    const req = mod.request(url, { method: 'HEAD', timeout: 10000 }, (res2) => {
      res2.resume(); // drain
      const headers = res2.headers;
      resolve({
        statusCode:    res2.statusCode,
        statusMessage: res2.statusMessage,
        headers,
        security:      SECURITY_HEADER_CHECKS.map(c => ({
          ...c,
          present: c.name in headers,
          value:   headers[c.name] ?? null,
        })),
        server:        headers['server'] ?? null,
        poweredBy:     headers['x-powered-by'] ?? null,
      });
    });
    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error('Request timed out')); });
    req.end();
  });
}

// ── Subdomain Enumeration ────────────────────────────────────────────────────

app.post('/subdomains', async (req, res) => {
  const { target, wordlist = [] } = req.body;
  if (!isValidTarget(target)) return res.status(400).json({ error: 'Invalid target' });

  const found = new Set();

  // Passive: Certificate Transparency via crt.sh
  try {
    const r = await fetch(`https://crt.sh/?q=%.${encodeURIComponent(target)}&output=json`, {
      signal: AbortSignal.timeout(10000),
      headers: { 'User-Agent': 'NetRecon/1.0' },
    });
    const data = await r.json();
    for (const entry of data) {
      for (const name of (entry.name_value || '').split('\n')) {
        const clean = name.trim().replace(/^\*\./, '').toLowerCase();
        if (clean.endsWith(`.${target}`) || clean === target) {
          if (isValidTarget(clean)) found.add(clean);
        }
      }
    }
  } catch { /* crt.sh unreachable or no results */ }

  // Active: DNS resolution from provided wordlist (capped at 500 entries)
  const active = [];
  const wordlistCapped = (Array.isArray(wordlist) ? wordlist : [])
    .filter(w => /^[a-z0-9\-]+$/i.test(w))
    .slice(0, 500);

  await Promise.allSettled(wordlistCapped.map(async (word) => {
    const fqdn = `${word}.${target}`;
    try {
      const ips = await dns.resolve4(fqdn);
      found.add(fqdn);
      active.push({ subdomain: fqdn, ips, status: 'live' });
    } catch { /* not resolvable */ }
  }));

  res.json({ subdomains: [...found].sort(), activeResolved: active });
});

// ── CVE Lookup (NVD API) ─────────────────────────────────────────────────────

app.get('/cve', async (req, res) => {
  const { query } = req.query;
  if (!query || typeof query !== 'string' || query.length > 200) {
    return res.status(400).json({ error: 'Invalid query' });
  }
  try {
    const isCveId = /^CVE-\d{4}-\d+$/i.test(query.trim());
    const url = isCveId
      ? `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${encodeURIComponent(query.trim())}`
      : `https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=${encodeURIComponent(query)}&resultsPerPage=20`;
    const r = await fetch(url, {
      headers: { 'User-Agent': 'NetRecon/1.0' },
      signal: AbortSignal.timeout(15000),
    });
    res.json(await r.json());
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ── IP Geolocation & ASN ─────────────────────────────────────────────────────

app.get('/geo', async (req, res) => {
  const { target } = req.query;
  if (!isValidTarget(target)) return res.status(400).json({ error: 'Invalid target' });
  try {
    const r = await fetch(`https://ipapi.co/${encodeURIComponent(target)}/json/`, {
      headers: { 'User-Agent': 'NetRecon/1.0' },
      signal: AbortSignal.timeout(10000),
    });
    const data = await r.json();
    if (data.error) return res.status(400).json({ error: data.reason || data.error });
    res.json(data);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ── Reverse IP Lookup ────────────────────────────────────────────────────────

app.get('/reverseip', async (req, res) => {
  const { target } = req.query;
  if (!isValidTarget(target)) return res.status(400).json({ error: 'Invalid target' });
  try {
    const r = await fetch(
      `https://api.hackertarget.com/reverseiplookup/?q=${encodeURIComponent(target)}`,
      { headers: { 'User-Agent': 'NetRecon/1.0' }, signal: AbortSignal.timeout(10000) }
    );
    const text = await r.text();
    if (text.startsWith('error') || text.startsWith('API')) {
      return res.status(400).json({ error: text.trim() });
    }
    res.json({ ip: target, domains: text.split('\n').map(d => d.trim()).filter(Boolean) });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ── Helpers ──────────────────────────────────────────────────────────────────

function execSafe(cmd, args, timeout = 10000) {
  return new Promise((resolve, reject) => {
    const proc = spawn(cmd, args);
    let stdout = '', stderr = '';
    const timer = setTimeout(() => { proc.kill(); reject(new Error('Timeout')); }, timeout);
    proc.stdout.on('data', d => { stdout += d; });
    proc.stderr.on('data', d => { stderr += d; });
    proc.on('close', code => {
      clearTimeout(timer);
      code === 0 ? resolve({ stdout, stderr }) : reject(new Error(stderr || `Exited ${code}`));
    });
    proc.on('error', e => { clearTimeout(timer); reject(e); });
  });
}

// ── HTTP Server ──────────────────────────────────────────────────────────────

const server = http.createServer(app);

// ── WebSocket — Nmap + Port Scanner streaming ────────────────────────────────

const wss = new WebSocketServer({ server, path: '/ws' });

const COMMON_PORTS = [
  21, 22, 23, 25, 53, 80, 110, 143, 389, 443, 445, 465, 587, 636,
  993, 995, 1433, 1521, 2049, 2375, 3306, 3389, 5432, 5900, 6379,
  8080, 8443, 8888, 9200, 9300, 27017, 50000,
];

const NMAP_PROFILES = {
  quick:  ['-T4', '-F', '--open'],
  full:   ['-T4', '-A', '-p-', '--open'],
  syn:    ['-sS', '-T2', '-p-', '--open'],     // SYN scan — requires root/sudo
  vuln:   ['-sV', '--script=vuln', '-T4'],
  udp:    ['-sU', '-T4', '--top-ports', '100'],
};

wss.on('connection', (ws, req) => {
  // Bind to loopback only — belt-and-suspenders check
  const addr = req.socket.remoteAddress;
  if (!['127.0.0.1', '::1', '::ffff:127.0.0.1'].includes(addr)) {
    ws.close(4003, 'Forbidden');
    return;
  }

  let activeProc = null;

  function send(obj) {
    if (ws.readyState === ws.OPEN) ws.send(JSON.stringify(obj));
  }

  function killActive() {
    if (activeProc) {
      try { activeProc.kill('SIGTERM'); } catch {}
      activeProc = null;
    }
  }

  ws.on('close', killActive);

  ws.on('message', (raw) => {
    let msg;
    try { msg = JSON.parse(raw.toString()); }
    catch { send({ type: 'error', message: 'Invalid JSON' }); return; }

    switch (msg.type) {
      case 'nmap':     handleNmap(msg);     break;
      case 'portscan': handlePortscan(msg); break;
      case 'cancel':   handleCancel();      break;
      default: send({ type: 'error', message: `Unknown type: ${msg.type}` });
    }
  });

  function handleNmap({ target, scanType }) {
    if (!isValidTarget(target)) {
      send({ type: 'error', message: 'Invalid target — only hostnames and IP addresses accepted' });
      return;
    }
    killActive();

    const profile = NMAP_PROFILES[scanType] || NMAP_PROFILES.quick;
    const args = [...profile, target];

    // SYN scan warning
    if (scanType === 'syn') {
      send({ type: 'warn', message: 'SYN scan requires root/sudo — agent must run with elevated privileges' });
    }

    send({ type: 'start', command: `nmap ${args.join(' ')}` });

    activeProc = spawn(NMAP_BIN, args);

    let errorSent = false;
    activeProc.stdout.on('data', d => send({ type: 'output', data: d.toString() }));
    activeProc.stderr.on('data', d => send({ type: 'stderr', data: d.toString() }));
    activeProc.on('close', code => { if (!errorSent) send({ type: 'done', code }); activeProc = null; });
    activeProc.on('error', e => {
      errorSent = true;
      const msg = e.code === 'ENOENT'
        ? `nmap not found — checked ${NMAP_BIN}. Install nmap via Homebrew (brew install nmap) or from nmap.org`
        : e.message;
      send({ type: 'error', message: msg });
      activeProc = null;
    });
  }

  function handlePortscan({ target, ports }) {
    if (!isValidTarget(target)) {
      send({ type: 'error', message: 'Invalid target' });
      return;
    }
    killActive();

    const portList = (Array.isArray(ports) && ports.length ? ports : COMMON_PORTS)
      .map(p => parseInt(p, 10))
      .filter(isValidPort)
      .slice(0, 1000); // hard cap

    const args = ['-T4', '--open', '-p', portList.join(','), '--reason', target];

    send({ type: 'start', command: `nmap ${args.join(' ')}`, total: portList.length });

    activeProc = spawn(NMAP_BIN, args);
    let portErrorSent = false;
    activeProc.stdout.on('data', d => send({ type: 'output', data: d.toString() }));
    activeProc.stderr.on('data', d => send({ type: 'stderr', data: d.toString() }));
    activeProc.on('close', code => { if (!portErrorSent) send({ type: 'done', code }); activeProc = null; });
    activeProc.on('error', e => {
      portErrorSent = true;
      const msg = e.code === 'ENOENT'
        ? `nmap not found — checked ${NMAP_BIN}. Install nmap via Homebrew (brew install nmap) or from nmap.org`
        : e.message;
      send({ type: 'error', message: msg });
      activeProc = null;
    });
  }

  function handleCancel() {
    killActive();
    send({ type: 'cancelled' });
  }
});

// ── Banner ───────────────────────────────────────────────────────────────────

async function printBanner() {
  const G  = '\x1b[32m';   // green
  const BG = '\x1b[92m';   // bright green
  const DG = '\x1b[90m';   // dark gray
  const W  = '\x1b[97m';   // white
  const AM = '\x1b[33m';   // amber
  const R  = '\x1b[0m';    // reset
  const BD = '\x1b[1m';    // bold
  const delay = ms => new Promise(res => setTimeout(res, ms));

  const logo = [
    '',
    `${G}${BD}    ██╗ ██╗  ${R}${W}${BD}N E T R E C O N${R}`,
    `${G}${BD}   ██╔╝██╔╝  ${R}${DG}Security Reconnaissance Toolkit${R}`,
    `${G}${BD}  ██╔╝██╔╝   ${R}${DG}Companion Agent  ${R}${BG}v${AGENT_VERSION}${R}`,
    `${G}${BD} ██╔╝██╔╝${R}`,
    `${G}${BD} ╚═╝ ╚═╝${R}`,
    '',
  ];

  for (const line of logo) {
    console.log(line);
    await delay(50);
  }

  console.log(`${DG}  ──────────────────────────────────────────────────${R}`);
  console.log(`  ${DG}HTTP ${R}  ${G}▸${R}  ${W}http://127.0.0.1:${PORT}${R}`);
  console.log(`  ${DG}WS   ${R}  ${G}▸${R}  ${W}ws://127.0.0.1:${PORT}/ws${R}`);

  // Animated connecting → ONLINE
  process.stdout.write(`  ${DG}STAT ${R}  ${G}▸${R}  ${DG}connecting`);
  for (let i = 0; i < 3; i++) { await delay(150); process.stdout.write('.'); }
  await delay(220);
  process.stdout.write(`\r  ${DG}STAT ${R}  ${G}▸${R}  ${BG}● ONLINE${R}                          \n`);

  console.log(`${DG}  ──────────────────────────────────────────────────${R}`);
  console.log('');
  console.log(`${AM}  ⚠  Only scan systems you own or are authorized to test.${R}`);
  console.log('');
}

// ── Start ────────────────────────────────────────────────────────────────────

resolveNmap();
server.listen(PORT, '127.0.0.1', () => { printBanner(); });

process.on('SIGTERM', () => { server.close(); process.exit(0); });
process.on('SIGINT',  () => { server.close(); process.exit(0); });
