// popup.js — module router and app bootstrap
import { AgentClient }    from './lib/agent-client.js';
import { HistoryManager } from './lib/history-manager.js';
import { NmapScanner }    from './modules/nmap-scanner.js';
import { DnsRecon }       from './modules/dns-recon.js';
import { WhoisLookup }    from './modules/whois-lookup.js';
import { SslInspector }   from './modules/ssl-inspector.js';
import { PortScanner }    from './modules/port-scanner.js';
import { HttpHeaders }    from './modules/http-headers.js';
import { SubdomainEnum }  from './modules/subdomain-enum.js';
import { IpGeo }          from './modules/ip-geo.js';
import { CveLookup }      from './modules/cve-lookup.js';
import { ReverseIp }      from './modules/reverse-ip.js';
import { HistoryTab }     from './modules/history-tab.js';

const agent   = new AgentClient();
const history = new HistoryManager();

const MODULES = {
  nmap:       NmapScanner,
  dns:        DnsRecon,
  whois:      WhoisLookup,
  ssl:        SslInspector,
  ports:      PortScanner,
  headers:    HttpHeaders,
  subdomains: SubdomainEnum,
  geo:        IpGeo,
  cve:        CveLookup,
  reverseip:  ReverseIp,
  history:    HistoryTab,
};

let activeModule = null;
let pollTimer    = null;

// ── Nav ───────────────────────────────────────────────────────────────────────

document.querySelectorAll('.nav-item[data-module]').forEach(btn => {
  btn.addEventListener('click', () => loadModule(btn.dataset.module));
});

function loadModule(id) {
  if (!MODULES[id]) return;

  // Teardown previous
  if (activeModule?.destroy) activeModule.destroy();

  // Update nav state
  document.querySelectorAll('.nav-item').forEach(b =>
    b.classList.toggle('active', b.dataset.module === id)
  );

  // Mount new module
  const content = document.getElementById('content');
  content.innerHTML = '';
  activeModule = new MODULES[id]({ container: content, agent, history });
  activeModule.render();

  // Persist last active tab
  chrome.storage.local.set({ lastTab: id });
}

// ── Agent status polling ──────────────────────────────────────────────────────

async function pollAgent() {
  const el = document.getElementById('agent-status');
  el.className = 'agent-status checking';
  el.innerHTML = '<span class="status-dot"></span> Checking…';

  const online = await agent.isConnected();

  el.className = `agent-status ${online ? 'connected' : 'disconnected'}`;
  if (online) {
    el.innerHTML = '<span class="status-dot"></span> Agent Online &nbsp;<button id="stop-agent-btn" class="stop-agent-btn" title="Stop companion server">■ Stop</button>';
    document.getElementById('stop-agent-btn')?.addEventListener('click', stopAgent);
  } else {
    el.innerHTML = '<span class="status-dot"></span> Agent Offline &nbsp;<button id="start-agent-btn" class="start-agent-btn" title="Launch companion server">▶ Start</button>';
    document.getElementById('start-agent-btn')?.addEventListener('click', launchAgent);
  }
}

// ── Native Messaging launcher ─────────────────────────────────────────────────

async function launchAgent() {
  const el  = document.getElementById('agent-status');
  const btn = document.getElementById('start-agent-btn');
  if (btn) { btn.disabled = true; btn.textContent = 'Starting…'; }

  // Pause the background poll so it doesn't overwrite our status messages
  clearInterval(pollTimer);

  let reply = null;
  let chromeError = null;
  try {
    reply = await new Promise((resolve) => {
      const port  = chrome.runtime.connectNative('net.brutal.netrecon');
      const timer = setTimeout(() => { port.disconnect(); resolve(null); }, 8000);
      port.onMessage.addListener((msg) => {
        clearTimeout(timer);
        port.disconnect();
        resolve(msg);
      });
      port.onDisconnect.addListener(() => {
        clearTimeout(timer);
        chromeError = chrome.runtime.lastError?.message || null;
        resolve(null);
      });
      port.postMessage({ action: 'start' });
    });
  } catch (e) { chromeError = e.message; reply = null; }

  // Chrome couldn't reach the native host — show the exact reason
  if (reply === null) {
    const reason = chromeError || 'host not found';
    el.className = 'agent-status disconnected';
    el.innerHTML = `<span class="status-dot"></span> <span title="${reason}">Launch failed</span> — see console for details`;
    console.error('[NetRecon] Native messaging error:', reason);
    console.info('[NetRecon] Fix: re-download the zip, reload the extension, then re-run: node install.js <ext-id>');
    pollTimer = setInterval(pollAgent, 6000);
    return;
  }

  // Launcher reported the server didn't start
  if (!reply.ok) {
    const hint = reply.hint ? ` — ${reply.hint}` : '';
    el.className = 'agent-status disconnected';
    el.innerHTML = `<span class="status-dot"></span> Start failed: ${reply.error || 'unknown error'}${hint}`;
    pollTimer = setInterval(pollAgent, 6000);
    return;
  }

  // Launcher confirmed the server is up (already running or just started)
  pollAgent();
  pollTimer = setInterval(pollAgent, 6000);
}

// ── Stop agent ────────────────────────────────────────────────────────────────

async function stopAgent() {
  const el  = document.getElementById('agent-status');
  const btn = document.getElementById('stop-agent-btn');
  if (btn) { btn.disabled = true; btn.textContent = 'Stopping…'; }

  clearInterval(pollTimer);

  // 1. Try graceful HTTP shutdown (only works on v1.0.2+)
  try {
    await fetch('http://127.0.0.1:31337/shutdown', { method: 'POST', signal: AbortSignal.timeout(2000) });
  } catch { /* connection closed before response — expected */ }

  await new Promise(r => setTimeout(r, 800));

  // 2. If still online, force-kill via native messaging (works against any version)
  if (await agent.isConnected()) {
    await new Promise((resolve) => {
      try {
        const port  = chrome.runtime.connectNative('net.brutal.netrecon');
        const timer = setTimeout(() => { port.disconnect(); resolve(); }, 5000);
        port.onMessage.addListener(() => { clearTimeout(timer); port.disconnect(); resolve(); });
        port.onDisconnect.addListener(() => { clearTimeout(timer); resolve(); });
        port.postMessage({ action: 'stop' });
      } catch { resolve(); }
    });
    await new Promise(r => setTimeout(r, 800));
  }

  await pollAgent();
  pollTimer = setInterval(pollAgent, 6000);
}

// ── Auth banner ───────────────────────────────────────────────────────────────

async function initAuthBanner() {
  const data = await chrome.storage.local.get('authDismissed');
  if (data.authDismissed) {
    document.getElementById('auth-banner').classList.add('hidden');
  }
  document.getElementById('auth-dismiss').addEventListener('click', () => {
    document.getElementById('auth-banner').classList.add('hidden');
    document.querySelector('.app-body').style.height = 'calc(700px - 42px)';
    chrome.storage.local.set({ authDismissed: true });
  });
}

// ── Boot ──────────────────────────────────────────────────────────────────────

(async () => {
  await initAuthBanner();
  pollAgent();
  pollTimer = setInterval(pollAgent, 6000);

  // Restore last active tab
  const { lastTab } = await chrome.storage.local.get('lastTab');
  loadModule(lastTab || 'nmap');
})();
