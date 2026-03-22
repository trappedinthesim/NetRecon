/**
 * modules/nmap-scanner.js — Reference module pattern
 * ─────────────────────────────────────────────────────────────────────────────
 * Every module exports a class with:
 *   constructor({ container, agent, history })
 *   render()           — builds DOM inside container
 *   destroy()          — cleans up (close WS, cancel timers)
 *
 * Companion server required: YES (WebSocket /ws, message type 'nmap')
 */

export class NmapScanner {
  constructor({ container, agent, history }) {
    this.container = container;
    this.agent     = agent;
    this.history   = history;
    this.ws        = null;
    this.rawOutput = '';
    this.startTime = null;
    this.scanning  = false;
  }

  // ── Render ──────────────────────────────────────────────────────────────────

  render() {
    this.container.innerHTML = `
      <div class="module-header">
        <div class="module-title">
          ⬡ Nmap Scanner
          <span class="agent-badge">⚡ Requires Agent</span>
        </div>
      </div>

      <div class="form-row">
        <input id="nm-target" class="input" type="text"
          placeholder="192.168.1.1  /  10.0.0.0/24  /  example.com"
          autocomplete="off" spellcheck="false">
        <select id="nm-profile" class="select">
          <option value="quick">Quick  (-T4 -F)</option>
          <option value="full" >Full   (-A -p-)</option>
          <option value="syn"  >SYN    (-sS -T2)</option>
          <option value="vuln" >Vuln   (--script=vuln)</option>
          <option value="udp"  >UDP    (top 100)</option>
        </select>
      </div>

      <div class="btn-row">
        <button id="nm-start"  class="btn btn-primary">▶ Start</button>
        <button id="nm-cancel" class="btn btn-danger"  disabled>■ Cancel</button>
        <button id="nm-copy"   class="btn btn-ghost"   disabled>⎘ Copy</button>
        <button id="nm-export" class="btn btn-ghost"   disabled>↓ JSON</button>
      </div>

      <div id="nm-status" class="status-bar hidden"></div>

      <div class="output-wrap">
        <div class="output-toolbar">
          <span id="nm-cmd" style="color:var(--dim2)">—</span>
          <span id="nm-timer"></span>
        </div>
        <pre id="nm-output" class="terminal empty">Waiting for scan…</pre>
      </div>
    `;

    this._bind();
    this._checkAgent();
  }

  // ── Event binding ────────────────────────────────────────────────────────────

  _bind() {
    const el = id => this.container.querySelector(`#${id}`);

    el('nm-start') .addEventListener('click', () => this._startScan());
    el('nm-cancel').addEventListener('click', () => this._cancel());
    el('nm-copy')  .addEventListener('click', () => this._copy());
    el('nm-export').addEventListener('click', () => this._export());
    el('nm-target').addEventListener('keydown', e => {
      if (e.key === 'Enter') this._startScan();
    });
  }

  // ── Agent check ──────────────────────────────────────────────────────────────

  async _checkAgent() {
    const ok = await this.agent.isConnected();
    if (!ok) {
      this._setStatus(
        '✗ Agent not running — start companion-server.js on port 31337',
        's-error'
      );
      this.container.querySelector('#nm-start').disabled = true;
    }
  }

  // ── Scan lifecycle ───────────────────────────────────────────────────────────

  async _startScan() {
    const target  = this.container.querySelector('#nm-target').value.trim();
    const profile = this.container.querySelector('#nm-profile').value;

    if (!target)                    return this._setStatus('Enter a target.', 's-warn');
    if (!this._isValidTarget(target)) return this._setStatus('Invalid target format.', 's-error');

    const ok = await this.agent.isConnected();
    if (!ok) return this._setStatus('Agent offline. Start companion-server.js first.', 's-error');

    // Reset state
    this.rawOutput = '';
    this.startTime = Date.now();
    this._setOutput('');
    this._setStatus('Connecting to agent…', 's-info');
    this._setScanning(true);
    this._startTimer();

    // SYN scan privilege notice
    if (profile === 'syn') {
      this._setStatus('SYN scan active — agent must be running with root/sudo privileges.', 's-warn');
    }

    this.ws = this.agent.openWebSocket();

    this.ws.onopen = () => {
      this.ws.send(JSON.stringify({ type: 'nmap', target, scanType: profile }));
    };

    this.ws.onmessage = ({ data }) => {
      const msg = JSON.parse(data);
      this._handleMsg(msg, target, profile);
    };

    this.ws.onerror = () => {
      this._setStatus('WebSocket error — is the agent running?', 's-error');
      this._setScanning(false);
      this._stopTimer();
    };

    this.ws.onclose = () => {
      if (this.scanning) {
        this._setStatus('Connection closed unexpectedly.', 's-warn');
        this._setScanning(false);
        this._stopTimer();
      }
    };
  }

  _handleMsg(msg, target, profile) {
    switch (msg.type) {
      case 'start':
        this.container.querySelector('#nm-cmd').textContent = msg.command;
        this._setStatus(`Running: ${msg.command}`, 's-info');
        break;

      case 'output':
        this._appendOutput(msg.data);
        break;

      case 'stderr':
        this._appendOutput(msg.data, 'c-dim');
        break;

      case 'warn':
        this._setStatus(msg.message, 's-warn');
        break;

      case 'error':
        this._setStatus(`✗ ${msg.message}`, 's-error');
        this._setScanning(false);
        this._stopTimer();
        break;

      case 'done': {
        const elapsed = ((Date.now() - this.startTime) / 1000).toFixed(1);
        this._setStatus(`✓ Scan complete — ${elapsed}s`, 's-success');
        this._setScanning(false);
        this._stopTimer();
        this._enableActions(true);

        this.history.add({
          tool:      'Nmap Scanner',
          target,
          params:    { profile },
          summary:   this._buildSummary(),
          rawOutput: this.rawOutput,
        });
        break;
      }

      case 'cancelled':
        this._setStatus('Scan cancelled.', 's-warn');
        this._setScanning(false);
        this._stopTimer();
        break;
    }
  }

  _cancel() {
    if (this.ws?.readyState === WebSocket.OPEN) {
      this.ws.send(JSON.stringify({ type: 'cancel' }));
    }
  }

  // ── Output rendering ─────────────────────────────────────────────────────────

  _setOutput(text) {
    const el = this.container.querySelector('#nm-output');
    el.innerHTML = '';
    el.classList.toggle('empty', !text);
    if (!text) el.textContent = 'Waiting for scan…';
    this.rawOutput = text;
  }

  _appendOutput(text, extraClass = '') {
    const el = this.container.querySelector('#nm-output');
    el.classList.remove('empty');

    this.rawOutput += text;

    // Syntax highlighting for common nmap output patterns
    const html = escHtml(text)
      .replace(/\b(open)\b/g,     '<span class="c-green">$1</span>')
      .replace(/\b(closed)\b/g,   '<span class="c-red">$1</span>')
      .replace(/\b(filtered)\b/g, '<span class="c-amber">$1</span>')
      .replace(/(\d+\/(tcp|udp))/g, '<span class="c-blue">$1</span>')
      .replace(/(Nmap scan report for .+)/g, '<span class="c-amber">$1</span>');

    const span = document.createElement('span');
    if (extraClass) span.className = extraClass;
    span.innerHTML = html;
    el.appendChild(span);
    el.scrollTop = el.scrollHeight;
  }

  // ── Timer ────────────────────────────────────────────────────────────────────

  _startTimer() {
    const el = this.container.querySelector('#nm-timer');
    this._timerInterval = setInterval(() => {
      const s = ((Date.now() - this.startTime) / 1000).toFixed(0);
      el.textContent = `${s}s`;
    }, 1000);
  }

  _stopTimer() {
    clearInterval(this._timerInterval);
  }

  // ── Status / button state ────────────────────────────────────────────────────

  _setStatus(msg, cls) {
    const el = this.container.querySelector('#nm-status');
    el.className = `status-bar ${cls}`;
    el.textContent = msg;
  }

  _setScanning(scanning) {
    this.scanning = scanning;
    const el = id => this.container.querySelector(`#${id}`);
    el('nm-start') .disabled = scanning;
    el('nm-cancel').disabled = !scanning;
  }

  _enableActions(yes) {
    const el = id => this.container.querySelector(`#${id}`);
    el('nm-copy')  .disabled = !yes;
    el('nm-export').disabled = !yes;
  }

  // ── Copy / Export ────────────────────────────────────────────────────────────

  _copy() {
    navigator.clipboard.writeText(this.rawOutput).then(() =>
      this._setStatus('✓ Copied to clipboard.', 's-success')
    );
  }

  _export() {
    const target  = this.container.querySelector('#nm-target').value.trim();
    const profile = this.container.querySelector('#nm-profile').value;
    exportJSON({
      tool:      'NetRecon / Nmap Scanner',
      target,
      profile,
      timestamp: new Date().toISOString(),
      summary:   this._buildSummary(),
      rawOutput: this.rawOutput,
    }, `netrecon-nmap-${target}`);
  }

  // ── Helpers ──────────────────────────────────────────────────────────────────

  _buildSummary() {
    const openPorts = (this.rawOutput.match(/\d+\/(?:tcp|udp)\s+open/g) || []).length;
    const hosts     = (this.rawOutput.match(/Nmap scan report/g) || []).length;
    const parts     = [];
    if (hosts    > 0) parts.push(`${hosts} host${hosts > 1 ? 's' : ''}`);
    if (openPorts > 0) parts.push(`${openPorts} open port${openPorts > 1 ? 's' : ''}`);
    return parts.join(', ') || 'Scan completed';
  }

  _isValidTarget(t) {
    // Hostname, IPv4 (optional CIDR), IPv4 range, IPv6
    return /^[a-zA-Z0-9][a-zA-Z0-9\-\.]{0,253}[a-zA-Z0-9]?$/.test(t) ||
           /^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$/.test(t) ||
           /^[0-9a-fA-F:]+$/.test(t);
  }

  // ── Teardown ─────────────────────────────────────────────────────────────────

  destroy() {
    this._stopTimer();
    if (this.ws) { try { this.ws.close(); } catch {} this.ws = null; }
  }
}

// ── Shared utilities (used by all modules) ────────────────────────────────────

export function escHtml(str) {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}

export function exportJSON(data, filenameBase) {
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement('a');
  a.href     = url;
  a.download = `${filenameBase}-${Date.now()}.json`;
  a.click();
  URL.revokeObjectURL(url);
}
