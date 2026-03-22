// modules/port-scanner.js — TCP port scan via nmap WebSocket stream
import { exportJSON } from './nmap-scanner.js';

const PRESETS = {
  common: [21,22,23,25,53,80,110,143,389,443,445,465,587,636,993,995,1433,1521,3306,3389,5432,5900,6379,8080,8443,9200,27017],
  web:    [80,443,8080,8443,8888,3000,3001,4000,4443,9000,9443],
  db:     [1433,1521,3306,5432,5984,6379,7474,9200,9300,27017,27018,28015],
  dev:    [3000,3001,4000,4200,5000,5173,8000,8080,8888,9000],
};

export class PortScanner {
  constructor({ container, agent, history }) {
    this.container = container; this.agent = agent; this.history = history;
    this.ws = null; this.rawOutput = ''; this.scanning = false;
  }

  render() {
    this.container.innerHTML = `
      <div class="module-header">
        <div class="module-title">◈ Port Scanner <span class="agent-badge">⚡ Requires Agent</span></div>
      </div>
      <div class="form-row">
        <input id="ps-target" class="input" type="text" placeholder="192.168.1.1 or example.com" autocomplete="off" spellcheck="false">
        <select id="ps-preset" class="select">
          <option value="common">Common ports</option>
          <option value="web">Web stack</option>
          <option value="db">Databases</option>
          <option value="dev">Dev servers</option>
          <option value="custom">Custom…</option>
        </select>
      </div>
      <div id="ps-custom-row" class="form-row" style="display:none">
        <input id="ps-custom" class="input" type="text" placeholder="80,443,8080  or  1-1024" autocomplete="off">
      </div>
      <div class="btn-row">
        <button id="ps-start"  class="btn btn-primary">▶ Scan</button>
        <button id="ps-cancel" class="btn btn-danger"  disabled>■ Cancel</button>
        <button id="ps-copy"   class="btn btn-ghost"   disabled>⎘ Copy</button>
        <button id="ps-export" class="btn btn-ghost"   disabled>↓ JSON</button>
      </div>
      <div id="ps-status" class="status-bar hidden"></div>
      <div class="output-wrap">
        <div class="output-toolbar"><span style="color:var(--dim2)">Port scan output</span><span id="ps-timer"></span></div>
        <pre id="ps-output" class="terminal empty">Waiting for scan…</pre>
      </div>
    `;
    const el = id => this.container.querySelector(`#${id}`);
    el('ps-start') .addEventListener('click',  () => this._start());
    el('ps-cancel').addEventListener('click',  () => this._cancel());
    el('ps-copy')  .addEventListener('click',  () => this._copy());
    el('ps-export').addEventListener('click',  () => this._export());
    el('ps-preset').addEventListener('change', () => {
      el('ps-custom-row').style.display = el('ps-preset').value === 'custom' ? 'flex' : 'none';
    });
  }

  _resolvePorts() {
    const preset = this.container.querySelector('#ps-preset').value;
    if (preset !== 'custom') return PRESETS[preset];
    const raw = this.container.querySelector('#ps-custom').value.trim();
    const ports = [];
    for (const part of raw.split(',')) {
      const range = part.trim().match(/^(\d+)-(\d+)$/);
      if (range) {
        for (let p = parseInt(range[1]); p <= parseInt(range[2]) && p <= 65535; p++) ports.push(p);
      } else {
        const n = parseInt(part.trim(), 10);
        if (n > 0 && n <= 65535) ports.push(n);
      }
    }
    return [...new Set(ports)].slice(0, 1000);
  }

  async _start() {
    const target = this.container.querySelector('#ps-target').value.trim();
    if (!target) return this._status('Enter a target.', 's-warn');
    const ports = this._resolvePorts();
    if (!ports.length) return this._status('No valid ports specified.', 's-warn');

    const ok = await this.agent.isConnected();
    if (!ok) return this._status('Agent offline.', 's-error');

    this.rawOutput = ''; this.startTime = Date.now();
    this._clearOutput(); this._setScanning(true);
    this._status(`Scanning ${ports.length} ports on ${target}…`, 's-info');

    this.ws = this.agent.openWebSocket();
    this.ws.onopen    = () => this.ws.send(JSON.stringify({ type: 'portscan', target, ports }));
    this.ws.onmessage = ({ data }) => {
      const msg = JSON.parse(data);
      if (msg.type === 'output')  { this.rawOutput += msg.data; this._appendOutput(msg.data); }
      if (msg.type === 'done')    { this._setScanning(false); this._setActions(true); this._status(`✓ Done — ${((Date.now()-this.startTime)/1000).toFixed(1)}s`, 's-success'); this.history.add({ tool: 'Port Scanner', target, params: { ports: ports.length }, summary: this._summary() }); }
      if (msg.type === 'error')   { this._status(`✗ ${msg.message}`, 's-error'); this._setScanning(false); }
      if (msg.type === 'cancelled') { this._status('Cancelled.', 's-warn'); this._setScanning(false); }
    };
    this.ws.onerror = () => { this._status('WebSocket error.', 's-error'); this._setScanning(false); };
  }

  _cancel()  { if (this.ws?.readyState === 1) this.ws.send(JSON.stringify({ type: 'cancel' })); }
  _clearOutput() { const el = this.container.querySelector('#ps-output'); el.innerHTML = ''; el.classList.add('empty'); el.textContent = 'Scanning…'; el.classList.remove('empty'); }
  _appendOutput(text) {
    const el = this.container.querySelector('#ps-output');
    el.classList.remove('empty');
    const span = document.createElement('span');
    span.innerHTML = escHtml(text).replace(/\b(open)\b/g,'<span class="c-green">$1</span>').replace(/\b(closed|filtered)\b/g,'<span class="c-red">$1</span>').replace(/(\d+\/(tcp|udp))/g,'<span class="c-blue">$1</span>');
    el.appendChild(span); el.scrollTop = el.scrollHeight;
  }
  _summary()  { const open = (this.rawOutput.match(/open/g) || []).length; return `${open} open port${open !== 1 ? 's' : ''} found`; }
  _status(msg, cls) { const el = this.container.querySelector('#ps-status'); el.className = `status-bar ${cls}`; el.innerHTML = msg; }
  _setScanning(s) { const el = id => this.container.querySelector(`#${id}`); el('ps-start').disabled = s; el('ps-cancel').disabled = !s; }
  _setActions(yes) { ['ps-copy','ps-export'].forEach(id => { this.container.querySelector(`#${id}`).disabled = !yes; }); }
  _copy()   { navigator.clipboard.writeText(this.rawOutput).then(() => this._status('✓ Copied.', 's-success')); }
  _export() { const t = this.container.querySelector('#ps-target').value.trim(); exportJSON({ tool: 'NetRecon / Port Scanner', target: t, timestamp: new Date().toISOString(), rawOutput: this.rawOutput }, `netrecon-ports-${t}`); }
  destroy() { if (this.ws) { try { this.ws.close(); } catch {} } }
}

function escHtml(s) { return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }
