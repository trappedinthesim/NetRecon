// modules/reverse-ip.js — Reverse IP lookup via HackerTarget API
import { exportJSON } from './nmap-scanner.js';

export class ReverseIp {
  constructor({ container, agent, history }) { this.container = container; this.agent = agent; this.history = history; this.result = null; }

  render() {
    this.container.innerHTML = `
      <div class="module-header"><div class="module-title">⬡ Reverse IP Lookup</div></div>
      <div class="form-row">
        <input id="ri-target" class="input" type="text" placeholder="93.184.216.34  or  example.com" autocomplete="off" spellcheck="false">
        <button id="ri-run" class="btn btn-primary">▶ Lookup</button>
      </div>
      <div class="btn-row">
        <button id="ri-copy"   class="btn btn-ghost" disabled>⎘ Copy</button>
        <button id="ri-export" class="btn btn-ghost" disabled>↓ JSON</button>
      </div>
      <div id="ri-status" class="status-bar hidden"></div>
      <p style="font-size:10.5px;color:var(--dim2);margin-bottom:10px">Data via HackerTarget API. Free tier limited to 100 results.</p>
      <div id="ri-results"></div>
    `;
    const el = id => this.container.querySelector(`#${id}`);
    el('ri-run')   .addEventListener('click',   () => this._run());
    el('ri-target').addEventListener('keydown', e => { if (e.key === 'Enter') this._run(); });
    el('ri-copy')  .addEventListener('click',   () => this._copy());
    el('ri-export').addEventListener('click',   () => this._export());
  }

  async _run() {
    const target = this.container.querySelector('#ri-target').value.trim();
    if (!target) return this._status('Enter an IP or hostname.', 's-warn');
    this._status('<span class="spinner"></span> Looking up…', 's-info');
    this._setActions(false);
    try {
      this.result = await this.agent.get('/reverseip', { target });
      const domains = this.result.domains || [];
      this._renderResult(domains);
      this._status(`✓ ${domains.length} domain${domains.length !== 1 ? 's' : ''} sharing this IP`, 's-success');
      this._setActions(true);
      this.history.add({ tool: 'Reverse IP', target, summary: `${domains.length} domains found` });
    } catch (e) {
      this._status(`✗ ${e.message}`, 's-error');
    }
  }

  _renderResult(domains) {
    if (!domains.length) {
      this.container.querySelector('#ri-results').innerHTML = '<p style="color:var(--dim2);font-size:12px">No domains found for this IP.</p>';
      return;
    }
    const html = `
      <div class="section-label">${domains.length} Domains on This IP</div>
      <div class="tbl-wrap mt8"><table class="tbl">
        <thead><tr><th>#</th><th>Domain</th></tr></thead>
        <tbody>${domains.map((d, i) => `<tr><td style="color:var(--dim2);width:36px">${i + 1}</td><td class="monospace">${escHtml(d)}</td></tr>`).join('')}</tbody>
      </table></div>`;
    this.container.querySelector('#ri-results').innerHTML = html;
  }

  _status(msg, cls) { const el = this.container.querySelector('#ri-status'); el.className = `status-bar ${cls}`; el.innerHTML = msg; }
  _setActions(yes)  { ['ri-copy','ri-export'].forEach(id => { this.container.querySelector(`#${id}`).disabled = !yes; }); }
  _copy()   { const domains = (this.result?.domains || []).join('\n'); navigator.clipboard.writeText(domains).then(() => this._status('✓ Copied.', 's-success')); }
  _export() { const t = this.container.querySelector('#ri-target').value.trim(); exportJSON({ tool: 'NetRecon / Reverse IP', target: t, timestamp: new Date().toISOString(), ...this.result }, `netrecon-reverseip-${t}`); }
  destroy() {}
}

function escHtml(s) { return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }
