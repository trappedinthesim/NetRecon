// modules/http-headers.js — HTTP security header analysis (routes through agent)
import { exportJSON } from './nmap-scanner.js';

export class HttpHeaders {
  constructor({ container, agent, history }) { this.container = container; this.agent = agent; this.history = history; this.result = null; }

  render() {
    this.container.innerHTML = `
      <div class="module-header">
        <div class="module-title">◎ HTTP Header Analyzer</div>
      </div>
      <div class="form-row">
        <input id="hh-target" class="input" type="text" placeholder="https://example.com  or  example.com" autocomplete="off" spellcheck="false">
        <button id="hh-run" class="btn btn-primary">▶ Fetch</button>
      </div>
      <div class="btn-row">
        <button id="hh-copy"   class="btn btn-ghost" disabled>⎘ Copy</button>
        <button id="hh-export" class="btn btn-ghost" disabled>↓ JSON</button>
      </div>
      <div id="hh-status" class="status-bar hidden"></div>
      <div id="hh-results"></div>
    `;
    const el = id => this.container.querySelector(`#${id}`);
    el('hh-run')   .addEventListener('click',   () => this._run());
    el('hh-target').addEventListener('keydown', e => { if (e.key === 'Enter') this._run(); });
    el('hh-copy')  .addEventListener('click',   () => this._copy());
    el('hh-export').addEventListener('click',   () => this._export());
  }

  async _run() {
    const target = this.container.querySelector('#hh-target').value.trim();
    if (!target) return this._status('Enter a URL.', 's-warn');
    this._status('<span class="spinner"></span> Fetching headers…', 's-info');
    this._setActions(false);
    try {
      this.result = await this.agent.post('/headers', { target });
      this._renderResult(this.result);
      const missing = this.result.security?.filter(h => !h.present && h.risk === 'high').length || 0;
      this._status(`✓ ${this.result.statusCode} ${this.result.statusMessage} — ${missing} high-risk header${missing !== 1 ? 's' : ''} missing`, missing ? 's-warn' : 's-success');
      this._setActions(true);
      this.history.add({ tool: 'HTTP Headers', target, summary: `${this.result.statusCode} — ${missing} missing security headers` });
    } catch (e) {
      this._status(`✗ ${e.message}`, 's-error');
    }
  }

  _renderResult(r) {
    const riskOrder = { high: 0, medium: 1, low: 2 };

    // Security header checklist
    const sorted = [...(r.security || [])].sort((a, b) => riskOrder[a.risk] - riskOrder[b.risk]);
    const secHtml = `
      <div class="section-label">Security Headers</div>
      <div class="tbl-wrap mt8"><table class="tbl">
        <thead><tr><th>Header</th><th>Status</th><th>Risk if Missing</th><th>Value</th></tr></thead>
        <tbody>${sorted.map(h => `
          <tr>
            <td class="monospace">${escHtml(h.label)}</td>
            <td><span class="badge ${h.present ? 'b-pass' : 'b-fail'}">${h.present ? '✓ PRESENT' : '✗ MISSING'}</span></td>
            <td><span class="badge b-${h.risk}">${h.risk.toUpperCase()}</span></td>
            <td style="font-size:10px;color:var(--dim);max-width:120px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${escHtml(h.value || h.desc)}">${escHtml(h.value || (h.present ? '' : h.desc))}</td>
          </tr>`).join('')}
        </tbody>
      </table></div>`;

    // Info headers (server fingerprinting)
    let infoHtml = '';
    if (r.server || r.poweredBy) {
      infoHtml = `<div class="section-label mt12">Server Fingerprint ⚠</div>
        <div class="card-grid mt8">
          ${r.server    ? `<div class="data-card"><div class="data-card-label">Server</div><div class="data-card-value">${escHtml(r.server)}</div></div>` : ''}
          ${r.poweredBy ? `<div class="data-card"><div class="data-card-label">X-Powered-By</div><div class="data-card-value">${escHtml(r.poweredBy)}</div></div>` : ''}
        </div>`;
    }

    // All headers
    const allHtml = `
      <div class="section-label mt12">All Response Headers</div>
      <div class="tbl-wrap mt8"><table class="tbl"><thead><tr><th>Header</th><th>Value</th></tr></thead>
        <tbody>${Object.entries(r.headers || {}).map(([k, v]) => `<tr><td class="monospace" style="color:var(--dim)">${escHtml(k)}</td><td>${escHtml(v)}</td></tr>`).join('')}</tbody>
      </table></div>`;

    this.container.querySelector('#hh-results').innerHTML = secHtml + infoHtml + allHtml;
  }

  _status(msg, cls)  { const el = this.container.querySelector('#hh-status'); el.className = `status-bar ${cls}`; el.innerHTML = msg; }
  _setActions(yes)   { ['hh-copy','hh-export'].forEach(id => { this.container.querySelector(`#${id}`).disabled = !yes; }); }
  _copy()   { navigator.clipboard.writeText(JSON.stringify(this.result, null, 2)).then(() => this._status('✓ Copied.', 's-success')); }
  _export() { const t = this.container.querySelector('#hh-target').value.trim(); exportJSON({ tool: 'NetRecon / HTTP Headers', target: t, timestamp: new Date().toISOString(), ...this.result }, `netrecon-headers-${t.replace(/[^a-z0-9]/gi,'-')}`); }
  destroy() {}
}

function escHtml(s) { return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }
