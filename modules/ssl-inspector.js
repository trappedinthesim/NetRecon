// modules/ssl-inspector.js
import { exportJSON } from './nmap-scanner.js';

export class SslInspector {
  constructor({ container, agent, history }) { this.container = container; this.agent = agent; this.history = history; this.result = null; }

  render() {
    this.container.innerHTML = `
      <div class="module-header">
        <div class="module-title">⬡ SSL/TLS Inspector <span class="agent-badge">⚡ Requires Agent</span></div>
      </div>
      <div class="form-row">
        <input id="ssl-target" class="input" type="text" placeholder="example.com  or  example.com:8443" autocomplete="off" spellcheck="false">
        <button id="ssl-run" class="btn btn-primary">▶ Inspect</button>
      </div>
      <div class="btn-row">
        <button id="ssl-copy"   class="btn btn-ghost" disabled>⎘ Copy</button>
        <button id="ssl-export" class="btn btn-ghost" disabled>↓ JSON</button>
      </div>
      <div id="ssl-status" class="status-bar hidden"></div>
      <div id="ssl-results"></div>
    `;
    const el = id => this.container.querySelector(`#${id}`);
    el('ssl-run')   .addEventListener('click',   () => this._run());
    el('ssl-target').addEventListener('keydown', e => { if (e.key === 'Enter') this._run(); });
    el('ssl-copy')  .addEventListener('click',   () => this._copy());
    el('ssl-export').addEventListener('click',   () => this._export());
  }

  async _run() {
    const target = this.container.querySelector('#ssl-target').value.trim();
    if (!target) return this._status('Enter a hostname.', 's-warn');
    this._status('<span class="spinner"></span> Connecting…', 's-info');
    this._setActions(false);
    try {
      this.result = await this.agent.post('/ssl', { target });
      this._renderResult(this.result);
      const severity = this.result.vulnerabilities?.length ? 's-warn' : 's-success';
      this._status(`✓ Done — ${this.result.vulnerabilities?.length || 0} issue(s) found`, severity);
      this._setActions(true);
      const summary = this.result.vulnerabilities?.length
        ? `${this.result.vulnerabilities.length} vulnerability flags`
        : `Valid — expires in ${this.result.daysLeft} days`;
      this.history.add({ tool: 'SSL Inspector', target, summary });
    } catch (e) {
      this._status(`✗ ${e.message}`, 's-error');
    }
  }

  _renderResult(r) {
    // Vulnerabilities
    let vulnHtml = '';
    if (r.vulnerabilities?.length) {
      vulnHtml = `<div class="section-label">⚠ Vulnerabilities</div>
        <div class="tbl-wrap mt8"><table class="tbl"><thead><tr><th>ID</th><th>Severity</th><th>Detail</th></tr></thead><tbody>
        ${r.vulnerabilities.map(v => `<tr><td>${escHtml(v.id)}</td><td><span class="badge b-${v.severity}">${v.severity.toUpperCase()}</span></td><td>${escHtml(v.detail)}</td></tr>`).join('')}
        </tbody></table></div>`;
    }

    // Cert details
    const days = r.daysLeft;
    const daysClass = days < 0 ? 'b-critical' : days < 14 ? 'b-high' : days < 30 ? 'b-medium' : 'b-pass';

    const certHtml = `
      <div class="section-label mt12">Certificate</div>
      <div class="card-grid mt8">
        <div class="data-card"><div class="data-card-label">Subject CN</div><div class="data-card-value">${escHtml(r.subject?.CN || '—')}</div></div>
        <div class="data-card"><div class="data-card-label">Issuer</div><div class="data-card-value">${escHtml(r.issuer?.O || r.issuer?.CN || '—')}</div></div>
        <div class="data-card"><div class="data-card-label">Valid From</div><div class="data-card-value">${escHtml(r.validFrom || '—')}</div></div>
        <div class="data-card"><div class="data-card-label">Valid To</div><div class="data-card-value">${escHtml(r.validTo || '—')} <span class="badge ${daysClass}">${days < 0 ? 'EXPIRED' : `${days}d`}</span></div></div>
        <div class="data-card"><div class="data-card-label">Protocol</div><div class="data-card-value">${escHtml(r.protocol || '—')}</div></div>
        <div class="data-card"><div class="data-card-label">Cipher</div><div class="data-card-value">${escHtml(r.cipher?.name || '—')}</div></div>
        <div class="data-card wide"><div class="data-card-label">Fingerprint (SHA-256)</div><div class="data-card-value" style="font-size:10px">${escHtml(r.fingerprint256 || '—')}</div></div>
      </div>`;

    // SAN
    const sanHtml = r.san?.length ? `
      <div class="section-label">Subject Alternative Names</div>
      <div class="tbl-wrap mt8"><table class="tbl"><tbody>
        ${r.san.map(s => `<tr><td>${escHtml(s)}</td></tr>`).join('')}
      </tbody></table></div>` : '';

    // Chain
    const chainHtml = r.chain?.length > 1 ? `
      <div class="section-label mt12">Certificate Chain</div>
      <div class="tbl-wrap mt8"><table class="tbl"><thead><tr><th>#</th><th>Subject</th><th>Issuer</th><th>Expires</th></tr></thead><tbody>
        ${r.chain.map((c, i) => `<tr><td>${i + 1}</td><td>${escHtml(c.subject)}</td><td>${escHtml(c.issuer)}</td><td>${escHtml(c.validTo || '—')}</td></tr>`).join('')}
      </tbody></table></div>` : '';

    this.container.querySelector('#ssl-results').innerHTML = vulnHtml + certHtml + sanHtml + chainHtml;
  }

  _status(msg, cls) { const el = this.container.querySelector('#ssl-status'); el.className = `status-bar ${cls}`; el.innerHTML = msg; }
  _setActions(yes) { ['ssl-copy','ssl-export'].forEach(id => { this.container.querySelector(`#${id}`).disabled = !yes; }); }
  _copy() { navigator.clipboard.writeText(JSON.stringify(this.result, null, 2)).then(() => this._status('✓ Copied.', 's-success')); }
  _export() { const t = this.container.querySelector('#ssl-target').value.trim(); exportJSON({ tool: 'NetRecon / SSL Inspector', target: t, timestamp: new Date().toISOString(), ...this.result }, `netrecon-ssl-${t}`); }
  destroy() {}
}

function escHtml(s) { return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }
