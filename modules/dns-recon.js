// modules/dns-recon.js — DNS Recon (A/AAAA/MX/TXT/NS/CNAME/SOA + zone transfer)
import { exportJSON } from './nmap-scanner.js';

export class DnsRecon {
  constructor({ container, agent, history }) {
    this.container = container;
    this.agent     = agent;
    this.history   = history;
    this.results   = null;
  }

  render() {
    this.container.innerHTML = `
      <div class="module-header">
        <div class="module-title">◈ DNS Recon <span class="agent-badge">⚡ Requires Agent</span></div>
      </div>
      <div class="form-row">
        <input id="dns-target" class="input" type="text" placeholder="example.com" autocomplete="off" spellcheck="false">
        <button id="dns-run" class="btn btn-primary">▶ Lookup</button>
      </div>
      <div class="btn-row">
        <button id="dns-copy"   class="btn btn-ghost" disabled>⎘ Copy</button>
        <button id="dns-export" class="btn btn-ghost" disabled>↓ JSON</button>
      </div>
      <div id="dns-status" class="status-bar hidden"></div>
      <div id="dns-results"></div>
    `;

    const el = id => this.container.querySelector(`#${id}`);
    el('dns-run')   .addEventListener('click',   () => this._run());
    el('dns-target').addEventListener('keydown', e => { if (e.key === 'Enter') this._run(); });
    el('dns-copy')  .addEventListener('click',   () => this._copy());
    el('dns-export').addEventListener('click',   () => this._export());
  }

  async _run() {
    const target = this.container.querySelector('#dns-target').value.trim();
    if (!target) return this._status('Enter a domain.', 's-warn');
    this._status('<span class="spinner"></span> Resolving…', 's-info');
    this._setActions(false);
    try {
      this.results = await this.agent.post('/dns', { target });
      this._render(target, this.results);
      this._status('✓ Done', 's-success');
      this._setActions(true);
      this.history.add({ tool: 'DNS Recon', target, summary: this._summary() });
    } catch (e) {
      this._status(`✗ ${e.message}`, 's-error');
    }
  }

  _render(target, data) {
    const TYPES = ['A', 'AAAA', 'MX', 'NS', 'CNAME', 'TXT', 'SOA'];
    const resultsEl = this.container.querySelector('#dns-results');
    let html = '';

    for (const type of TYPES) {
      const val = data[type];
      if (!val || val.error) continue;
      const rows = Array.isArray(val) ? val : [val];
      html += `<div class="section-label">${type} Records</div>
        <div class="tbl-wrap mt8"><table class="tbl"><thead><tr>
          <th>Value</th>${type === 'MX' ? '<th>Priority</th>' : ''}
        </tr></thead><tbody>`;
      for (const row of rows) {
        if (type === 'MX')       html += `<tr><td>${escHtml(row.exchange)}</td><td>${row.priority}</td></tr>`;
        else if (type === 'TXT') html += `<tr><td>${escHtml(Array.isArray(row) ? row.join(' ') : row)}</td></tr>`;
        else if (type === 'SOA') html += `<tr><td>${escHtml(JSON.stringify(row))}</td></tr>`;
        else                     html += `<tr><td>${escHtml(String(row))}</td></tr>`;
      }
      html += `</tbody></table></div>`;
    }

    if (data.AXFR) {
      html += `<div class="section-label mt12">Zone Transfer (AXFR)</div>
        <div class="output-wrap mt8"><pre class="terminal">${escHtml(data.AXFR)}</pre></div>`;
    }

    resultsEl.innerHTML = html || '<p style="color:var(--dim2);font-size:12px">No records found.</p>';
  }

  _status(msg, cls) {
    const el = this.container.querySelector('#dns-status');
    el.className = `status-bar ${cls}`;
    el.innerHTML = msg;
  }

  _setActions(yes) {
    ['dns-copy', 'dns-export'].forEach(id => {
      this.container.querySelector(`#${id}`).disabled = !yes;
    });
  }

  _copy() {
    navigator.clipboard.writeText(JSON.stringify(this.results, null, 2))
      .then(() => this._status('✓ Copied.', 's-success'));
  }

  _export() {
    const target = this.container.querySelector('#dns-target').value.trim();
    exportJSON({ tool: 'NetRecon / DNS Recon', target, timestamp: new Date().toISOString(), results: this.results }, `netrecon-dns-${target}`);
  }

  _summary() {
    if (!this.results) return '';
    const counts = ['A', 'MX', 'NS'].map(t => this.results[t]?.length ? `${this.results[t].length} ${t}` : null).filter(Boolean);
    return counts.join(', ') || 'Lookup complete';
  }

  destroy() {}
}

function escHtml(s) {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}
