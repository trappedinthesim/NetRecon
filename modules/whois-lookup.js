// modules/whois-lookup.js
import { exportJSON } from './nmap-scanner.js';

export class WhoisLookup {
  constructor({ container, agent, history }) { this.container = container; this.agent = agent; this.history = history; this.result = null; }

  render() {
    this.container.innerHTML = `
      <div class="module-header">
        <div class="module-title">◎ WHOIS Lookup <span class="agent-badge">⚡ Requires Agent</span></div>
      </div>
      <div class="form-row">
        <input id="w-target" class="input" type="text" placeholder="example.com  or  8.8.8.8" autocomplete="off" spellcheck="false">
        <button id="w-run" class="btn btn-primary">▶ Lookup</button>
      </div>
      <div class="btn-row">
        <button id="w-copy"   class="btn btn-ghost" disabled>⎘ Copy</button>
        <button id="w-export" class="btn btn-ghost" disabled>↓ JSON</button>
      </div>
      <div id="w-status" class="status-bar hidden"></div>
      <div id="w-results"></div>
    `;
    const el = id => this.container.querySelector(`#${id}`);
    el('w-run')   .addEventListener('click',   () => this._run());
    el('w-target').addEventListener('keydown', e => { if (e.key === 'Enter') this._run(); });
    el('w-copy')  .addEventListener('click',   () => this._copy());
    el('w-export').addEventListener('click',   () => this._export());
  }

  async _run() {
    const target = this.container.querySelector('#w-target').value.trim();
    if (!target) return this._status('Enter a domain or IP.', 's-warn');
    this._status('<span class="spinner"></span> Querying WHOIS…', 's-info');
    ['w-copy','w-export'].forEach(id => this.container.querySelector(`#${id}`).disabled = true);
    try {
      this.result = await this.agent.post('/whois', { target });
      this._renderResult(this.result);
      this._status('✓ Done', 's-success');
      ['w-copy','w-export'].forEach(id => this.container.querySelector(`#${id}`).disabled = false);
      this.history.add({ tool: 'WHOIS Lookup', target, summary: this.result.parsed?.registrar || 'Lookup complete' });
    } catch (e) {
      this._status(`✗ ${e.message}`, 's-error');
    }
  }

  _renderResult({ parsed, raw }) {
    const row = (label, value) => value
      ? `<tr><td style="color:var(--dim);white-space:nowrap">${label}</td><td>${escHtml(Array.isArray(value) ? value.join(', ') : value)}</td></tr>`
      : '';

    const parsedHtml = `
      <div class="section-label">Parsed Fields</div>
      <div class="tbl-wrap mt8"><table class="tbl"><tbody>
        ${row('Registrar',   parsed.registrar)}
        ${row('Registrant',  parsed.registrant)}
        ${row('Country',     parsed.country)}
        ${row('Created',     parsed.created)}
        ${row('Expires',     parsed.expires)}
        ${row('Updated',     parsed.updated)}
        ${row('Status',      parsed.status)}
        ${row('Nameservers', parsed.nameservers)}
        ${row('Abuse',       parsed.abuse)}
      </tbody></table></div>`;

    const rawHtml = `
      <div class="section-label mt12">Raw Output</div>
      <div class="output-wrap mt8"><pre class="terminal" style="max-height:200px">${escHtml(raw)}</pre></div>`;

    this.container.querySelector('#w-results').innerHTML = parsedHtml + rawHtml;
  }

  _status(msg, cls) { const el = this.container.querySelector('#w-status'); el.className = `status-bar ${cls}`; el.innerHTML = msg; }
  _copy() { navigator.clipboard.writeText(JSON.stringify(this.result, null, 2)).then(() => this._status('✓ Copied.', 's-success')); }
  _export() { const t = this.container.querySelector('#w-target').value.trim(); exportJSON({ tool: 'NetRecon / WHOIS', target: t, timestamp: new Date().toISOString(), ...this.result }, `netrecon-whois-${t}`); }
  destroy() {}
}

function escHtml(s) { return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }
