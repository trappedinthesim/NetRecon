// modules/ip-geo.js — IP Geolocation & ASN via ipapi.co (through agent)
import { exportJSON } from './nmap-scanner.js';

export class IpGeo {
  constructor({ container, agent, history }) { this.container = container; this.agent = agent; this.history = history; this.result = null; }

  render() {
    this.container.innerHTML = `
      <div class="module-header"><div class="module-title">◈ IP Geolocation & ASN</div></div>
      <div class="form-row">
        <input id="geo-target" class="input" type="text" placeholder="8.8.8.8  or  example.com" autocomplete="off" spellcheck="false">
        <button id="geo-run" class="btn btn-primary">▶ Lookup</button>
      </div>
      <div class="btn-row">
        <button id="geo-copy"   class="btn btn-ghost" disabled>⎘ Copy</button>
        <button id="geo-export" class="btn btn-ghost" disabled>↓ JSON</button>
      </div>
      <div id="geo-status" class="status-bar hidden"></div>
      <div id="geo-results"></div>
    `;
    const el = id => this.container.querySelector(`#${id}`);
    el('geo-run')   .addEventListener('click',   () => this._run());
    el('geo-target').addEventListener('keydown', e => { if (e.key === 'Enter') this._run(); });
    el('geo-copy')  .addEventListener('click',   () => this._copy());
    el('geo-export').addEventListener('click',   () => this._export());
  }

  async _run() {
    const target = this.container.querySelector('#geo-target').value.trim();
    if (!target) return this._status('Enter an IP or hostname.', 's-warn');
    this._status('<span class="spinner"></span> Looking up…', 's-info');
    this._setActions(false);
    try {
      this.result = await this.agent.get('/geo', { target });
      this._renderResult(this.result);
      this._status('✓ Done', 's-success');
      this._setActions(true);
      const city = this.result.city || '';
      const cc   = this.result.country_code || '';
      this.history.add({ tool: 'IP Geo', target, summary: [city, cc].filter(Boolean).join(', ') || 'Lookup complete' });
    } catch (e) {
      this._status(`✗ ${e.message}`, 's-error');
    }
  }

  _renderResult(r) {
    const card = (label, value) => value
      ? `<div class="data-card"><div class="data-card-label">${label}</div><div class="data-card-value">${escHtml(String(value))}</div></div>`
      : '';
    const wideCard = (label, value) => value
      ? `<div class="data-card wide"><div class="data-card-label">${label}</div><div class="data-card-value">${escHtml(String(value))}</div></div>`
      : '';

    const bogon = r.bogon
      ? `<div class="status-bar s-warn mt8">⚠ Bogon / private address — geolocation not available for private IP ranges.</div>`
      : '';

    const html = `
      ${bogon}
      <div class="section-label mt8">Location</div>
      <div class="card-grid mt8">
        ${card('IP',         r.ip)}
        ${card('Country',    r.country_name + (r.country_code ? ` (${r.country_code})` : ''))}
        ${card('Region',     r.region)}
        ${card('City',       r.city)}
        ${card('Postal',     r.postal)}
        ${card('Timezone',   r.timezone)}
        ${card('Coordinates', r.latitude && r.longitude ? `${r.latitude}, ${r.longitude}` : null)}
      </div>
      <div class="section-label mt12">Network</div>
      <div class="card-grid mt8">
        ${card('ASN',     r.asn)}
        ${wideCard('ISP / Org', r.org)}
      </div>`;
    this.container.querySelector('#geo-results').innerHTML = html;
  }

  _status(msg, cls) { const el = this.container.querySelector('#geo-status'); el.className = `status-bar ${cls}`; el.innerHTML = msg; }
  _setActions(yes)  { ['geo-copy','geo-export'].forEach(id => { this.container.querySelector(`#${id}`).disabled = !yes; }); }
  _copy()   { navigator.clipboard.writeText(JSON.stringify(this.result, null, 2)).then(() => this._status('✓ Copied.', 's-success')); }
  _export() { const t = this.container.querySelector('#geo-target').value.trim(); exportJSON({ tool: 'NetRecon / IP Geo', target: t, timestamp: new Date().toISOString(), ...this.result }, `netrecon-geo-${t}`); }
  destroy() {}
}

function escHtml(s) { return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }
