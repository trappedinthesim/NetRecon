// modules/subdomain-enum.js — crt.sh passive + active DNS wordlist
import { exportJSON } from './nmap-scanner.js';

const DEFAULT_WORDLIST = ['www','mail','remote','blog','webmail','server','ns1','ns2','smtp',
  'secure','vpn','m','shop','ftp','mail2','test','portal','ns','ww1','host','support',
  'dev','web','bbs','ww42','mx','email','cloud','1','mail1','2','forum','owa','www2',
  'gw','admin','store','mx1','cdn','api','exchange','app','gov','2tty','vps','gate'];

export class SubdomainEnum {
  constructor({ container, agent, history }) { this.container = container; this.agent = agent; this.history = history; this.result = null; }

  render() {
    this.container.innerHTML = `
      <div class="module-header">
        <div class="module-title">⬡ Subdomain Enumerator <span class="agent-badge">⚡ Requires Agent</span></div>
      </div>
      <div class="form-row">
        <input id="sd-target" class="input" type="text" placeholder="example.com" autocomplete="off" spellcheck="false">
      </div>
      <div class="form-row" style="align-items:flex-start;gap:8px;margin-bottom:8px">
        <label style="display:flex;align-items:center;gap:5px;color:var(--dim);font-size:11.5px;cursor:pointer">
          <input type="checkbox" id="sd-passive" checked> Passive (crt.sh)
        </label>
        <label style="display:flex;align-items:center;gap:5px;color:var(--dim);font-size:11.5px;cursor:pointer">
          <input type="checkbox" id="sd-active"> Active (DNS wordlist)
        </label>
      </div>
      <div id="sd-wordlist-row" style="display:none;margin-bottom:8px">
        <textarea id="sd-words" class="textarea" style="height:60px;font-size:11px" placeholder="One subdomain prefix per line, or leave blank for built-in list (${DEFAULT_WORDLIST.length} entries)"></textarea>
      </div>
      <div class="btn-row">
        <button id="sd-run"    class="btn btn-primary">▶ Enumerate</button>
        <button id="sd-copy"   class="btn btn-ghost" disabled>⎘ Copy</button>
        <button id="sd-export" class="btn btn-ghost" disabled>↓ JSON</button>
      </div>
      <div id="sd-status" class="status-bar hidden"></div>
      <div id="sd-results"></div>
    `;
    const el = id => this.container.querySelector(`#${id}`);
    el('sd-run')   .addEventListener('click',   () => this._run());
    el('sd-copy')  .addEventListener('click',   () => this._copy());
    el('sd-export').addEventListener('click',   () => this._export());
    el('sd-active').addEventListener('change',  () => {
      el('sd-wordlist-row').style.display = el('sd-active').checked ? 'block' : 'none';
    });
  }

  async _run() {
    const target  = this.container.querySelector('#sd-target').value.trim();
    const passive = this.container.querySelector('#sd-passive').checked;
    const active  = this.container.querySelector('#sd-active').checked;
    if (!target)           return this._status('Enter a domain.', 's-warn');
    if (!passive && !active) return this._status('Select at least one method.', 's-warn');

    let wordlist = [];
    if (active) {
      const raw = this.container.querySelector('#sd-words').value.trim();
      wordlist = raw ? raw.split('\n').map(w => w.trim()).filter(Boolean) : DEFAULT_WORDLIST;
    }

    this._status(`<span class="spinner"></span> Enumerating subdomains${active ? ` (${wordlist.length} words)` : ''}…`, 's-info');
    this._setActions(false);
    try {
      this.result = await this.agent.post('/subdomains', { target, wordlist: active ? wordlist : [] });
      this._renderResult(this.result);
      const total = this.result.subdomains?.length || 0;
      this._status(`✓ ${total} subdomain${total !== 1 ? 's' : ''} found`, 's-success');
      this._setActions(true);
      this.history.add({ tool: 'Subdomain Enum', target, summary: `${total} subdomains found` });
    } catch (e) {
      this._status(`✗ ${e.message}`, 's-error');
    }
  }

  _renderResult(r) {
    const all    = r.subdomains || [];
    const active = new Set((r.activeResolved || []).map(a => a.subdomain));
    if (!all.length) {
      this.container.querySelector('#sd-results').innerHTML = '<p style="color:var(--dim2);font-size:12px;padding:16px 0">No subdomains found.</p>';
      return;
    }
    const html = `
      <div class="section-label">${all.length} Subdomains</div>
      <div class="tbl-wrap mt8"><table class="tbl">
        <thead><tr><th>Subdomain</th><th>Status</th></tr></thead>
        <tbody>${all.map(s => `
          <tr>
            <td class="monospace">${escHtml(s)}</td>
            <td>${active.has(s) ? '<span class="badge b-pass">LIVE</span>' : '<span class="badge b-info">PASSIVE</span>'}</td>
          </tr>`).join('')}
        </tbody>
      </table></div>`;
    this.container.querySelector('#sd-results').innerHTML = html;
  }

  _status(msg, cls) { const el = this.container.querySelector('#sd-status'); el.className = `status-bar ${cls}`; el.innerHTML = msg; }
  _setActions(yes) { ['sd-copy','sd-export'].forEach(id => { this.container.querySelector(`#${id}`).disabled = !yes; }); }
  _copy() { const subs = (this.result?.subdomains || []).join('\n'); navigator.clipboard.writeText(subs).then(() => this._status('✓ Copied.', 's-success')); }
  _export() { const t = this.container.querySelector('#sd-target').value.trim(); exportJSON({ tool: 'NetRecon / Subdomains', target: t, timestamp: new Date().toISOString(), ...this.result }, `netrecon-subs-${t}`); }
  destroy() {}
}

function escHtml(s) { return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }
