// modules/history-tab.js — scan history viewer
import { exportJSON } from './nmap-scanner.js';

export class HistoryTab {
  constructor({ container, agent, history }) { this.container = container; this.history = history; }

  render() {
    this.container.innerHTML = `
      <div class="module-header">
        <div class="module-title">☰ Scan History</div>
        <div style="display:flex;gap:6px">
          <button id="hist-export" class="btn btn-ghost">↓ Export All</button>
          <button id="hist-clear"  class="btn btn-danger">✕ Clear</button>
        </div>
      </div>
      <div class="form-row" style="margin-bottom:10px">
        <input id="hist-filter" class="input" type="text" placeholder="Filter by tool or target…">
        <select id="hist-tool" class="select">
          <option value="">All tools</option>
          <option>Nmap Scanner</option>
          <option>DNS Recon</option>
          <option>WHOIS Lookup</option>
          <option>SSL Inspector</option>
          <option>Port Scanner</option>
          <option>HTTP Headers</option>
          <option>Subdomain Enum</option>
          <option>IP Geo</option>
          <option>CVE Lookup</option>
          <option>Reverse IP</option>
        </select>
      </div>
      <div id="hist-status" class="status-bar hidden"></div>
      <div id="hist-list"></div>
      <div id="hist-detail" style="display:none;margin-top:12px">
        <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:8px">
          <span class="section-label" style="margin:0">Raw Output</span>
          <button id="hist-close-detail" class="btn btn-ghost" style="padding:2px 8px;font-size:10px">× Close</button>
        </div>
        <div class="output-wrap"><pre id="hist-raw" class="terminal" style="max-height:250px"></pre></div>
      </div>
    `;
    this.container.querySelector('#hist-clear') .addEventListener('click',  () => this._clear());
    this.container.querySelector('#hist-export').addEventListener('click',  () => this._exportAll());
    this.container.querySelector('#hist-filter').addEventListener('input',  () => this._load());
    this.container.querySelector('#hist-tool')  .addEventListener('change', () => this._load());
    this.container.querySelector('#hist-close-detail').addEventListener('click', () => {
      this.container.querySelector('#hist-detail').style.display = 'none';
    });
    this._load();
  }

  async _load() {
    const all    = await this.history.getAll();
    const filter = this.container.querySelector('#hist-filter').value.toLowerCase();
    const tool   = this.container.querySelector('#hist-tool').value;
    const items  = all.filter(r =>
      (!tool   || r.tool === tool) &&
      (!filter || r.target?.toLowerCase().includes(filter) || r.tool?.toLowerCase().includes(filter))
    );
    this._renderList(items);
  }

  _renderList(items) {
    const el = this.container.querySelector('#hist-list');
    if (!items.length) {
      el.innerHTML = '<div class="history-empty">No scan history yet.</div>';
      return;
    }
    el.innerHTML = `<div class="history-list">
      ${items.map(r => `
        <div class="history-item" data-id="${r.id}">
          <div class="h-row1">
            <span class="h-tool">${escHtml(r.tool)}</span>
            <span class="h-time">${new Date(r.timestamp).toLocaleString()}</span>
          </div>
          <div class="h-target">${escHtml(r.target || '—')}</div>
          <div class="h-summary">${escHtml(r.summary || '')}</div>
        </div>`).join('')}
    </div>`;

    el.querySelectorAll('.history-item').forEach(item => {
      item.addEventListener('click', () => this._showDetail(items.find(r => r.id == item.dataset.id)));
    });
  }

  _showDetail(record) {
    if (!record?.rawOutput) return;
    const detail = this.container.querySelector('#hist-detail');
    this.container.querySelector('#hist-raw').textContent = record.rawOutput;
    detail.style.display = 'block';
    detail.scrollIntoView({ behavior: 'smooth' });
  }

  async _clear() {
    const btn = this.container.querySelector('#hist-clear');
    if (btn.dataset.confirm !== '1') {
      btn.textContent = '✕ Confirm';
      btn.dataset.confirm = '1';
      setTimeout(() => { btn.textContent = '✕ Clear'; delete btn.dataset.confirm; }, 3000);
      return;
    }
    await this.history.clear();
    btn.textContent = '✕ Clear';
    delete btn.dataset.confirm;
    const status = this.container.querySelector('#hist-status');
    status.className = 'status-bar s-success';
    status.textContent = '✓ History cleared.';
    this._load();
  }

  async _exportAll() {
    const all = await this.history.getAll();
    exportJSON({ tool: 'NetRecon History Export', timestamp: new Date().toISOString(), count: all.length, records: all }, 'netrecon-history');
  }

  destroy() {}
}

function escHtml(s) { return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }
