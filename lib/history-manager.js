// lib/history-manager.js — chrome.storage.local scan history

const KEY      = 'netrecon_history';
const MAX_ROWS = 300;

export class HistoryManager {
  async add({ tool, target, params = {}, summary, rawOutput = null }) {
    const all = await this.getAll();
    all.unshift({
      id:        Date.now(),
      timestamp: new Date().toISOString(),
      tool,
      target,
      params,
      summary,
      rawOutput, // may be null for large results
    });
    await chrome.storage.local.set({ [KEY]: all.slice(0, MAX_ROWS) });
  }

  async getAll() {
    const d = await chrome.storage.local.get(KEY);
    return d[KEY] ?? [];
  }

  async clear() {
    await chrome.storage.local.remove(KEY);
  }

  async remove(id) {
    const all = await this.getAll();
    await chrome.storage.local.set({ [KEY]: all.filter(r => r.id !== id) });
  }
}
