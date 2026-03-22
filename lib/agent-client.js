// lib/agent-client.js — singleton HTTP + WebSocket client for companion agent

export class AgentClient {
  constructor(baseUrl = 'http://127.0.0.1:31337') {
    this.baseUrl = baseUrl;
    this.wsUrl   = baseUrl.replace('http://', 'ws://') + '/ws';
  }

  async isConnected() {
    try {
      const res = await fetch(`${this.baseUrl}/health`, {
        signal: AbortSignal.timeout(1800),
      });
      return res.ok;
    } catch {
      return false;
    }
  }

  async post(endpoint, body) {
    const res = await fetch(`${this.baseUrl}${endpoint}`, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify(body),
      signal:  AbortSignal.timeout(30000),
    });
    const data = await res.json().catch(() => ({ error: res.statusText }));
    if (!res.ok) throw new Error(data.error || res.statusText);
    return data;
  }

  async get(endpoint, params = {}) {
    const qs  = new URLSearchParams(params).toString();
    const url = `${this.baseUrl}${endpoint}${qs ? '?' + qs : ''}`;
    const res = await fetch(url, { signal: AbortSignal.timeout(30000) });
    const data = await res.json().catch(() => ({ error: res.statusText }));
    if (!res.ok) throw new Error(data.error || res.statusText);
    return data;
  }

  openWebSocket() {
    return new WebSocket(this.wsUrl);
  }
}
