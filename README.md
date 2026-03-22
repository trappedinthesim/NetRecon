# NetRecon

**10 security tools in a Chrome side panel.**

Nmap scanning, DNS recon, WHOIS, SSL inspection, port scanning, HTTP headers, subdomain enumeration, IP geolocation, CVE lookup, and reverse IP — all without leaving the browser.

Built for security researchers, CTF players, and pentesters who want recon tools alongside their target, not in a separate terminal window.

→ **[brutal.net/netrecon](https://brutal.net/netrecon/)**

![NetRecon version](https://img.shields.io/badge/version-1.0.3-3fb950?style=flat-square)
![Chrome MV3](https://img.shields.io/badge/Chrome-MV3-4a6ef5?style=flat-square)
![Node.js](https://img.shields.io/badge/Node.js-18%2B-339933?style=flat-square)
![License](https://img.shields.io/badge/license-MIT-6c8fff?style=flat-square)

---

## Tools

| Tool | What it does | External API |
|---|---|---|
| Nmap Scanner | Full nmap scans with flag control and real-time streaming output | — |
| DNS Recon | Query A, MX, TXT, CNAME, NS records | — |
| WHOIS Lookup | Registrar and contact data for any domain or IP | — |
| SSL Inspector | Certificate chain, expiry, issuer, and cipher details | — |
| Port Scanner | TCP port scan with custom port ranges | — |
| HTTP Headers | Full response header inspection for any URL | — |
| Subdomain Enumerator | Enumerate subdomains via certificate transparency logs | crt.sh |
| IP Geolocation | ASN, org, ISP, and location data for any IP | ipapi.co |
| CVE Lookup | Search the NVD database by keyword or CVE ID | NVD API |
| Reverse IP | Find all domains hosted on a given IP | HackerTarget |

All results are saved to scan history automatically.

---

## How it works

NetRecon has two parts:

- **Chrome extension** — the UI, runs as a side panel (MV3)
- **Companion server** — a lightweight Node.js HTTP + WebSocket server on `localhost:31337` that handles OS-level operations browsers can't do directly

The companion server launches on demand from the extension panel — no terminal needed during normal use. It only accepts connections from `chrome-extension://` origins and binds to `127.0.0.1` only.

---

## Requirements

- Node.js >= 18
- nmap installed
- Chrome or Chromium

**macOS**
```bash
brew install node nmap
```

**Linux (Debian/Ubuntu)**
```bash
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt install -y nodejs nmap
```

**Windows**
- [nodejs.org](https://nodejs.org) — download and run the installer
- [nmap.org/download.html](https://nmap.org/download.html) — install with Npcap checked (required for SYN scans)

---

## Install

### 1. Clone the repo

```bash
git clone https://github.com/brutalnet/netrecon.git ~/netrecon
cd ~/netrecon
```

### 2. Install dependencies

```bash
npm install
```

### 3. Load the extension in Chrome

1. Go to `chrome://extensions`
2. Enable **Developer Mode** (top-right toggle)
3. Click **Load unpacked** → select the `~/netrecon` folder (the one containing `manifest.json`)

### 4. Register the native launcher — one time only

Copy your 32-character extension ID from `chrome://extensions`, then run:

```bash
node install.js YOUR_EXTENSION_ID
```

This registers the native messaging host so Chrome can launch the companion server. Re-run if you move the folder or reinstall Chrome.

### 5. Start the companion server

Open the NetRecon side panel in Chrome and click **▶ Start**. The server launches silently in the background.

To stop it: click **■ Stop** in the panel, or send a `POST` to `http://127.0.0.1:31337/shutdown`.

---

## Project structure

```
netrecon/
├── companion-server.js     # Local HTTP + WebSocket server (Node.js, port 31337)
├── launcher.js             # Native messaging host — starts/stops the server
├── install.js              # One-time setup: registers the native host with Chrome
├── manifest.json           # Chrome extension manifest (MV3)
├── popup.html              # Extension side panel HTML
├── popup.js                # Module router and app bootstrap
├── popup.css               # Extension styles
├── background.js           # MV3 service worker
├── icons/                  # Extension icons (16, 48, 128px)
├── lib/
│   ├── agent-client.js     # HTTP/WS client for the companion server
│   └── history-manager.js  # Scan history via chrome.storage.local
└── modules/                # One file per tool
    ├── nmap-scanner.js
    ├── dns-recon.js
    ├── whois-lookup.js
    ├── ssl-inspector.js
    ├── port-scanner.js
    ├── http-headers.js
    ├── subdomain-enum.js
    ├── ip-geo.js
    ├── cve-lookup.js
    ├── reverse-ip.js
    └── history-tab.js
```

---

## Security

- Companion server binds to `127.0.0.1` only — not accessible from the network
- CORS restricted to `chrome-extension://` origins
- All shell commands use `spawn()` with array arguments — no shell injection surface
- Extension `connect-src` is scoped to `127.0.0.1:31337` only
- Extension permissions: `storage`, `sidePanel`, `clipboardWrite`, `nativeMessaging` — nothing broader
- Nmap SYN scans (`-sS`) require root/sudo on Linux/macOS

---

## Contributing

Issues and PRs welcome.

For new tool modules, follow the pattern in any file under `modules/` — each module exports a class with `render()` and optionally `destroy()`. The constructor receives `{ container, agent, history }`.

---

## Legal

**Only use against systems you own or have explicit written authorisation to test.**

Unauthorized scanning or enumeration of systems you do not own is illegal in most jurisdictions. The authors accept no liability for misuse.

---

## License

[MIT](./LICENSE) — © Brutal (brutal.net)
