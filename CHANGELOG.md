# Changelog

All notable changes to NetRecon are documented here.

---

## [1.0.3] — March 2026

### Fixed
- **Stop button still showed "Agent Online" after stopping.** The HTTP shutdown was silently failing against older server versions that don't have the `/shutdown` endpoint. The stop button now falls back to a native messaging force-kill (`lsof -ti tcp:31337 | xargs kill -9`) if the server is still alive after the graceful attempt — works against any server version.

- **Scans still showed "Scan complete — 0.0s" after re-downloading.** The old server remained running because the native launcher detects an existing process on port 31337 and skips starting a new one. Re-running `node install.js <ext-id>` re-registers the native host after extracting a new zip. Kill the old process first: `pkill -f companion-server.js`, then click ▶ Start.

---

## [1.0.2] — March 2026

### Fixed
- **Nmap / Port Scanner still showed "Scan complete — 0.0s" with zero results.** Replaced PATH-based nmap lookup with direct filesystem detection. The server now checks all known install locations (`/opt/homebrew/bin/nmap`, `/usr/local/bin/nmap`, `/usr/bin/nmap`, etc.) at startup and spawns nmap using its absolute path — no longer dependent on PATH inheritance from Chrome.

- **Stop button showed "Agent Online" after stopping.** The shutdown handler now exits the process after 150ms (enough to flush the response) instead of waiting for keep-alive connections to drain. The extension also waits longer before re-polling to confirm the process has fully exited.

### Added
- **Stop button added to the extension.** When the agent is online, a ■ Stop button appears in the status bar so you can shut down the companion server from within the extension — no terminal needed.

- **`/health` now reports the resolved nmap path.** Open `http://127.0.0.1:31337/health` to see which nmap binary the server found at startup, making path issues easier to diagnose.

---

## [1.0.1] — March 2026

### Fixed
- **Nmap / Port Scanner returned "Scan complete — 0.0s" instantly.** When Chrome launches the companion server via native messaging it passes a minimal `PATH` that omits Homebrew (`/opt/homebrew/bin`) and `/usr/local/bin`. Added PATH augmentation at server startup so nmap is found correctly.

- **Scan error was immediately overwritten by "Scan complete".** When nmap is missing, Node.js fires both the `error` and `close` events — the `done` message was reaching the UI last and wiping the error. Added an `errorSent` guard to both nmap and port-scan handlers so `close` is silenced after an error.

- **▶ Start button reported success before the server was actually up.** The native launcher now polls `/health` for up to 4 seconds after spawning the companion server, only reporting success once it gets a 200 response. If the server doesn't come up in time it returns the last few lines of the log as a hint.

- **"Failed to load extension — Could not load icon 'icons/icon16.png'".** Extension icons were missing from the download zip. Icons are now bundled at `icons/icon16.png`, `icon48.png`, and `icon128.png`.

- **"Bad request / requires agent" on most tools.** The companion server crashed on startup with "Cannot find module 'express'" because `node_modules` were not included in the zip. Dependencies are now pre-bundled — no `npm install` step needed for zip installs.

- **macOS: "EPERM: process.cwd failed" when running `node install.js`.** macOS applies a TCC sandbox restriction on the Downloads folder that blocks Node.js from reading its own working directory. Instructions updated — extract to `~/netrecon` before running the installer.

---

## [1.0.0] — March 2026 — Initial release

### Added
- 10 security tools in a Chrome side panel: Nmap Scanner, Port Scanner, DNS Recon, WHOIS, SSL Inspector, HTTP Headers, Subdomain Enumerator, IP Geolocation, CVE Lookup, and Reverse IP.
- Chrome Native Messaging integration — companion server starts from the extension with one click. No terminal needed after initial setup.
- Scan history saved automatically via `chrome.storage.local`.
- WebSocket streaming for real-time nmap output.
- Local companion server binds to `127.0.0.1:31337` only, restricted to `chrome-extension://` origins.
