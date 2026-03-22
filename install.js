#!/usr/bin/env node
/**
 * NetRecon Native Messaging Host Installer
 * ─────────────────────────────────────────────────────────────────────────────
 * Run this once after loading the extension in Chrome:
 *
 *   node install.js <your-extension-id>
 *
 * Find your extension ID at chrome://extensions (the 32-character string
 * under the NetRecon card when Developer Mode is on).
 *
 * What this does:
 *   1. Creates a thin wrapper script (launcher.sh / launcher.bat) that Chrome
 *      can execute as a native messaging host.
 *   2. Writes the Chrome native messaging manifest to the correct OS path.
 *   3. On Windows, also adds the required registry key.
 *
 * To uninstall: node install.js --uninstall
 */

'use strict';

const fs   = require('fs');
const path = require('path');
const os   = require('os');
const { execSync } = require('child_process');

const HOST_NAME = 'net.brutal.netrecon';
const HERE      = __dirname;
const NODE      = process.execPath;
const PLATFORM  = os.platform();

// ── Helpers ───────────────────────────────────────────────────────────────────

function die(msg) { console.error(`\n  ✗  ${msg}\n`); process.exit(1); }
function ok(msg)  { console.log(`  ✓  ${msg}`); }

function chromeNativeHostDir() {
  if (PLATFORM === 'darwin') {
    return path.join(os.homedir(), 'Library/Application Support/Google/Chrome/NativeMessagingHosts');
  }
  if (PLATFORM === 'linux') {
    return path.join(os.homedir(), '.config/google-chrome/NativeMessagingHosts');
  }
  if (PLATFORM === 'win32') {
    return path.join(HERE); // on Windows the manifest path goes in the registry
  }
  die(`Unsupported platform: ${PLATFORM}`);
}

// ── Uninstall ─────────────────────────────────────────────────────────────────

if (process.argv[2] === '--uninstall') {
  const manifestPath = path.join(chromeNativeHostDir(), `${HOST_NAME}.json`);
  if (fs.existsSync(manifestPath)) { fs.unlinkSync(manifestPath); ok(`Removed ${manifestPath}`); }

  if (PLATFORM !== 'win32') {
    const wrapper = path.join(HERE, 'launcher.sh');
    if (fs.existsSync(wrapper)) { fs.unlinkSync(wrapper); ok('Removed launcher.sh'); }
  } else {
    const wrapper = path.join(HERE, 'launcher.bat');
    if (fs.existsSync(wrapper)) { fs.unlinkSync(wrapper); ok('Removed launcher.bat'); }
    try {
      execSync(`reg delete "HKCU\\Software\\Google\\Chrome\\NativeMessagingHosts\\${HOST_NAME}" /f`, { stdio: 'pipe' });
      ok('Removed registry key');
    } catch { /* already gone */ }
  }

  console.log('\n  Native messaging host uninstalled.\n');
  process.exit(0);
}

// ── Install ───────────────────────────────────────────────────────────────────

const extensionId = process.argv[2];
if (!extensionId || !/^[a-z]{32}$/.test(extensionId)) {
  console.log(`
  Usage:   node install.js <extension-id>
  Remove:  node install.js --uninstall

  Find your extension ID at chrome://extensions
  (the 32-character lowercase string under the NetRecon card).

  Example: node install.js abcdefghijklmnopabcdefghijklmnop
`);
  process.exit(1);
}

const launcherScript = path.join(HERE, 'launcher.js');
if (!fs.existsSync(launcherScript)) die('launcher.js not found — make sure you\'re running from the netrecon folder.');

console.log(`\n  Installing NetRecon native messaging host…\n`);

let wrapperPath;

if (PLATFORM === 'win32') {
  // Windows: .bat wrapper
  wrapperPath = path.join(HERE, 'launcher.bat');
  fs.writeFileSync(wrapperPath, `@echo off\r\n"${NODE}" "${launcherScript}"\r\n`);
  ok(`Created launcher.bat`);
} else {
  // macOS / Linux: shell wrapper
  wrapperPath = path.join(HERE, 'launcher.sh');
  fs.writeFileSync(wrapperPath, `#!/bin/bash\n"${NODE}" "${launcherScript}"\n`);
  fs.chmodSync(wrapperPath, '755');
  ok(`Created launcher.sh`);
}

const manifest = {
  name:            HOST_NAME,
  description:     'NetRecon Companion Server Launcher',
  path:            wrapperPath,
  type:            'stdio',
  allowed_origins: [`chrome-extension://${extensionId}/`],
};

if (PLATFORM === 'win32') {
  // Windows: write manifest next to the extension, register path in registry
  const manifestPath = path.join(HERE, `${HOST_NAME}.json`);
  fs.writeFileSync(manifestPath, JSON.stringify(manifest, null, 2));
  ok(`Wrote ${manifestPath}`);

  const regKey = `HKCU\\Software\\Google\\Chrome\\NativeMessagingHosts\\${HOST_NAME}`;
  try {
    execSync(`reg add "${regKey}" /ve /d "${manifestPath}" /f`, { stdio: 'pipe' });
    ok(`Registered in Windows registry`);
  } catch (e) {
    die(`Could not write registry key — try running as Administrator\n     ${e.message}`);
  }
} else {
  // macOS / Linux: write manifest to Chrome's expected directory
  const hostDir = chromeNativeHostDir();
  fs.mkdirSync(hostDir, { recursive: true });
  const manifestPath = path.join(hostDir, `${HOST_NAME}.json`);
  fs.writeFileSync(manifestPath, JSON.stringify(manifest, null, 2));
  ok(`Wrote ${manifestPath}`);
}

console.log(`
  ✓  Done! Native messaging host registered for:
     Extension ID: ${extensionId}

  From now on you can start the companion server directly
  from the NetRecon extension — no terminal needed.
`);
