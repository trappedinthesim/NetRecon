// background.js — MV3 service worker
// Minimal: opens side panel on action click

chrome.sidePanel
  .setPanelBehavior({ openPanelOnActionClick: true })
  .catch(() => {});
