/**
 * background.js — Service Worker (normally Member 6's territory, but a
 * minimal version is included here so Member 2 can test end-to-end without
 * waiting on the full extension to be built).
 *
 * Job: receive the message that content.js sends, forward it to the
 * backend's /scan endpoint, and log/react to the response.
 */

const BACKEND_URL = 'http://localhost:8000/scan';

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type !== 'PAGE_SCAN_REQUEST') {
    return false; // not our message, ignore
  }

  console.log('[background] Received page features:', message.payload);

  fetch(BACKEND_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(message.payload),
  })
    .then((res) => res.json())
    .then((result) => {
      console.log('[background] Backend response:', result);
      sendResponse({ ok: true, result });
    })
    .catch((err) => {
      console.error('[background] Failed to reach backend:', err);
      sendResponse({ ok: false, error: String(err) });
    });

  // Returning true keeps the message channel open for the async fetch above
  return true;
});
