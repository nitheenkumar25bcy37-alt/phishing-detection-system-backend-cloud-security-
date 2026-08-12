/**
 * content.js — Member 2: Webpage & DOM Analysis
 *
 * This script runs automatically on every page the user visits (injected by
 * the extension's manifest.json / service worker — that's Member 6's job).
 *
 * Its ONLY responsibility: look at the page's HTML *structure* and count a
 * few phishing-relevant signals. It never reads what the user types, never
 * touches cookies, and never captures page text/content — just structural
 * counts, per the privacy rules in the project blueprint.
 */

function extractPageFeatures() {
  // --- 1. Count all <form> elements on the page ---
  const forms = document.querySelectorAll('form');
  const formCount = forms.length;

  // --- 2. Count password input fields ---
  // These are the highest-signal phishing indicator: a page asking for a
  // password is exactly what an attacker wants.
  const passwordFields = document.querySelectorAll('input[type="password"]');
  const passwordFieldCount = passwordFields.length;

  // --- 3. Count hidden iframes ---
  // Phishing kits sometimes hide iframes (used for tracking pixels, cloaking,
  // or loading malicious content invisibly). We flag any iframe that's
  // effectively invisible to the user.
  const allIframes = document.querySelectorAll('iframe');
  let hiddenIframeCount = 0;

  allIframes.forEach((iframe) => {
    const style = window.getComputedStyle(iframe);
    const isZeroSize =
      iframe.width === '0' ||
      iframe.height === '0' ||
      style.width === '0px' ||
      style.height === '0px';
    const isHiddenByCSS =
      style.display === 'none' ||
      style.visibility === 'hidden' ||
      parseFloat(style.opacity) === 0;
    const isHiddenAttr = iframe.hidden === true;

    if (isZeroSize || isHiddenByCSS || isHiddenAttr) {
      hiddenIframeCount++;
    }
  });

  // --- 4. Check if any form submits to an external domain ---
  // A login form on "yourbank.com" that actually POSTs credentials to
  // "totally-different-domain.ru" is a textbook phishing pattern.
  let hasExternalAction = false;

  forms.forEach((form) => {
    // form.action can be relative ("/login") or absolute
    // ("https://evil.com/steal"). Resolving against window.location.href
    // normalizes both cases so we can compare hostnames fairly.
    try {
      const actionURL = new URL(form.action || window.location.href, window.location.href);
      if (actionURL.hostname && actionURL.hostname !== window.location.hostname) {
        hasExternalAction = true;
      }
    } catch (err) {
      // Malformed/empty action attribute — ignore rather than crash the script.
    }
  });

  // --- 5. Package everything into the exact API contract shape ---
  // This must match what Member 5's FastAPI /scan endpoint expects.
  return {
    url: window.location.href,
    page_features: {
      form_count: formCount,
      password_fields: passwordFieldCount,
      hidden_iframes: hiddenIframeCount,
      has_external_action: hasExternalAction,
    },
  };
}

/**
 * Sends the extracted features to the background service worker (Member 6's
 * code), which forwards them to the backend /scan endpoint. Content scripts
 * can't call fetch() directly to arbitrary backend URLs in Manifest V3 best
 * practice, so we relay through chrome.runtime.sendMessage instead.
 */
function sendFeaturesToBackground() {
  const payload = extractPageFeatures();

  chrome.runtime.sendMessage(
    {
      type: 'PAGE_SCAN_REQUEST',
      payload,
    },
    (response) => {
      if (chrome.runtime.lastError) {
        console.error('Phishing Guard: failed to reach background script', chrome.runtime.lastError);
        return;
      }
      // response handling (e.g. rendering a warning overlay) is Member 6's
      // territory — this file's job ends at sending the data.
      console.log('Phishing Guard: scan request sent', payload);
    }
  );
}

// Run once the DOM is fully parsed. Using DOMContentLoaded (rather than
// firing immediately) ensures forms/iframes added by inline scripts near
// the top of the page are already present when we count them.
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', sendFeaturesToBackground);
} else {
  sendFeaturesToBackground();
}
