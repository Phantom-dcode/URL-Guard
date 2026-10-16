/**
 * URL Guard - In-Page Content Script
 * 
 * Synchronizes with the background service worker and backend ML model to display
 * in-page warning shields for Suspicious and Malicious sites.
 * 
 * Uses the exact same classification result as the extension badge and popup.
 * Does NOT run independent duplicate heuristic checks.
 */

(function () {
  const currentUrl = window.location.href;
  if (!currentUrl || (!currentUrl.startsWith('http://') && !currentUrl.startsWith('https://'))) {
    return;
  }

  const BANNER_ID = 'url-guard-inpage-banner';

  function removeBanner() {
    const existing = document.getElementById(BANNER_ID);
    if (existing) {
      existing.remove();
    }
  }

  function showSecurityBanner(result) {
    if (!result) return;
    const { verdict, score, reasons = [] } = result;

    // Only display in-page warnings for Malicious or Suspicious verdicts
    if (verdict !== 'Malicious' && verdict !== 'Suspicious') {
      removeBanner();
      return;
    }

    if (document.getElementById(BANNER_ID)) {
      // Update existing banner rather than creating duplicate
      removeBanner();
    }

    const isMalicious = verdict === 'Malicious';
    const themeColor = isMalicious ? '#ef4444' : '#f59e0b';
    const bgColor = '#090d16';
    const scoreText = typeof score === 'number' ? ` (Risk Score: ${score.toFixed(2)})` : '';
    const headline = isMalicious 
      ? `Malicious Website Detected${scoreText}`
      : `Suspicious Website Warning${scoreText}`;

    const warningAdvice = isMalicious
      ? 'This page has been identified as high-risk malicious infrastructure by URL Guard ML. Never enter passwords, banking details, or OTPs. Close this tab immediately!'
      : 'URL Guard detected unusual infrastructure characteristics on this page. Exercise caution and do not enter sensitive passwords, OTPs, or payment information.';

    const primaryReason = reasons && reasons.length > 0 ? reasons[0] : (isMalicious ? 'High-risk infrastructure patterns' : 'Unusual domain signals');

    const banner = document.createElement('div');
    banner.id = BANNER_ID;
    banner.setAttribute('role', 'alert');
    banner.style.cssText = `
      position: fixed;
      top: 16px;
      right: 16px;
      max-width: 400px;
      width: calc(100vw - 32px);
      z-index: 2147483647;
      background: ${bgColor};
      color: #f1f5f9;
      border: 1px solid ${themeColor};
      border-left: 6px solid ${themeColor};
      padding: 14px 16px;
      border-radius: 12px;
      box-shadow: 0 12px 30px rgba(0, 0, 0, 0.7);
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
      font-size: 13px;
      line-height: 1.45;
      box-sizing: border-box;
      pointer-events: auto;
    `;

    banner.innerHTML = `
      <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:8px;">
        <div style="font-weight:700;color:${themeColor};display:flex;align-items:center;gap:7px;font-size:13px;">
          <span style="font-size:16px;">${isMalicious ? '🚨' : '⚠️'}</span>
          <span>${headline}</span>
        </div>
        <button id="url-guard-close-btn" title="Dismiss" style="background:none;border:none;color:#94a3b8;font-size:16px;cursor:pointer;padding:2px 6px;line-height:1;">✕</button>
      </div>

      <div style="color:#cbd5e1;font-size:12px;margin-bottom:8px;">
        ${warningAdvice}
      </div>

      <div style="background:rgba(255,255,255,0.04);border:1px solid rgba(255,255,255,0.08);border-radius:6px;padding:6px 8px;margin-bottom:10px;font-size:11px;color:#94a3b8;">
        <span style="color:#e2e8f0;font-weight:600;">Detection factor:</span> ${primaryReason}
      </div>

      <div style="display:flex;align-items:center;justify-content:space-between;gap:8px;">
        <span style="font-size:10px;color:#64748b;text-transform:uppercase;letter-spacing:0.5px;font-weight:600;">URL Guard Protection</span>
        <button id="url-guard-dismiss-btn" style="background:#1e293b;border:1px solid #334155;color:#f8fafc;font-size:11px;padding:5px 12px;border-radius:6px;cursor:pointer;font-weight:600;">
          I Understand
        </button>
      </div>
    `;

    // Ensure DOM is ready before appending
    if (document.body) {
      document.body.appendChild(banner);
    } else {
      document.addEventListener('DOMContentLoaded', () => {
        document.body.appendChild(banner);
      });
    }

    const closeBtn = banner.querySelector('#url-guard-close-btn');
    const dismissBtn = banner.querySelector('#url-guard-dismiss-btn');
    if (closeBtn) closeBtn.addEventListener('click', () => banner.remove());
    if (dismissBtn) dismissBtn.addEventListener('click', () => banner.remove());
  }

  // Request unified tab classification from the background service worker
  if (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.sendMessage) {
    chrome.runtime.sendMessage({
      action: 'GET_TAB_ANALYSIS',
      url: currentUrl
    }, (response) => {
      if (chrome.runtime.lastError) {
        return;
      }
      if (response && response.success && response.result) {
        showSecurityBanner(response.result);
      }
    });

    // Listen for live classification updates pushed by background
    chrome.runtime.onMessage.addListener((message) => {
      if (message && message.action === 'URL_GUARD_UPDATE' && message.result) {
        showSecurityBanner(message.result);
      }
    });
  }
})();
