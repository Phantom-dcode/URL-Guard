/**
 * URL Guard - Background Service Worker (Manifest V3)
 * 
 * Provides unified, single-source URL security inspection by connecting directly
 * to the backend Random Forest ML classification engine (/api/analyze).
 * 
 * Synchronizes classification results across:
 *   1. Extension Icon Badge
 *   2. In-Page Content Script Warning Shield
 *   3. Popup Status Card & Explainer
 */

const DEFAULT_API_BASE_URL = 'http://localhost:3000';
const API_TIMEOUT_MS = 4500;

// In-memory cache for fast lookup and deduplication
const urlCache = new Map();
const inFlightRequests = new Map();

/**
 * Retrieve configured backend API base URL from chrome.storage.local
 */
async function getApiBaseUrl() {
  return new Promise((resolve) => {
    if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
      chrome.storage.local.get(['url_guard_api_url'], (res) => {
        resolve((res && res.url_guard_api_url) ? res.url_guard_api_url.trim().replace(/\/+$/, '') : DEFAULT_API_BASE_URL);
      });
    } else {
      resolve(DEFAULT_API_BASE_URL);
    }
  });
}

/**
 * Analyze a URL using the backend trained Random Forest model.
 * If backend or model is unavailable, safely marks status as "Analysis Unavailable".
 * NEVER falls back to heuristic Safe verdicts.
 */
async function analyzeUrlWithBackend(rawUrl, language = 'en') {
  if (!rawUrl || typeof rawUrl !== 'string') {
    return {
      verdict: 'Analysis Unavailable',
      score: null,
      status: 'invalid_url',
      reasons: ['No URL provided for analysis'],
      url: rawUrl || ''
    };
  }

  // Handle internal browser URLs
  if (!rawUrl.startsWith('http://') && !rawUrl.startsWith('https://')) {
    return {
      verdict: 'Internal',
      score: 0.0,
      status: 'internal_page',
      reasons: ['Internal browser or non-HTTP page'],
      url: rawUrl
    };
  }

  // Check URL cache (valid for 5 minutes)
  const cached = urlCache.get(rawUrl);
  if (cached && (Date.now() - cached.timestamp < 5 * 60 * 1000)) {
    return cached.result;
  }

  // Deduplicate concurrent requests for the exact same URL
  if (inFlightRequests.has(rawUrl)) {
    return inFlightRequests.get(rawUrl);
  }

  const analysisPromise = (async () => {
    const apiBase = await getApiBaseUrl();
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), API_TIMEOUT_MS);

    try {
      const response = await fetch(`${apiBase}/api/analyze`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: rawUrl, language }),
        signal: controller.signal
      });

      clearTimeout(timeoutId);

      if (!response.ok) {
        let errData = {};
        try { errData = await response.json(); } catch (_) {}
        const errorMsg = errData.message || `Server returned HTTP ${response.status}`;
        
        const unavailableResult = {
          verdict: 'Analysis Unavailable',
          score: null,
          status: 'backend_error',
          error: errorMsg,
          reasons: [errData.error === 'MODEL_UNAVAILABLE' ? 'Trained ML model is unavailable' : errorMsg],
          url: rawUrl,
          apiBase
        };
        return unavailableResult;
      }

      const data = await response.json();

      // Extract unified reasons from rule evidence and top SHAP model factors
      const reasons = [];
      if (data.evidence && Array.isArray(data.evidence.rules)) {
        for (const r of data.evidence.rules) {
          reasons.push(r.name || r.id);
        }
      }
      if (data.evidence && Array.isArray(data.evidence.model_factors)) {
        for (const f of data.evidence.model_factors) {
          if (f.attribution > 0.015 && reasons.length < 5) {
            reasons.push(f.human_name || f.feature_name);
          }
        }
      }

      const unifiedResult = {
        verdict: data.verdict || 'Analysis Unavailable',
        score: typeof data.model?.score === 'number' ? data.model.score : null,
        status: 'success',
        normalized_url: data.normalized_url || rawUrl,
        verdict_basis: data.verdict_basis,
        confidence_band: data.confidence_band,
        operational_thresholds: data.operational_thresholds,
        reasons: reasons.length > 0 ? reasons : ['No threat indicators detected by trained ML model'],
        simple_explanation: data.simple_explanation || null,
        evidence: data.evidence,
        url: rawUrl,
        apiBase
      };

      // Cache successful response
      urlCache.set(rawUrl, {
        timestamp: Date.now(),
        result: unifiedResult
      });

      return unifiedResult;
    } catch (err) {
      clearTimeout(timeoutId);
      const isAbort = err.name === 'AbortError';
      const failReason = isAbort 
        ? 'Request timed out connecting to backend ML server'
        : (err.message || 'Unable to connect to URL Guard backend');

      const unavailableResult = {
        verdict: 'Analysis Unavailable',
        score: null,
        status: 'network_failure',
        error: failReason,
        reasons: ['Backend analysis server or trained ML model unreachable'],
        url: rawUrl,
        apiBase
      };
      return unavailableResult;
    } finally {
      inFlightRequests.delete(rawUrl);
    }
  })();

  inFlightRequests.set(rawUrl, analysisPromise);
  return analysisPromise;
}

/**
 * Update Chrome extension badge and title for a specific tab
 */
function updateTabBadge(tabId, result) {
  if (typeof chrome === 'undefined' || !chrome.action) return;

  if (!result || result.verdict === 'Internal') {
    chrome.action.setBadgeText({ tabId, text: '' });
    chrome.action.setTitle({ tabId, title: 'URL Guard - AI URL Protection' });
    return;
  }

  const { verdict, score } = result;

  if (verdict === 'Malicious') {
    chrome.action.setBadgeText({ tabId, text: '✕' });
    chrome.action.setBadgeBackgroundColor({ tabId, color: '#ef4444' });
    const scoreStr = typeof score === 'number' ? ` (${score.toFixed(2)})` : '';
    chrome.action.setTitle({ tabId, title: `URL Guard: MALICIOUS${scoreStr} - Danger` });
  } else if (verdict === 'Suspicious') {
    chrome.action.setBadgeText({ tabId, text: '!' });
    chrome.action.setBadgeBackgroundColor({ tabId, color: '#f59e0b' });
    const scoreStr = typeof score === 'number' ? ` (${score.toFixed(2)})` : '';
    chrome.action.setTitle({ tabId, title: `URL Guard: SUSPICIOUS${scoreStr} - Caution` });
  } else if (verdict === 'Safe') {
    chrome.action.setBadgeText({ tabId, text: 'OK' });
    chrome.action.setBadgeBackgroundColor({ tabId, color: '#10b981' });
    const scoreStr = typeof score === 'number' ? ` (${score.toFixed(2)})` : '';
    chrome.action.setTitle({ tabId, title: `URL Guard: SAFE${scoreStr}` });
  } else {
    // Analysis Unavailable - Never show Safe!
    chrome.action.setBadgeText({ tabId, text: '?' });
    chrome.action.setBadgeBackgroundColor({ tabId, color: '#64748b' });
    chrome.action.setTitle({ tabId, title: 'URL Guard: Analysis Unavailable (Backend server offline)' });
  }
}

/**
 * Handle Tab URL Security Inspection & Storage Synchronization
 */
async function processTabSecurity(tabId, url) {
  if (!url || (!url.startsWith('http://') && !url.startsWith('https://'))) {
    updateTabBadge(tabId, { verdict: 'Internal' });
    if (chrome.storage && chrome.storage.local) {
      chrome.storage.local.remove([`tab_${tabId}`]);
    }
    return;
  }

  // Set badge to evaluating state briefly
  chrome.action.setBadgeText({ tabId, text: '...' });
  chrome.action.setBadgeBackgroundColor({ tabId, color: '#334155' });

  const result = await analyzeUrlWithBackend(url);

  // Synchronize result in chrome.storage.local using consistent key schema
  if (chrome.storage && chrome.storage.local) {
    chrome.storage.local.set({
      [`tab_${tabId}`]: result,
      [`url_${encodeURIComponent(url)}`]: result
    });
  }

  // Update action badge
  updateTabBadge(tabId, result);

  // Notify active content script in this tab of the synchronized classification
  try {
    chrome.tabs.sendMessage(tabId, {
      action: 'URL_GUARD_UPDATE',
      tabId,
      result
    }).catch(() => {
      // Content script may not be loaded yet; it will fetch via GET_TAB_ANALYSIS on load
    });
  } catch (_) {}

  return result;
}

// Tab navigation listener
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === 'complete' && tab.url) {
    processTabSecurity(tabId, tab.url);
  } else if (changeInfo.url) {
    processTabSecurity(tabId, changeInfo.url);
  }
});

// Tab activation listener
chrome.tabs.onActivated.addListener((activeInfo) => {
  chrome.tabs.get(activeInfo.tabId, (tab) => {
    if (tab && tab.url) {
      // If we already have stored tab state, restore badge immediately
      chrome.storage.local.get([`tab_${activeInfo.tabId}`], (data) => {
        const stored = data[`tab_${activeInfo.tabId}`];
        if (stored && stored.url === tab.url) {
          updateTabBadge(activeInfo.tabId, stored);
        } else {
          processTabSecurity(activeInfo.tabId, tab.url);
        }
      });
    }
  });
});

// Message listener for popup & content script communication
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (!message || typeof message !== 'object') return false;

  const tabId = message.tabId || sender.tab?.id;
  const targetUrl = message.url || sender.tab?.url;

  if (message.action === 'GET_TAB_ANALYSIS') {
    (async () => {
      if (tabId) {
        const storedData = await new Promise((res) => {
          chrome.storage.local.get([`tab_${tabId}`], res);
        });
        const stored = storedData[`tab_${tabId}`];
        if (stored && (!targetUrl || stored.url === targetUrl)) {
          sendResponse({ success: true, result: stored });
          return;
        }
      }

      if (targetUrl) {
        const result = await analyzeUrlWithBackend(targetUrl, message.language || 'en');
        if (tabId) {
          chrome.storage.local.set({ [`tab_${tabId}`]: result });
          updateTabBadge(tabId, result);
        }
        sendResponse({ success: true, result });
      } else {
        sendResponse({
          success: false,
          result: {
            verdict: 'Analysis Unavailable',
            score: null,
            status: 'no_url',
            reasons: ['No URL specified']
          }
        });
      }
    })();
    return true; // Keep message channel open for async response
  }

  if (message.action === 'ANALYZE_URL') {
    (async () => {
      const result = await analyzeUrlWithBackend(message.url, message.language || 'en');
      if (tabId) {
        chrome.storage.local.set({ [`tab_${tabId}`]: result });
        updateTabBadge(tabId, result);
      }
      sendResponse({ success: true, result });
    })();
    return true;
  }

  if (message.action === 'GET_API_CONFIG') {
    (async () => {
      const apiUrl = await getApiBaseUrl();
      sendResponse({ success: true, apiUrl });
    })();
    return true;
  }

  if (message.action === 'SET_API_CONFIG') {
    (async () => {
      const newUrl = (message.apiUrl || '').trim().replace(/\/+$/, '') || DEFAULT_API_BASE_URL;
      chrome.storage.local.set({ url_guard_api_url: newUrl }, () => {
        // Clear caches so fresh analysis uses the new backend
        urlCache.clear();
        sendResponse({ success: true, apiUrl: newUrl });
      });
    })();
    return true;
  }

  return false;
});
