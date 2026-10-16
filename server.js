/**
 * URL-Guard Full-Stack Node.js Server.
 * 
 * Provides:
 *   - POST /api/analyze: Pure string-only URL inspection and threat classification
 *   - GET  /api/model-info: Metrics for both domain-grouped and random splits
 *   - GET  /api/health: Operational health check
 *   - GET  /: Serves the static cyber defense dashboard
 * 
 * Runs natively in Node.js on port 3000, ensuring 100% compatibility with
 * Google Cloud Run deployment environments.
 */

import express from 'express';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { generateSimpleExplanation } from './app/explainer.js';
import { classifyScore, makeDecision } from './app/classifier.js';
export { classifyScore, makeDecision };

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
app.use(express.json({ limit: '10kb' }));

// Cross-Origin Resource Sharing (CORS) headers for public extension & API clients
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') {
    return res.sendStatus(200);
  }
  next();
});

const PORT = process.env.PORT ? parseInt(process.env.PORT, 10) : 3000;
const HOST = process.env.HOST || '0.0.0.0';

// In-memory rate limiter: max 60 requests per minute per IP
const rateLimitMap = new Map();
function rateLimiter(req, res, next) {
  const ip = req.ip || req.connection.remoteAddress || '127.0.0.1';
  const now = Date.now();
  const windowMs = 60 * 1000;
  const userRecord = rateLimitMap.get(ip) || { count: 0, resetTime: now + windowMs };

  if (now > userRecord.resetTime) {
    userRecord.count = 0;
    userRecord.resetTime = now + windowMs;
  }

  userRecord.count++;
  rateLimitMap.set(ip, userRecord);

  // Allow unlimited requests in test environments or higher ceiling for local health/test runners
  if (process.env.NODE_ENV === 'test' || ip === '127.0.0.1' || ip === '::1' || ip === '::ffff:127.0.0.1') {
    return next();
  }

  if (userRecord.count > 60) {
    return res.status(429).json({
      error: 'RATE_LIMIT_EXCEEDED',
      message: 'Too many requests. Limit is 60 requests per minute.'
    });
  }
  next();
}

// Load Model Artifacts
const MODELS_DIR = path.join(__dirname, 'models');
const DATA_DIR = path.join(__dirname, 'data');

let modelExport = null;
let metricsData = {};
let thresholdsData = { low_threshold: 0.38, high_threshold: 0.81 };
let localFeedSet = new Set();

try {
  const exportPath = path.join(MODELS_DIR, 'model_export.json');
  if (fs.existsSync(exportPath)) {
    modelExport = JSON.parse(fs.readFileSync(exportPath, 'utf8'));
    console.log(`[URL-Guard] Loaded model export: ${modelExport.feature_names.length} features.`);
  }

  const metricsPath = path.join(MODELS_DIR, 'metrics.json');
  if (fs.existsSync(metricsPath)) {
    metricsData = JSON.parse(fs.readFileSync(metricsPath, 'utf8'));
  }

  const threshPath = path.join(MODELS_DIR, 'thresholds.json');
  if (fs.existsSync(threshPath)) {
    thresholdsData = JSON.parse(fs.readFileSync(threshPath, 'utf8'));
  }

  const feedPath = path.join(DATA_DIR, 'intel_feed.txt');
  if (fs.existsSync(feedPath)) {
    const lines = fs.readFileSync(feedPath, 'utf8').split('\n');
    for (const l of lines) {
      const clean = l.trim().toLowerCase();
      if (clean && !clean.startsWith('#')) {
        localFeedSet.add(clean);
      }
    }
    console.log(`[URL-Guard] Loaded ${localFeedSet.size} local IOC indicators into memory.`);
  }
} catch (e) {
  console.error('[URL-Guard] Warning while loading artifacts:', e.message);
}

// Targeted Brands for Brand Mismatch & Typosquatting Heuristics
const BRAND_TARGETS = new Set([
  'google', 'apple', 'microsoft', 'paypal', 'amazon', 'netflix', 'facebook',
  'instagram', 'chase', 'wellsfargo', 'binance', 'coinbase', 'bankofamerica',
  'ebay', 'dropbox', 'adobe', 'walmart', 'twitter', 'linkedin', 'steam',
  'roblox', 'telegram', 'whatsapp', 'citibank', 'dhl', 'fedex', 'usps',
  // Indian Banking, Fintech & Critical Public Services
  'sbi', 'onlinesbi', 'hdfc', 'hdfcbank', 'icici', 'icicibank', 'axisbank', 'kotak',
  'pnb', 'bankofbaroda', 'canarabank', 'paytm', 'phonepe', 'gpay', 'cred', 'bhim',
  'aadhaar', 'uidai', 'incometax', 'epfindia', 'irctc', 'parivahan', 'digilocker',
  'flipkart', 'swiggy', 'zomato', 'meesho', 'myntra', 'airtel', 'jio', 'hotstar'
]);

const SUSPICIOUS_TOKENS = [
  'login', 'verify', 'secure', 'account', 'update', 'signin', 'banking',
  'wallet', 'password', 'confirm',
  // High-Risk Fraud, KYC & Impersonation Tokens
  'kyc', 'pan', 'aadhaar', 'otp', 'reward', 'cashback', 'lottery', 'refund',
  'unblock', 'debit', 'credit', 'claim', 'bonus', 'subsidy', 'yojana', 'recharge'
];

const SHORTENER_DOMAINS = new Set([
  'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly',
  'adf.ly', 'bit.do', 'cutt.ly', 'rebrand.ly', 'shorte.st', 'tiny.cc', 'rb.gy', 'v.gd'
]);

const HIGH_RISK_TLDS = new Set([
  'xyz', 'top', 'tk', 'ml', 'ga', 'cf', 'gq', 'fit', 'work', 'loan',
  'click', 'country', 'racing', 'download', 'stream', 'science', 'bid',
  'party', 'win', 'cricket', 'trade', 'accountant', 'date', 'faith',
  'review', 'zip', 'mov', 'buzz', 'surf', 'live', 'gdn', 'men',
  'icu', 'vip', 'monster', 'cfd', 'sbs', 'quest', 'beauty', 'skin', 'cam'
]);

const COMMON_TLDS = new Set([
  'com', 'org', 'net', 'edu', 'gov', 'mil', 'int', 'info'
]);

const RISKY_EXTENSIONS = [
  '.exe', '.scr', '.zip', '.apk', '.bat', '.cmd', '.iso', '.vbs',
  '.ps1', '.sh', '.msi', '.dll', '.hta', '.jar', '.reg', '.rar', '.7z'
];

// Human-friendly feature labels
const FEATURE_HUMAN_NAMES = {
  url_length: 'Overall URL Character Length',
  host_length: 'Hostname Character Length',
  path_length: 'Path Character Length',
  query_length: 'Query String Length',
  dot_count: 'Count of Dots (.) in URL',
  subdomain_count: 'Number of Subdomain Levels',
  path_depth: 'Path Directory Depth',
  query_param_count: 'Number of Query Parameters',
  count_hyphen: 'Count of Hyphens (-)',
  count_at: "Userinfo '@' Symbol Count",
  count_question: 'Question Mark Count',
  count_ampersand: 'Ampersand (&) Count',
  count_equal: 'Equal Sign (=) Count',
  count_percent: 'Percent Encoded Symbol (%) Count',
  count_underscore: 'Underscore (_) Count',
  count_tilde: 'Tilde (~) Count',
  double_slash_in_path: 'Unescaped Double Slash (//) in Path',
  digit_ratio: 'Proportion of Numeric Digits in URL',
  host_hyphen_count: 'Hyphens in Hostname',
  host_digit_count: 'Numeric Digits in Hostname',
  is_ip_host: 'Direct IP Address as Hostname',
  non_standard_port: 'Non-Standard Port Specified',
  is_punycode: 'Punycode (xn--) / Homograph Indicator',
  has_non_ascii: 'Non-ASCII Characters in URL',
  percent_encoded_count: 'Count of Hex Percent Sequences',
  suspicious_token_count: 'Credential / Security Keyword Tokens',
  brand_mismatch: 'Brand in Subdomain/Path (Mismatch)',
  tld_category: 'Top-Level Domain (TLD) Risk Profile',
  is_shortener: 'URL Shortener Service Domain',
  host_entropy: 'Hostname Shannon Character Entropy',
  longest_digit_run: 'Longest Sequence of Consecutive Digits',
  https_token_in_host: "Deceptive 'http/https' Token in Host",
  risky_file_extension: 'Dangerous File Extension (.exe/.zip/.sh)',
  is_https: 'HTTPS Encrypted Protocol Flag',
};

// Helper: Calculate Shannon entropy of text
function calculateEntropy(str) {
  if (!str) return 0.0;
  const len = str.length;
  const counts = {};
  for (let i = 0; i < len; i++) {
    const ch = str[i];
    counts[ch] = (counts[ch] || 0) + 1;
  }
  let ent = 0.0;
  for (const ch in counts) {
    const p = counts[ch] / len;
    ent -= p * Math.log2(p);
  }
  return parseFloat(ent.toFixed(4));
}

// Helper: Check if host is an IP address
function isIpAddress(host) {
  const clean = host.replace(/[\[\]]/g, '').toLowerCase();
  // IPv4 dotted-quad
  const parts = clean.split('.');
  if (parts.length === 4 && parts.every(p => /^\d+$/.test(p) && parseInt(p, 10) >= 0 && parseInt(p, 10) <= 255)) {
    return true;
  }
  // Pure integer decimal IP
  if (/^\d+$/.test(clean) && parseInt(clean, 10) <= 0xffffffff) {
    return true;
  }
  // Hex IP
  if (clean.startsWith('0x')) {
    return true;
  }
  return false;
}

// Step 1: URL Validation and Normalization
function validateAndNormalizeUrl(rawUrl) {
  if (typeof rawUrl !== 'string') {
    throw { code: 'TYPE_ERROR', message: 'URL must be a text string.' };
  }
  const stripped = rawUrl.trim();
  if (!stripped) {
    throw { code: 'EMPTY_URL', message: 'URL cannot be empty.' };
  }
  if (stripped.length > 2048) {
    throw { code: 'EXCEEDS_MAX_LENGTH', message: `URL exceeds maximum length of 2048 characters (got ${stripped.length}).` };
  }
  if (/[\x00-\x1f\x7f]/.test(stripped)) {
    throw { code: 'CONTROL_CHAR_DETECTED', message: 'URL contains disallowed control characters.' };
  }
  if (/\s/.test(stripped)) {
    throw { code: 'WHITESPACE_DETECTED', message: 'URL contains unencoded whitespace.' };
  }

  let parsed;
  try {
    parsed = new URL(stripped);
  } catch (e) {
    throw { code: 'PARSE_ERROR', message: `Invalid URL format: ${e.message}` };
  }

  const scheme = parsed.protocol.replace(':', '').toLowerCase();
  if (scheme !== 'http' && scheme !== 'https') {
    throw { code: 'UNSUPPORTED_SCHEME', message: `Unsupported scheme '${scheme}'. URL-Guard only accepts 'http' or 'https'.` };
  }

  const hostRaw = parsed.hostname;
  if (!hostRaw) {
    throw { code: 'EMPTY_HOST', message: 'Hostname cannot be empty.' };
  }

  const hasNonAscii = /[^\x00-\x7F]/.test(stripped);
  const isPunycode = hostRaw.toLowerCase().includes('xn--');
  const host = hostRaw.toLowerCase();
  const port = parsed.port ? parseInt(parsed.port, 10) : null;
  const isIp = isIpAddress(host);
  const hasUserinfo = !!parsed.username || !!parsed.password;

  let pathStr = parsed.pathname || '/';
  const queryStr = parsed.search ? parsed.search.replace(/^\?/, '') : '';

  // Canonical normalized URL
  let normNetloc = host;
  if (port) {
    if (!((scheme === 'http' && port === 80) || (scheme === 'https' && port === 443))) {
      normNetloc += `:${port}`;
    }
  }
  const normUrl = `${scheme}://${normNetloc}${pathStr}${queryStr ? '?' + queryStr : ''}${parsed.hash || ''}`;

  return {
    rawUrl,
    normalizedUrl: normUrl,
    scheme,
    host,
    port,
    path: pathStr,
    query: queryStr,
    isPunycode,
    hasNonAscii,
    isIp,
    hasUserinfo,
  };
}

// Multi-part country-code secondary TLDs
const MULTI_PART_TLDS = new Set([
  'co.uk', 'gov.uk', 'ac.uk', 'org.uk', 'ltd.uk', 'me.uk', 'net.uk',
  'com.au', 'net.au', 'org.au', 'edu.au', 'gov.au',
  'co.jp', 'ne.jp', 'ac.jp', 'go.jp', 'or.jp',
  'co.nz', 'net.nz', 'org.nz', 'govt.nz',
  'com.br', 'net.br', 'org.br', 'gov.br',
  'co.in', 'net.in', 'org.in', 'gen.in', 'firm.in', 'ind.in',
  'edu.cn', 'com.cn', 'net.cn', 'org.cn', 'gov.cn',
  'co.za', 'org.za', 'gov.za',
  'com.sg', 'edu.sg', 'gov.sg',
  'com.mx', 'edu.mx', 'gob.mx',
  'com.ar', 'gov.ar',
  'qc.ca', 'gc.ca'
]);

// Step 2: Extract 34 Features (Matching app/features.py exactly)
function extractFeatures(val) {
  const normUrl = val.normalizedUrl;
  const host = val.host;
  const pathStr = val.path;
  const queryStr = val.query;

  // Split host for subdomain, registered domain, and suffix
  const hostParts = host.split('.');
  let suffix = '';
  let registeredDomain = '';
  let subdomain = '';

  if (val.isIp) {
    registeredDomain = host;
  } else if (hostParts.length >= 3) {
    const lastTwo = `${hostParts[hostParts.length - 2]}.${hostParts[hostParts.length - 1]}`;
    if (MULTI_PART_TLDS.has(lastTwo)) {
      suffix = lastTwo;
      registeredDomain = hostParts[hostParts.length - 3];
      if (hostParts.length > 3) {
        subdomain = hostParts.slice(0, hostParts.length - 3).join('.');
      }
    } else {
      suffix = hostParts[hostParts.length - 1];
      registeredDomain = hostParts[hostParts.length - 2];
      subdomain = hostParts.slice(0, hostParts.length - 2).join('.');
    }
  } else if (hostParts.length === 2) {
    suffix = hostParts[1];
    registeredDomain = hostParts[0];
  } else {
    registeredDomain = host;
  }

  // Subdomain count: strip standard 'www' prefix so legitimate websites are not penalized
  let cleanSub = subdomain.replace(/^www\./i, '');
  if (cleanSub.toLowerCase() === 'www') cleanSub = '';
  const subdomain_count = cleanSub ? cleanSub.split('.').filter(Boolean).length : 0;

  // 1-4: Lengths
  const url_length = normUrl.length;
  const host_length = host.length;
  const path_length = pathStr.length;
  const query_length = queryStr.length;

  // 5-8: Structural
  const dot_count = (normUrl.match(/\./g) || []).length;
  const pathSegs = pathStr.replace(/^\/|\/$/g, '').split('/').filter(Boolean);
  const path_depth = pathSegs.length;
  const query_param_count = queryStr ? queryStr.split('&').filter(Boolean).length : 0;

  // 9-16: Character counts
  const count_hyphen = (normUrl.match(/-/g) || []).length;
  const count_at = (normUrl.match(/@/g) || []).length;
  const count_question = (normUrl.match(/\?/g) || []).length;
  const count_ampersand = (normUrl.match(/&/g) || []).length;
  const count_equal = (normUrl.match(/=/g) || []).length;
  const count_percent = (normUrl.match(/%/g) || []).length;
  const count_underscore = (normUrl.match(/_/g) || []).length;
  const count_tilde = (normUrl.match(/~/g) || []).length;

  // 17: Double slash in path
  const double_slash_in_path = pathStr.includes('//') ? 1 : 0;

  // 18-20: Digits
  const totalDigits = (normUrl.match(/\d/g) || []).length;
  const digit_ratio = url_length > 0 ? parseFloat((totalDigits / url_length).toFixed(4)) : 0;
  const host_hyphen_count = (host.match(/-/g) || []).length;
  const host_digit_count = (host.match(/\d/g) || []).length;

  // 21-22: Host characteristics
  const is_ip_host = val.isIp ? 1 : 0;
  let non_standard_port = 0;
  if (val.port) {
    if ((val.scheme === 'http' && val.port !== 80) || (val.scheme === 'https' && val.port !== 443)) {
      non_standard_port = 1;
    }
  }

  // 23-25: Encoding
  const is_punycode = val.isPunycode ? 1 : 0;
  const has_non_ascii = val.hasNonAscii ? 1 : 0;
  const percent_encoded_count = (normUrl.match(/%[0-9a-fA-F]{2}/g) || []).length;

  // 26: Suspicious keyword tokens
  const lowerScope = `${subdomain}/${pathStr}/${queryStr}`.toLowerCase();
  let suspicious_token_count = 0;
  for (const t of SUSPICIOUS_TOKENS) {
    const matches = lowerScope.match(new RegExp(t, 'g'));
    if (matches) suspicious_token_count += matches.length;
  }

  // 27: Brand Mismatch (Brand in subdomain or path, but NOT in registered domain)
  let brand_mismatch = 0;
  for (const b of BRAND_TARGETS) {
    const inSubOrPath = subdomain.includes(b) || pathStr.toLowerCase().includes(b);
    if (inSubOrPath && registeredDomain !== b) {
      brand_mismatch = 1;
      break;
    }
  }

  // 28: TLD Category: 0 = common generic, 1 = ccTLD, 2 = high-risk / abused
  let tld_category = 0;
  const cleanSuffix = suffix.split('.').pop() || '';
  if (HIGH_RISK_TLDS.has(cleanSuffix)) {
    tld_category = 2;
  } else if (cleanSuffix.length === 2 && /^[a-z]+$/i.test(cleanSuffix)) {
    tld_category = 1; // ccTLD
  } else if (COMMON_TLDS.has(cleanSuffix)) {
    tld_category = 0;
  } else {
    tld_category = 1;
  }

  // 29: Shortener
  const fullDomain = suffix ? `${registeredDomain}.${suffix}` : registeredDomain;
  const is_shortener = SHORTENER_DOMAINS.has(fullDomain) || SHORTENER_DOMAINS.has(host) ? 1 : 0;

  // 30: Host Entropy
  const host_entropy = calculateEntropy(host);

  // 31: Longest digit run
  const digitRuns = normUrl.match(/\d+/g) || [];
  let longest_digit_run = 0;
  for (const r of digitRuns) {
    if (r.length > longest_digit_run) longest_digit_run = r.length;
  }

  // 32: Deceptive https token in host
  let https_token_in_host = 0;
  if (/https/i.test(host) || /(?:^|[\.-])http(?:[\.-]|$)/i.test(host)) {
    https_token_in_host = 1;
  }

  // 33: Risky file extension
  const lowerPath = pathStr.toLowerCase();
  let risky_file_extension = 0;
  for (const ext of RISKY_EXTENSIONS) {
    if (lowerPath.endsWith(ext) || lowerPath.includes(`${ext}?`)) {
      risky_file_extension = 1;
      break;
    }
  }

  // 34: Is HTTPS
  const is_https = val.scheme === 'https' ? 1 : 0;

  return {
    url_length, host_length, path_length, query_length, dot_count,
    subdomain_count, path_depth, query_param_count, count_hyphen,
    count_at, count_question, count_ampersand, count_equal,
    count_percent, count_underscore, count_tilde, double_slash_in_path,
    digit_ratio, host_hyphen_count, host_digit_count, is_ip_host,
    non_standard_port, is_punycode, has_non_ascii, percent_encoded_count,
    suspicious_token_count, brand_mismatch, tld_category, is_shortener,
    host_entropy, longest_digit_run, https_token_in_host,
    risky_file_extension, is_https
  };
}

// Step 3: Evaluate Heuristic Rules
function evaluateRules(val, features) {
  const flags = [];

  if (val.isIp || features.is_ip_host === 1) {
    flags.push({
      id: 'RULE_IP_HOST',
      name: 'Direct IP Address Host',
      severity: 'high',
      description: 'The URL uses a raw IP address instead of a registered domain name, bypassing domain reputation systems.',
      evidence: `Host resolved directly as IP: ${val.host}`
    });
  }

  if (val.hasUserinfo || features.count_at > 0) {
    flags.push({
      id: 'RULE_USERINFO_AT',
      name: "Userinfo '@' Symbol in URL",
      severity: 'critical',
      description: "The '@' character instructs browsers to treat preceding text as user credentials, obscuring the actual destination host.",
      evidence: "Detected '@' character in URL string."
    });
  }

  if (val.isPunycode || val.hasNonAscii || features.is_punycode === 1) {
    flags.push({
      id: 'RULE_PUNYCODE_IDN',
      name: 'Punycode / IDN Homograph Indicator',
      severity: 'high',
      description: "The domain uses Punycode ('xn--') or non-ASCII characters, a technique commonly used for visual impersonation attacks.",
      evidence: `Punycode/IDN host: ${val.host}`
    });
  }

  if (features.brand_mismatch === 1) {
    flags.push({
      id: 'RULE_BRAND_MISMATCH',
      name: 'Brand Impersonation in Subdomain/Path',
      severity: 'critical',
      description: 'A recognized brand appears in the subdomain or path, but the registered domain does not match.',
      evidence: `Brand token found outside registered domain in: ${val.host}${val.path}`
    });
  }

  if (features.subdomain_count >= 3) {
    flags.push({
      id: 'RULE_EXCESSIVE_SUBDOMAINS',
      name: 'Excessive Subdomain Depth',
      severity: 'medium',
      description: 'The URL contains 3 or more subdomain levels, frequently employed to spoof corporate hierarchies or evade filters.',
      evidence: `Detected ${features.subdomain_count} subdomain levels in host: ${val.host}`
    });
  }

  if (/https?%3A%2F%2F|https?:\/\//i.test(val.query || '')) {
    flags.push({
      id: 'RULE_NESTED_URL_IN_QUERY',
      name: 'Nested URL in Query Parameters',
      severity: 'high',
      description: 'A secondary URL is embedded in the query string, which may indicate an open redirect, phishing redirector, or credential relay.',
      evidence: 'Nested URL found inside query string'
    });
  }

  if (features.risky_file_extension === 1) {
    flags.push({
      id: 'RULE_RISKY_EXTENSION',
      name: 'Dangerous File Extension Target',
      severity: 'critical',
      description: 'The URL points directly to an executable, script, or compressed container file commonly used for malware delivery.',
      evidence: `Target path: ${val.path}`
    });
  }

  if (features.is_shortener === 1) {
    flags.push({
      id: 'RULE_SHORTENER_MASK',
      name: 'URL Shortening Service',
      severity: 'medium',
      description: 'The URL uses a public shortening service, masking the true destination host and path from user inspection.',
      evidence: `Shortener domain: ${val.host}`
    });
  }

  if (features.double_slash_in_path === 1) {
    flags.push({
      id: 'RULE_DOUBLE_SLASH_PATH',
      name: 'Unescaped Double Slash in Path',
      severity: 'medium',
      description: "The URL path contains '//', which is often exploited in web server path traversal, redirection tricks, or filter evasion.",
      evidence: `Double slash found in path: ${val.path}`
    });
  }

  if (features.non_standard_port === 1) {
    flags.push({
      id: 'RULE_NON_STANDARD_PORT',
      name: 'Non-Standard Port Specified',
      severity: 'medium',
      description: 'The URL explicitly connects to a non-standard port (not 80 or 443), typical of ad-hoc malware drop hosts or command-and-control servers.',
      evidence: `Port: ${val.port}`
    });
  }

  return flags;
}

// Step 4: Threat Intelligence Lookup
function checkThreatIntel(val) {
  const normLower = val.normalizedUrl.toLowerCase().replace(/\/$/, '');
  const rawLower = val.rawUrl.toLowerCase().replace(/\/$/, '');
  const hostOnly = `${val.scheme}://${val.host}`.toLowerCase();

  if (localFeedSet.has(normLower) || localFeedSet.has(rawLower) || localFeedSet.has(hostOnly)) {
    return {
      hit: true,
      status: 'checked',
      source: 'local_threat_feed',
      threat_type: 'CONFIRMED_MALWARE_OR_PHISHING',
      details: 'URL matches a known active indicator of compromise (IOC) in the local threat intelligence feed.',
      privacy_notice: 'Local feed checks remain completely offline on-device.'
    };
  }

  return {
    hit: false,
    status: 'not_configured',
    source: 'local_threat_feed',
    threat_type: null,
    details: 'Local offline feed checked (no match). Google Safe Browsing API key (GSB_API_KEY) not configured.',
    privacy_notice: 'Local feed checks remain completely offline on-device.'
  };
}

// Helper: Evaluate a single decision tree and compute path contributions
function evaluateTreeWithAttribution(tree, featureVector, attributions, nTrees) {
  let node = 0;
  while (tree.feature[node] !== -2) {
    const featIdx = tree.feature[node];
    const thresh = tree.threshold[node];
    const val = featureVector[featIdx];
    const currentProb = tree.prob1[node];
    const nextNode = val <= thresh ? tree.children_left[node] : tree.children_right[node];
    const nextProb = tree.prob1[nextNode];
    if (featIdx >= 0 && featIdx < attributions.length) {
      attributions[featIdx] += (nextProb - currentProb) / nTrees;
    }
    node = nextNode;
  }
  return tree.prob1[node];
}

// Step 5: Model Scoring and Tree SHAP Local Feature Attributions
function computeModelScoreAndAttributions(features) {
  if (!modelExport) {
    const score = features.is_ip_host || features.brand_mismatch || features.risky_file_extension ? 0.85 : 0.20;
    return { score, attributions: [] };
  }

  const { feature_names, trees, scaler_mean, scaler_scale, lr_coef, lr_intercept } = modelExport;
  const featureVector = feature_names.map(fn => features[fn] ?? 0);

  // 1. Primary: Random Forest Tree Ensemble (when exported)
  if (trees && trees.length > 0) {
    const nTrees = trees.length;
    const attributions = new Array(feature_names.length).fill(0);
    let scoreSum = 0;

    for (let i = 0; i < nTrees; i++) {
      scoreSum += evaluateTreeWithAttribution(trees[i], featureVector, attributions, nTrees);
    }

    const score = scoreSum / nTrees;

    // Build factor list sorted by absolute Tree SHAP attribution
    const factorList = [];
    for (let i = 0; i < feature_names.length; i++) {
      const fn = feature_names[i];
      const rawVal = features[fn] ?? 0;
      const attr = attributions[i];
      factorList.push({
        feature_name: fn,
        human_name: FEATURE_HUMAN_NAMES[fn] || fn,
        feature_value: rawVal,
        attribution: parseFloat(attr.toFixed(4)),
        absAttr: Math.abs(attr)
      });
    }

    factorList.sort((a, b) => b.absAttr - a.absAttr);
    const topFactors = factorList.slice(0, 5).map(f => {
      const isRisk = f.attribution > 0.005;
      const isSafe = f.attribution < -0.005;
      return {
        feature_name: f.feature_name,
        human_name: f.human_name,
        feature_value: f.feature_value,
        attribution: f.attribution,
        influence: isRisk ? 'pushed toward Malicious' : (isSafe ? 'pushed toward Safe' : 'neutral contribution'),
        influence_type: isRisk ? 'risk_increasing' : (isSafe ? 'risk_decreasing' : 'neutral'),
        explanation: isRisk
          ? `Observed value (${f.feature_value}) increased the model's suspicion (+${(f.attribution * 100).toFixed(1)}%).`
          : (isSafe
            ? `Observed value (${f.feature_value}) aligned with benign training distributions (-${(Math.abs(f.attribution) * 100).toFixed(1)}%).`
            : `Observed value (${f.feature_value}) had negligible local influence on the ensemble decision.`)
      };
    });

    return {
      score: parseFloat(score.toFixed(4)),
      attributions: topFactors
    };
  }

  // 2. Fallback: Scaled Logistic Regression
  let z = lr_intercept || 0;
  const factorList = [];

  for (let i = 0; i < feature_names.length; i++) {
    const fn = feature_names[i];
    const rawVal = features[fn] ?? 0;
    const mean = scaler_mean ? scaler_mean[i] : 0;
    const scale = scaler_scale ? (scaler_scale[i] || 1) : 1;
    const scaledVal = (rawVal - mean) / scale;
    const coef = lr_coef ? lr_coef[i] : 0;

    const contrib = coef * scaledVal;
    z += contrib;

    factorList.push({
      feature_name: fn,
      human_name: FEATURE_HUMAN_NAMES[fn] || fn,
      feature_value: rawVal,
      attribution: parseFloat(contrib.toFixed(4)),
      absAttr: Math.abs(contrib)
    });
  }

  const score = 1 / (1 + Math.exp(-z));
  factorList.sort((a, b) => b.absAttr - a.absAttr);
  const topFactors = factorList.slice(0, 5).map(f => {
    const isRisk = f.attribution > 0.005;
    const isSafe = f.attribution < -0.005;
    return {
      feature_name: f.feature_name,
      human_name: f.human_name,
      feature_value: f.feature_value,
      attribution: f.attribution,
      influence: isRisk ? 'pushed toward Malicious' : (isSafe ? 'pushed toward Safe' : 'neutral contribution'),
      influence_type: isRisk ? 'risk_increasing' : (isSafe ? 'risk_decreasing' : 'neutral'),
      explanation: isRisk
        ? `Observed value (${f.feature_value}) increased suspicion.`
        : `Observed value (${f.feature_value}) aligned with benign distributions.`
    };
  });

  return {
    score: parseFloat(score.toFixed(4)),
    attributions: topFactors
  };
}

// Decision policy and classification logic imported from ./app/classifier.js


// Static files
const STATIC_DIR = path.join(__dirname, 'app', 'static');
app.use('/static', express.static(STATIC_DIR));

// Root route serves the UI
app.get('/', (req, res) => {
  const indexHtml = path.join(STATIC_DIR, 'index.html');
  if (fs.existsSync(indexHtml)) {
    return res.sendFile(indexHtml);
  }
  res.send('URL-Guard Service is running.');
});

// GET /api/health
app.get('/api/health', (req, res) => {
  const isModelLoaded = Boolean(modelExport && modelExport.trees && modelExport.trees.length > 0);
  res.json({
    status: isModelLoaded ? 'healthy' : 'degraded',
    service: 'URL-Guard',
    model_loaded: isModelLoaded,
    feature_count: modelExport && modelExport.feature_names ? modelExport.feature_names.length : 0,
    version: '1.0.0'
  });
});

// GET /api/model-info
app.get('/api/model-info', (req, res) => {
  res.json({
    metadata: {
      model_name: 'RandomForestClassifier (Tree Ensemble)',
      version: '1.0.0',
      n_features: 34
    },
    operational_thresholds: thresholdsData,
    metrics: metricsData,
    features: modelExport ? modelExport.feature_names : []
  });
});

const SUPPORTED_LANGUAGES = ['en', 'ta', 'hi', 'te', 'kn', 'ml'];

// GET /api/languages: List of supported elderly explainer languages
app.get('/api/languages', (req, res) => {
  res.json({
    languages: [
      { code: 'en', label: 'English', native: 'English' },
      { code: 'ta', label: 'Tamil', native: 'தமிழ்' },
      { code: 'hi', label: 'Hindi', native: 'हिन्दी' },
      { code: 'te', label: 'Telugu', native: 'తెలుగు' },
      { code: 'kn', label: 'Kannada', native: 'ಕನ್ನಡ' },
      { code: 'ml', label: 'Malayalam', native: 'മലയാളം' }
    ]
  });
});

// GET /api/extension/download: Download packed Chrome / Edge / Firefox extension
app.get('/api/extension/download', (req, res) => {
  const zipPath = path.join(STATIC_DIR, 'url-guard-extension.zip');
  if (fs.existsSync(zipPath)) {
    res.setHeader('Content-Disposition', 'attachment; filename="url-guard-extension.zip"');
    res.setHeader('Content-Type', 'application/zip');
    return res.sendFile(zipPath);
  }
  res.status(404).json({ error: 'EXTENSION_NOT_FOUND', message: 'Extension zip package not found.' });
});

// POST /api/explain: Dedicated endpoint to generate elderly-friendly simple explanation
app.post('/api/explain', rateLimiter, async (req, res) => {
  const {
    verdict: incomingVerdict,
    score = 0,
    ruleFlags = [],
    topFactors = [],
    intelResult = {},
    language = 'en',
    url = ''
  } = req.body || {};

  const numScore = typeof score === 'number' ? score : parseFloat(score) || 0;
  const lowThresh = typeof thresholdsData.low_threshold === 'number' ? thresholdsData.low_threshold : 0.38;
  const highThresh = typeof thresholdsData.high_threshold === 'number' ? thresholdsData.high_threshold : 0.81;
  const verdict = incomingVerdict || (intelResult && intelResult.hit ? 'Malicious' : classifyScore(numScore, lowThresh, highThresh));
  const langKey = SUPPORTED_LANGUAGES.includes(language) ? language : 'en';

  try {
    const explanation = await generateSimpleExplanation({
      verdict,
      score: numScore,
      ruleFlags,
      topFactors,
      intelResult,
      language: langKey,
      url
    });
    res.json({ simple_explanation: explanation });
  } catch (err) {
    res.status(500).json({ error: 'Failed to generate explanation', message: err.message });
  }
});

// POST /api/analyze: Pure string-only URL inspection and threat classification
app.post('/api/analyze', rateLimiter, async (req, res) => {
  if (!req.body || typeof req.body !== 'object') {
    return res.status(400).json({
      error: 'INVALID_REQUEST',
      message: 'Request body must be a valid JSON object.',
      verdict: 'Invalid Request',
      detail: {
        error: 'INVALID_REQUEST',
        code: 'INVALID_JSON_BODY',
        message: 'Request body must be a valid JSON object.'
      }
    });
  }

  const { url: rawUrl, language = 'en' } = req.body;

  if (typeof rawUrl !== 'string' || !rawUrl.trim()) {
    return res.status(422).json({
      error: 'URL_VALIDATION_FAILED',
      message: 'A non-empty URL string is required.',
      verdict: 'Invalid URL',
      detail: {
        error: 'URL_VALIDATION_FAILED',
        code: 'MISSING_URL',
        message: 'A non-empty URL string is required.'
      }
    });
  }

  if (rawUrl.length > 4096) {
    return res.status(422).json({
      error: 'URL_VALIDATION_FAILED',
      message: 'URL length exceeds maximum limit of 4096 characters.',
      verdict: 'Invalid URL',
      detail: {
        error: 'URL_VALIDATION_FAILED',
        code: 'URL_TOO_LONG',
        message: 'URL length exceeds maximum limit of 4096 characters.'
      }
    });
  }

  let val;
  try {
    val = validateAndNormalizeUrl(rawUrl);
  } catch (err) {
    return res.status(422).json({
      error: 'URL_VALIDATION_FAILED',
      message: err.message || 'Validation failed.',
      verdict: 'Invalid URL',
      detail: {
        error: 'URL_VALIDATION_FAILED',
        code: err.code || 'INVALID_URL',
        message: err.message || 'Validation failed.'
      }
    });
  }

  // Ensure trained Random Forest model is available
  if (!modelExport || !modelExport.trees || modelExport.trees.length === 0) {
    return res.status(503).json({
      error: 'MODEL_UNAVAILABLE',
      message: 'The trained Random Forest ML model is unavailable.',
      verdict: 'Analysis Unavailable',
      status: 'Analysis Unavailable'
    });
  }

  // Privacy compliance: log ONLY hostname, never full URL
  console.log(`[URL-Guard] Analyzed request for host: ${val.host}`);

  // Feature extraction
  const features = extractFeatures(val);

  // Rule evaluation
  const ruleFlags = evaluateRules(val, features);

  // Threat intelligence lookup
  const intelResult = checkThreatIntel(val);

  // Model score & Tree SHAP attributions
  const { score: modelScore, attributions } = computeModelScoreAndAttributions(features);

  // Decision policy strictly utilizing configurable thresholds
  const lowThresh = typeof thresholdsData.low_threshold === 'number' ? thresholdsData.low_threshold : 0.38;
  const highThresh = typeof thresholdsData.high_threshold === 'number' ? thresholdsData.high_threshold : 0.81;
  const decision = makeDecision(modelScore, ruleFlags, intelResult, lowThresh, highThresh);

  // Generate elderly-friendly NLP explanation in requested language (en, ta, hi, te, kn, ml)
  const langKey = SUPPORTED_LANGUAGES.includes(language) ? language : 'en';
  const explanation = await generateSimpleExplanation({
    verdict: decision.verdict,
    score: decision.model_score,
    ruleFlags,
    topFactors: attributions,
    intelResult,
    language: langKey,
    url: val.normalizedUrl
  });

  res.json({
    normalized_url: val.normalizedUrl,
    verdict: decision.verdict,
    verdict_basis: decision.verdict_basis,
    confidence_band: decision.confidence_band,
    model: {
      score: decision.model_score,
      name: 'RandomForestClassifier (Tree Ensemble)',
      version: '1.0.0',
      feature_count: 34
    },
    operational_thresholds: {
      low_threshold: lowThresh,
      high_threshold: highThresh,
      bands: {
        safe: `score < ${lowThresh}`,
        suspicious: `${lowThresh} <= score <= ${highThresh}`,
        malicious: `score > ${highThresh}`
      }
    },
    evidence: {
      threat_intel: intelResult,
      rules: ruleFlags,
      model_factors: attributions,
      methodology_note: 'Attributions explain local feature contributions for THIS specific URL via Tree SHAP rather than global statistics.'
    },
    simple_explanation: explanation,
    recommended_action: decision.recommended_action,
    disclaimer: decision.disclaimer
  });
});

const isDirectRun = process.argv[1] && (process.argv[1].endsWith('server.js') || process.argv[1] === fileURLToPath(import.meta.url));
if (isDirectRun) {
  app.listen(PORT, HOST, () => {
    console.log(`[URL-Guard] Node.js server running at http://${HOST}:${PORT}`);
  });
}

export { app };
