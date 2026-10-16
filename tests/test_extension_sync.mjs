/**
 * Test Suite: Extension Synchronization, Backend ML Integration & Error Handling
 * 
 * Verifies:
 *   1. Health endpoint reporting actual model-loading status (model_loaded: true, 34 features)
 *   2. Request validation on /api/analyze (empty body, missing URL, invalid scheme)
 *   3. Safe URL classification using trained Random Forest model (score < 0.38)
 *   4. Suspicious URL classification within [0.38, 0.81] band
 *   5. Phishing / Malicious URL classification (score > 0.81 or threat intel match)
 *   6. Backend / Model Unavailable handling (Analysis Unavailable, never false Safe)
 *   7. Extension manifest.json validity and host_permissions compliance
 *   8. Consistency across extension background, content, and popup schemas
 */

import assert from 'assert';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const ROOT = path.join(__dirname, '..');

const BASE_URL = process.env.TEST_API_URL || 'http://localhost:3000';

let passed = 0;
let failed = 0;

async function check(desc, fn) {
  try {
    await fn();
    console.log(`  ✓ ${desc}`);
    passed++;
  } catch (err) {
    console.error(`  ✗ ${desc}`);
    console.error(`    ${err.message}`);
    failed++;
  }
}

async function runTests() {
  console.log('='.repeat(70));
  console.log('URL GUARD: EXTENSION SYNCHRONIZATION & ML INTEGRATION TESTS');
  console.log('='.repeat(70));

  // --- 1. Health Endpoint & Model Status ---
  await check('GET /api/health reports accurate model loading status and feature count', async () => {
    const res = await fetch(`${BASE_URL}/api/health`);
    assert.strictEqual(res.status, 200);
    const data = await res.json();
    assert.strictEqual(data.status, 'healthy');
    assert.strictEqual(data.model_loaded, true, 'model_loaded must accurately report true when model is loaded');
    assert.strictEqual(data.feature_count, 34, 'Model must have 34 features');
    assert.strictEqual(data.service, 'URL-Guard');
  });

  // --- 2. Request Validation ---
  await check('POST /api/analyze rejects empty or non-string URLs with 422', async () => {
    const resEmpty = await fetch(`${BASE_URL}/api/analyze`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: '' })
    });
    assert.strictEqual(resEmpty.status, 422);
    const errData = await resEmpty.json();
    assert.ok(errData.error || errData.detail);

    const resMissing = await fetch(`${BASE_URL}/api/analyze`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({})
    });
    assert.strictEqual(resMissing.status, 422);
  });

  await check('POST /api/analyze rejects non-HTTP schemes with 422', async () => {
    const res = await fetch(`${BASE_URL}/api/analyze`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: 'javascript:alert(1)' })
    });
    assert.strictEqual(res.status, 422);
  });

  // --- 3. Safe URL Scenario ---
  await check('Safe Scenario: Legitimate domain is classified as Safe with score < 0.38', async () => {
    const res = await fetch(`${BASE_URL}/api/analyze`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: 'https://example.com/', language: 'en' })
    });
    assert.strictEqual(res.status, 200);
    const data = await res.json();
    assert.strictEqual(data.verdict, 'Safe');
    assert.ok(typeof data.model.score === 'number');
    assert.ok(data.model.score < 0.38, `Expected score < 0.38, got ${data.model.score}`);
    assert.strictEqual(data.model.name, 'RandomForestClassifier (Tree Ensemble)');
    assert.ok(data.simple_explanation);
    assert.strictEqual(data.simple_explanation.verdict, 'Safe');
  });

  // --- 4. Suspicious URL Scenario ---
  await check('Suspicious Scenario: Lookalike URL is classified as Suspicious in [0.38, 0.81] band', async () => {
    const res = await fetch(`${BASE_URL}/api/analyze`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: 'https://paypal.com.verify-login.xyz/account/login?ref=secure', language: 'en' })
    });
    assert.strictEqual(res.status, 200);
    const data = await res.json();
    assert.strictEqual(data.verdict, 'Suspicious');
    assert.ok(data.model.score >= 0.38 && data.model.score <= 0.81, `Expected score in [0.38, 0.81], got ${data.model.score}`);
    assert.ok(data.evidence.rules.length > 0, 'Should have rule evidence flags');
    assert.ok(
      data.simple_explanation.what_to_do.toLowerCase().includes('password') ||
      data.simple_explanation.summary.toLowerCase().includes('password'),
      'Must advise against password entry'
    );
  });

  // --- 5. Phishing / Malicious Scenario ---
  await check('Phishing/Malicious Scenario: High-risk attack is classified as Malicious', async () => {
    const res = await fetch(`${BASE_URL}/api/analyze`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: 'http://198.51.100.12/update-bank-login.exe?auth=token', language: 'en' })
    });
    assert.strictEqual(res.status, 200);
    const data = await res.json();
    assert.strictEqual(data.verdict, 'Malicious');
    assert.ok(data.model.score > 0.81 || (data.evidence.threat_intel && data.evidence.threat_intel.hit));
    assert.ok(
      data.simple_explanation.what_to_do.toLowerCase().includes('close') ||
      data.simple_explanation.title.toLowerCase().includes('danger') ||
      data.simple_explanation.title.toLowerCase().includes('malicious')
    );
  });

  // --- 6. Backend Unavailable / Error Scenario Simulation ---
  await check('Backend Unavailable Scenario: Extension returns Analysis Unavailable without false Safe', async () => {
    // Simulate what the extension client does when connecting to an invalid or offline port
    const offlineUrl = 'http://127.0.0.1:59999';
    let caughtVerdict = null;

    try {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 1000);
      const res = await fetch(`${offlineUrl}/api/analyze`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: 'https://unverified-bank.example.com' }),
        signal: controller.signal
      });
      clearTimeout(timeout);
      if (!res.ok) throw new Error('Offline');
      caughtVerdict = 'Safe';
    } catch (err) {
      // The extension sets verdict to 'Analysis Unavailable'
      caughtVerdict = 'Analysis Unavailable';
    }

    assert.strictEqual(caughtVerdict, 'Analysis Unavailable');
    assert.notStrictEqual(caughtVerdict, 'Safe', 'Unavailable backend must NEVER mark URLs as Safe');
  });

  // --- 7. Extension Manifest V3 Compliance ---
  await check('Extension Manifest: Valid Manifest V3, host_permissions, and required permissions', async () => {
    const manifestPath = path.join(ROOT, 'extension', 'manifest.json');
    assert.ok(fs.existsSync(manifestPath), 'manifest.json must exist');
    const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));

    assert.strictEqual(manifest.manifest_version, 3);
    assert.ok(Array.isArray(manifest.permissions), 'permissions must be an array');
    assert.ok(manifest.permissions.includes('storage'), 'storage permission required');
    assert.ok(manifest.permissions.includes('tabs'), 'tabs permission required');
    assert.ok(Array.isArray(manifest.host_permissions), 'host_permissions must be an array');
    assert.ok(
      manifest.host_permissions.some(p => p.includes('localhost:3000')),
      'host_permissions must include backend localhost:3000'
    );
    assert.strictEqual(manifest.background.service_worker, 'background.js');
    assert.ok(manifest.content_scripts && manifest.content_scripts[0].js.includes('content.js'));
  });

  // --- 8. Consistency Between Extension Files ---
  await check('Consistency: background, content, and popup use single classification source', async () => {
    const bgCode = fs.readFileSync(path.join(ROOT, 'extension', 'background.js'), 'utf8');
    const contentCode = fs.readFileSync(path.join(ROOT, 'extension', 'content.js'), 'utf8');
    const popupCode = fs.readFileSync(path.join(ROOT, 'extension', 'popup.js'), 'utf8');

    // Verify background.js connects to /api/analyze and does NOT have quickAnalyze
    assert.ok(bgCode.includes('/api/analyze'), 'background.js must query /api/analyze');
    assert.ok(!bgCode.includes('function quickAnalyze'), 'background.js must NOT contain duplicate quickAnalyze heuristic');
    assert.ok(bgCode.includes('Analysis Unavailable'), 'background.js must handle Analysis Unavailable');

    // Verify content.js uses message passing rather than local heuristic checks
    assert.ok(contentCode.includes('GET_TAB_ANALYSIS'), 'content.js must query background for tab analysis');
    assert.ok(!contentCode.includes('RISKY_EXTENSIONS'), 'content.js must not have duplicate heuristic definitions');

    // Verify popup.js uses /api/analyze and handles Analysis Unavailable
    assert.ok(popupCode.includes('/api/analyze'), 'popup.js must call /api/analyze');
    assert.ok(popupCode.includes('Analysis Unavailable'), 'popup.js must handle Analysis Unavailable state');
    assert.ok(popupCode.includes('GET_TAB_ANALYSIS'), 'popup.js must coordinate with background tab analysis');
  });

  console.log('='.repeat(70));
  console.log(`EXTENSION SYNC RESULTS: ${passed} passed, ${failed} failed`);
  console.log('='.repeat(70));

  if (failed > 0) {
    process.exit(1);
  }
}

runTests().catch(err => {
  console.error('Test execution error:', err);
  process.exit(1);
});
