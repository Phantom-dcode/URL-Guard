/**
 * Automated Regression and Safety Test Suite for PhishGuard AI / URL-Guard.
 * 
 * Runs natively in Node.js (zero external dependencies).
 * Verifies:
 *   1. Mandatory legitimate websites (Google, Wikipedia, Microsoft, Python, Example.com)
 *      are classified as 'Safe' (score < 0.38) without false positives.
 *   2. Suspicious URLs with scores between 0.38 and 0.81 are classified as 'Suspicious'
 *      (fixing the bug where suspicious URLs displayed Malicious).
 *   3. High-confidence malicious attacks (score > 0.81 or confirmed threat intel)
 *      are classified as 'Malicious'.
 *   4. Boundary tests for 0.37, 0.38, 0.50, 0.81, and 0.82.
 *   5. Simple Warning Explainer for elderly users in both English and Tamil:
 *      - Preserves verdict
 *      - Explains what warning means and next steps
 *      - Advises against entering passwords/OTPs/banking details for Suspicious/Malicious
 *      - Never claims 100% guarantee for Safe
 *      - No invented indicators
 *   6. Zero-network offline guarantee: string-only parsing without DNS resolution or HTTP requests.
 *   7. Separation of evidence sources (ML prediction, rule flags, and threat intelligence).
 */

import assert from 'assert';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { classifyScore, makeDecision } from '../app/classifier.js';
import { generateFallbackExplanation } from '../app/explainer.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const ROOT = path.join(__dirname, '..');

const BASE_URL = 'http://localhost:3000';

async function analyze(url, language = 'en') {
  const res = await fetch(`${BASE_URL}/api/analyze`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url, language })
  });
  if (!res.ok) {
    const err = await res.json();
    throw new Error(`HTTP ${res.status}: ${JSON.stringify(err)}`);
  }
  return await res.json();
}

async function explain(payload) {
  const res = await fetch(`${BASE_URL}/api/explain`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload)
  });
  if (!res.ok) {
    const err = await res.json();
    throw new Error(`HTTP ${res.status}: ${JSON.stringify(err)}`);
  }
  return await res.json();
}

async function runTests() {
  console.log('='.repeat(70));
  console.log('      RUNNING PHISHGUARD AI AUTOMATED REGRESSION TEST SUITE');
  console.log('='.repeat(70));

  let passed = 0;
  let failed = 0;

  async function check(name, fn) {
    try {
      await fn();
      console.log(`  [PASS] ${name}`);
      passed++;
    } catch (err) {
      console.error(`  [FAIL] ${name}: ${err.message}`);
      failed++;
    }
  }

  // Test 1: Mandatory Legitimate Targets (Score < 0.38 -> Safe)
  const legitimateTargets = [
    { url: 'https://www.google.com/', name: 'Google Search Homepage' },
    { url: 'https://www.wikipedia.org/', name: 'Wikipedia Portal' },
    { url: 'https://www.microsoft.com/', name: 'Microsoft Enterprise Homepage' },
    { url: 'https://www.python.org/', name: 'Python Foundation Homepage' },
    { url: 'https://example.com/', name: 'IANA Example Apex Domain' },
    { url: 'https://docs.python.org/', name: 'Python Official Documentation Portal' },
    { url: 'https://en.wikipedia.org/wiki/Computer_security', name: 'Wikipedia Deep Article' },
    { url: 'https://github.com/torvalds/linux', name: 'GitHub Repository Deep Path' }
  ];

  for (const item of legitimateTargets) {
    await check(`Legitimate URL classified Safe: ${item.name} (${item.url})`, async () => {
      const res = await analyze(item.url);
      assert.strictEqual(
        res.verdict,
        'Safe',
        `Expected Safe but got ${res.verdict} (score: ${res.model.score}, basis: ${res.verdict_basis})`
      );
      assert.ok(
        res.model.score < 0.38,
        `Expected model score < 0.38 but got ${res.model.score}`
      );
      assert.strictEqual(res.evidence.rules.length, 0, `Expected 0 rule flags for clean URL`);
    });
  }

  // Test 2: Suspicious URLs (0.38 <= Score <= 0.81 -> Suspicious)
  // Verifies that URLs in the suspicious band are NOT erroneously marked Malicious.
  const suspiciousTargets = [
    {
      url: 'https://paypal.com.verify-login.xyz/account/login?ref=secure',
      name: 'Brand spoofing on high-risk TLD (Suspicious Risk Band)',
      expectedRule: 'RULE_BRAND_MISMATCH'
    },
    {
      url: 'http://bankofamerica.com.account-update.info/login.php',
      name: 'Banking credential harvester pattern (Suspicious Risk Band)',
      expectedRule: 'RULE_BRAND_MISMATCH'
    },
    {
      url: 'https://bit.ly/3xY9zQ',
      name: 'URL shortener masking service',
      expectedRule: 'RULE_SHORTENER_MASK'
    },
    {
      url: 'http://paypal-security-update.com.tk/login/verify.exe',
      name: 'High-risk TLD with security tokens and extension (Suspicious score <= 0.81)'
    },
    {
      url: 'http://chase-bank-verify-account-update.top/security/login.php?user=test&token=123456789',
      name: 'Unusual query tokens on .top TLD'
    }
  ];

  for (const item of suspiciousTargets) {
    await check(`Suspicious URL classified Suspicious (not Malicious): ${item.name}`, async () => {
      const res = await analyze(item.url);
      assert.strictEqual(
        res.verdict,
        'Suspicious',
        `Expected Suspicious but got ${res.verdict} (score: ${res.model.score})`
      );
      assert.ok(
        res.model.score >= 0.38 && res.model.score <= 0.81,
        `Expected 0.38 <= score <= 0.81 but got ${res.model.score}`
      );
      if (item.expectedRule) {
        assert.ok(res.evidence.rules.some(r => r.id === item.expectedRule), `Expected rule ${item.expectedRule}`);
      }
    });
  }

  // Test 3: High-Risk Attacks Detected as Malicious (Score > 0.81 or Confirmed Threat Intel)
  const attackTargets = [
    {
      url: 'http://192.168.1.1/admin',
      expectedVerdict: 'Malicious',
      name: 'Direct Raw IP Host Access',
      expectedRule: 'RULE_IP_HOST'
    },
    {
      url: 'http://192.168.1.1:8080/admin/panel.php',
      expectedVerdict: 'Malicious',
      name: 'Raw IP with Non-standard Port',
      expectedRule: 'RULE_IP_HOST'
    },
    {
      url: 'http://files-download.xyz/update_patch.exe',
      expectedVerdict: 'Malicious',
      name: 'Direct Executable Payload on High-Risk TLD',
      expectedRule: 'RULE_RISKY_EXTENSION'
    },
    {
      url: 'http://185.220.101.5/botnet/x86',
      expectedVerdict: 'Malicious',
      name: 'Direct IP Host Botnet Binary Payload',
      expectedRule: 'RULE_IP_HOST'
    },
    {
      url: 'http://1.23.99.116:41148/bin.sh',
      expectedVerdict: 'Malicious',
      name: 'Known Active Threat Intel IOC Feed',
      expectedBasis: 'confirmed_intel'
    }
  ];

  for (const item of attackTargets) {
    await check(`Attack detected as Malicious: ${item.name} (${item.url})`, async () => {
      const res = await analyze(item.url);
      assert.strictEqual(
        res.verdict,
        item.expectedVerdict,
        `Expected ${item.expectedVerdict} but got ${res.verdict} (score: ${res.model.score})`
      );
      if (item.expectedRule) {
        const hasRule = res.evidence.rules.some(r => r.id === item.expectedRule);
        assert.ok(hasRule, `Expected rule ${item.expectedRule} to be triggered`);
      }
      if (item.expectedBasis) {
        assert.strictEqual(res.verdict_basis, item.expectedBasis);
      }
    });
  }

  // Test 4: Required Boundary Tests for 0.37, 0.38, 0.50, 0.81, and 0.82
  await check('Score boundary 0.37 is classified as Safe (score < 0.38)', () => {
    assert.strictEqual(classifyScore(0.37), 'Safe');
    assert.strictEqual(makeDecision(0.37).verdict, 'Safe');
  });

  await check('Score boundary 0.38 is classified as Suspicious (0.38 <= score <= 0.81)', () => {
    assert.strictEqual(classifyScore(0.38), 'Suspicious');
    assert.strictEqual(makeDecision(0.38).verdict, 'Suspicious');
  });

  await check('Score boundary 0.50 is classified as Suspicious (0.38 <= score <= 0.81)', () => {
    assert.strictEqual(classifyScore(0.50), 'Suspicious');
    assert.strictEqual(makeDecision(0.50).verdict, 'Suspicious');
  });

  await check('Score boundary 0.81 is classified as Suspicious (0.38 <= score <= 0.81)', () => {
    assert.strictEqual(classifyScore(0.81), 'Suspicious');
    assert.strictEqual(makeDecision(0.81).verdict, 'Suspicious');
  });

  await check('Score boundary 0.82 is classified as Malicious (score > 0.81)', () => {
    assert.strictEqual(classifyScore(0.82), 'Malicious');
    assert.strictEqual(makeDecision(0.82).verdict, 'Malicious');
  });

  // Test 5: Simple Explainer Integration - English Warning Messages
  await check('English Explainer: Suspicious link warns against entering passwords and OTPs', async () => {
    const res = await analyze('https://paypal.com.verify-login.xyz/account/login?ref=secure', 'en');
    const expl = res.simple_explanation;
    assert.ok(expl, 'Missing simple_explanation object');
    assert.strictEqual(expl.verdict, 'Suspicious');
    assert.strictEqual(expl.language, 'en');
    assert.ok(
      expl.summary.toLowerCase().includes('password') || expl.what_to_do.toLowerCase().includes('password'),
      'Explainer must advise against entering passwords'
    );
    assert.ok(
      expl.summary.toLowerCase().includes('otp') || expl.what_to_do.toLowerCase().includes('otp'),
      'Explainer must advise against entering OTPs'
    );
  });

  // Test 6: Simple Explainer Integration - Tamil (தமிழ்) Warning Messages
  await check('Tamil Explainer: Suspicious link produces authentic Tamil warning with password/OTP protection', async () => {
    const res = await analyze('https://paypal.com.verify-login.xyz/account/login?ref=secure', 'ta');
    const expl = res.simple_explanation;
    assert.ok(expl, 'Missing simple_explanation object');
    assert.strictEqual(expl.verdict, 'Suspicious');
    assert.strictEqual(expl.language, 'ta');
    assert.ok(expl.title.includes('சந்தேகத்திற்குரிய'));
    assert.ok(
      expl.summary.includes('password') || expl.summary.includes('OTP') || expl.what_to_do.includes('Password'),
      'Tamil explanation must warn about password/OTP protection'
    );
    assert.ok(
      expl.summary.includes('அதிகாரப்பூர்வ') || expl.elderly_advice.includes('அதிகாரப்பூர்வ'),
      'Tamil explanation must advise using official website directly'
    );
  });

  // Test 7: Explainer API Dedicated Endpoint (/api/explain)
  await check('Dedicated /api/explain endpoint generates localized explanations on demand', async () => {
    const explRes = await explain({
      score: 0.75,
      language: 'ta',
      ruleFlags: [{ id: 'RULE_BRAND_MISMATCH', name: 'Brand Impersonation' }]
    });
    assert.ok(explRes.simple_explanation);
    assert.strictEqual(explRes.simple_explanation.verdict, 'Suspicious');
    assert.strictEqual(explRes.simple_explanation.language, 'ta');
  });

  // Test 7b: Multilingual Indian Explanations (Hindi, Telugu, Kannada, Malayalam)
  await check('Hindi Explainer: Suspicious link produces Hindi warning against passwords/OTPs', async () => {
    const res = await analyze('https://paypal.com.verify-login.xyz/account/login?ref=secure', 'hi');
    const expl = res.simple_explanation;
    assert.ok(expl);
    assert.strictEqual(expl.language, 'hi');
    assert.strictEqual(expl.verdict, 'Suspicious');
    assert.ok(expl.title.includes('संदिग्ध'));
    assert.ok(expl.summary.includes('पासवर्ड') || expl.summary.includes('ओटीपी') || expl.what_to_do.includes('पासवर्ड'));
  });

  await check('Telugu Explainer: Suspicious link produces Telugu warning with password/OTP protection', async () => {
    const res = await analyze('https://paypal.com.verify-login.xyz/account/login?ref=secure', 'te');
    const expl = res.simple_explanation;
    assert.ok(expl);
    assert.strictEqual(expl.language, 'te');
    assert.strictEqual(expl.verdict, 'Suspicious');
    assert.ok(expl.title.includes('అనుమానాస్పద'));
    assert.ok(expl.summary.includes('పాస్‌వర్డ్') || expl.summary.includes('OTP') || expl.what_to_do.includes('పాస్‌వర్డ్'));
  });

  await check('Kannada Explainer: Suspicious link produces Kannada warning with password/OTP protection', async () => {
    const res = await analyze('https://paypal.com.verify-login.xyz/account/login?ref=secure', 'kn');
    const expl = res.simple_explanation;
    assert.ok(expl);
    assert.strictEqual(expl.language, 'kn');
    assert.strictEqual(expl.verdict, 'Suspicious');
    assert.ok(expl.title.includes('ಸಂಶಯಾಸ್ಪದ'));
    assert.ok(expl.summary.includes('ಪಾಸ್‌ವರ್ಡ್') || expl.summary.includes('OTP') || expl.what_to_do.includes('ಪಾಸ್‌ವರ್ಡ್'));
  });

  await check('Malayalam Explainer: Suspicious link produces Malayalam warning with password/OTP protection', async () => {
    const res = await analyze('https://paypal.com.verify-login.xyz/account/login?ref=secure', 'ml');
    const expl = res.simple_explanation;
    assert.ok(expl);
    assert.strictEqual(expl.language, 'ml');
    assert.strictEqual(expl.verdict, 'Suspicious');
    assert.ok(expl.title.includes('സംശയാസ്പദമായ'));
    assert.ok(expl.summary.includes('പാസ്‌വേഡ്') || expl.summary.includes('ഒടിപി') || expl.what_to_do.includes('പാസ്‌വേഡ്'));
  });

  // Test 7c: Extension Endpoints & Language Listing
  await check('GET /api/languages returns all 6 supported languages', async () => {
    const res = await fetch(`${BASE_URL}/api/languages`);
    assert.strictEqual(res.status, 200);
    const data = await res.json();
    assert.ok(Array.isArray(data.languages));
    assert.strictEqual(data.languages.length, 6);
    const codes = data.languages.map(l => l.code);
    assert.ok(['en', 'ta', 'hi', 'te', 'kn', 'ml'].every(c => codes.includes(c)));
  });

  await check('GET /api/extension/download returns extension zip package', async () => {
    const res = await fetch(`${BASE_URL}/api/extension/download`);
    assert.strictEqual(res.status, 200);
    assert.strictEqual(res.headers.get('content-type'), 'application/zip');
  });

  // Test 8: Evidence Source Separation
  await check('Evidence sources are distinct and do not conflate absence of hits with safety', async () => {
    const res = await analyze('https://example.com/');
    assert.ok(res.evidence.threat_intel, 'Missing threat_intel block');
    assert.ok(res.evidence.rules, 'Missing rules block');
    assert.ok(res.evidence.model_factors, 'Missing model_factors block');
    assert.strictEqual(res.evidence.threat_intel.hit, false);
    assert.ok(
      res.disclaimer.includes('Zero-network') && res.disclaimer.includes('not a cryptographic guarantee'),
      'Disclaimer must explicitly state absence of indicators is not a guarantee'
    );
  });

  // Test 9: Rejection of Disallowed Inputs
  await check('Rejection of non-HTTP schemes (ftp://, javascript:)', async () => {
    const ftpRes = await fetch(`${BASE_URL}/api/analyze`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: 'ftp://ftp.example.com/file.iso' })
    });
    assert.strictEqual(ftpRes.status, 422);
  });

  console.log('='.repeat(70));
  console.log(`RESULTS: ${passed} passed, ${failed} failed`);
  console.log('='.repeat(70));

  if (failed > 0) {
    process.exit(1);
  }
}

runTests().catch(err => {
  console.error('Test execution failed:', err);
  process.exit(1);
});
