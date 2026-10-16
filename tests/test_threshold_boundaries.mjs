/**
 * Unit and Boundary Tests for URL Risk Classification Logic and Explainer Layer.
 * 
 * Verifies:
 *   1. Required boundary classifications:
 *      - Score 0.37 -> Safe / Low Risk (score < 0.38)
 *      - Score 0.38 -> Suspicious (0.38 <= score <= 0.81)
 *      - Score 0.50 -> Suspicious (0.38 <= score <= 0.81)
 *      - Score 0.81 -> Suspicious (0.38 <= score <= 0.81)
 *      - Score 0.82 -> Malicious / High Risk (score > 0.81)
 *   2. Strict threshold behavior with float boundary precision (0.3799 vs 0.38, 0.81 vs 0.8101).
 *   3. Separation of classification logic and NLP explanation layer.
 *   4. Tamil and English warning messages:
 *      - Preserves exact verdict
 *      - Advises against entering passwords, OTPs, or banking details for Suspicious/Malicious
 *      - Never claims 100% guaranteed safety
 *      - Never invents unobserved indicators
 *      - Fallback reliability
 */

import assert from 'assert';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { classifyScore, makeDecision } from '../app/classifier.js';
import { generateFallbackExplanation, extractFriendlyIndicators } from '../app/explainer.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const ROOT = path.join(__dirname, '..');

async function runBoundaryTests() {
  console.log('='.repeat(70));
  console.log('   URL RISK CLASSIFICATION & EXPLAINER BOUNDARY TEST SUITE');
  console.log('='.repeat(70));

  let passed = 0;
  let failed = 0;

  function test(description, fn) {
    try {
      fn();
      console.log(`  [PASS] ${description}`);
      passed++;
    } catch (err) {
      console.error(`  [FAIL] ${description}: ${err.message}`);
      failed++;
    }
  }

  // Section 1: Verify Configurable Thresholds File
  test('models/thresholds.json defines low_threshold=0.38 and high_threshold=0.81', () => {
    const raw = fs.readFileSync(path.join(ROOT, 'models', 'thresholds.json'), 'utf8');
    const config = JSON.parse(raw);
    assert.strictEqual(config.low_threshold, 0.38, 'low_threshold must equal 0.38');
    assert.strictEqual(config.high_threshold, 0.81, 'high_threshold must equal 0.81');
    assert.ok(config.documentation, 'Must document threshold validation requirement');
  });

  // Section 2: Exact Boundary Tests Specified in User Requirements
  // - Score < 0.38 -> Safe
  // - Score >= 0.38 and <= 0.81 -> Suspicious
  // - Score > 0.81 -> Malicious
  test('Boundary 0.37 is classified as Safe', () => {
    assert.strictEqual(classifyScore(0.37), 'Safe');
    const decision = makeDecision(0.37);
    assert.strictEqual(decision.verdict, 'Safe');
  });

  test('Boundary 0.38 is classified as Suspicious', () => {
    assert.strictEqual(classifyScore(0.38), 'Suspicious');
    const decision = makeDecision(0.38);
    assert.strictEqual(decision.verdict, 'Suspicious');
  });

  test('Boundary 0.50 is classified as Suspicious', () => {
    assert.strictEqual(classifyScore(0.50), 'Suspicious');
    const decision = makeDecision(0.50);
    assert.strictEqual(decision.verdict, 'Suspicious');
  });

  test('Boundary 0.81 is classified as Suspicious', () => {
    assert.strictEqual(classifyScore(0.81), 'Suspicious');
    const decision = makeDecision(0.81);
    assert.strictEqual(decision.verdict, 'Suspicious');
  });

  test('Boundary 0.82 is classified as Malicious', () => {
    assert.strictEqual(classifyScore(0.82), 'Malicious');
    const decision = makeDecision(0.82);
    assert.strictEqual(decision.verdict, 'Malicious');
  });

  // Section 3: Fine-grained precision checks at boundary transitions
  test('Float precision below low threshold (0.3799) is Safe', () => {
    assert.strictEqual(classifyScore(0.3799), 'Safe');
    assert.strictEqual(makeDecision(0.3799).verdict, 'Safe');
  });

  test('Float precision above high threshold (0.8101) is Malicious', () => {
    assert.strictEqual(classifyScore(0.8101), 'Malicious');
    assert.strictEqual(makeDecision(0.8101).verdict, 'Malicious');
  });

  test('Zero and extreme upper boundary: 0.00 is Safe, 1.00 is Malicious', () => {
    assert.strictEqual(classifyScore(0.00), 'Safe');
    assert.strictEqual(classifyScore(1.00), 'Malicious');
  });

  // Section 4: Confirmed Threat Intel Precedence
  test('Active threat intelligence hit produces Malicious verdict even with low model score', () => {
    const decision = makeDecision(0.15, [], { hit: true, threat_type: 'CONFIRMED_MALWARE' });
    assert.strictEqual(decision.verdict, 'Malicious');
    assert.strictEqual(decision.verdict_basis, 'confirmed_intel');
  });

  // Section 5: NLP Explainer - English Warnings & Constraints
  test('English Explainer: Suspicious verdict warns against entering passwords and OTPs', () => {
    const explanation = generateFallbackExplanation({
      verdict: 'Suspicious',
      score: 0.60,
      ruleFlags: [{ id: 'RULE_BRAND_MISMATCH', name: 'Brand Impersonation in Subdomain' }],
      language: 'en'
    });

    assert.strictEqual(explanation.verdict, 'Suspicious', 'Verdict must be preserved');
    assert.strictEqual(explanation.language, 'en');
    assert.ok(
      explanation.what_to_do.toLowerCase().includes('password') && explanation.what_to_do.toLowerCase().includes('otp'),
      'Must advise not to enter password or OTP'
    );
    assert.ok(
      explanation.summary.toLowerCase().includes('password') || explanation.message.toLowerCase().includes('password'),
      'Warning message must mention password protection'
    );
    assert.ok(!explanation.what_to_do.toLowerCase().includes('100% guarantee'), 'Never claim 100% guarantee');
  });

  test('English Explainer: Malicious verdict warns against passwords/banking and directs immediate exit', () => {
    const explanation = generateFallbackExplanation({
      verdict: 'Malicious',
      score: 0.85,
      ruleFlags: [{ id: 'RULE_RISKY_EXTENSION', name: 'Dangerous File Extension Target' }],
      language: 'en'
    });

    assert.strictEqual(explanation.verdict, 'Malicious');
    assert.ok(explanation.what_to_do.toLowerCase().includes('do not'));
    assert.ok(explanation.elderly_advice.toLowerCase().includes('password') || explanation.elderly_advice.toLowerCase().includes('pin'));
  });

  test('English Explainer: Safe verdict never claims guaranteed safety', () => {
    const explanation = generateFallbackExplanation({
      verdict: 'Safe',
      score: 0.12,
      language: 'en'
    });

    assert.strictEqual(explanation.verdict, 'Safe');
    const combined = `${explanation.summary} ${explanation.what_to_do} ${explanation.elderly_advice}`;
    assert.ok(
      combined.toLowerCase().includes('guarantee'),
      'Safe message must explicitly mention absence of 100% guarantee'
    );
  });

  // Section 6: NLP Explainer - Tamil (தமிழ்) Warnings & Constraints
  test('Tamil Explainer: Suspicious verdict translates into clear Tamil warning with password/OTP protection', () => {
    const explanation = generateFallbackExplanation({
      verdict: 'Suspicious',
      score: 0.50,
      ruleFlags: [{ id: 'RULE_EXCESSIVE_SUBDOMAINS', name: 'Excessive Subdomain Depth' }],
      language: 'ta'
    });

    assert.strictEqual(explanation.verdict, 'Suspicious', 'Verdict must be preserved');
    assert.strictEqual(explanation.language, 'ta');
    assert.ok(explanation.title.includes('சந்தேகத்திற்குரிய'));
    assert.ok(
      explanation.summary.includes('password') || explanation.summary.includes('OTP') || explanation.summary.includes('கடவுச்சொல்'),
      'Tamil summary must advise on password / OTP protection'
    );
    assert.ok(
      explanation.what_to_do.includes('Password') || explanation.what_to_do.includes('OTP'),
      'Tamil what_to_do must advise against entering password or OTP'
    );
    assert.ok(
      explanation.message.includes('அதிகாரப்பூர்வ') || explanation.summary.includes('அதிகாரப்பூர்வ'),
      'Tamil explanation should advise opening official website directly'
    );
  });

  test('Tamil Explainer: Malicious verdict translates into high-risk Tamil alert', () => {
    const explanation = generateFallbackExplanation({
      verdict: 'Malicious',
      score: 0.92,
      ruleFlags: [{ id: 'RULE_IP_HOST', name: 'Direct IP Address Host' }],
      language: 'ta'
    });

    assert.strictEqual(explanation.verdict, 'Malicious');
    assert.strictEqual(explanation.language, 'ta');
    assert.ok(explanation.title.includes('ஆபத்து'));
    assert.ok(explanation.what_to_do.includes('திறக்காதீர்கள்'));
    assert.ok(explanation.elderly_advice.includes('PIN') || explanation.elderly_advice.includes('OTP'));
  });

  test('Tamil Explainer: Safe verdict provides calm advice without claiming 100% guarantee', () => {
    const explanation = generateFallbackExplanation({
      verdict: 'Safe',
      score: 0.08,
      language: 'ta'
    });

    assert.strictEqual(explanation.verdict, 'Safe');
    assert.strictEqual(explanation.language, 'ta');
    assert.ok(explanation.title.includes('பாதுகாப்பான'));
    assert.ok(explanation.what_to_do.includes('100%'));
  });

  // Section 7: Anti-Hallucination Indicator Extraction
  test('Indicator extraction only reflects actual reported rules and factors', () => {
    const indicators = extractFriendlyIndicators(
      [{ id: 'RULE_BRAND_MISMATCH' }],
      [{ feature_name: 'is_ip_host', influence_type: 'risk_increasing' }],
      { hit: false },
      'en'
    );

    assert.strictEqual(indicators.length, 2);
    assert.ok(indicators.some(i => i.toLowerCase().includes('company name') || i.toLowerCase().includes('brand')));
    assert.ok(indicators.some(i => i.toLowerCase().includes('numeric') || i.toLowerCase().includes('ip')));
    assert.ok(!indicators.some(i => i.toLowerCase().includes('punycode')), 'Must not invent unobserved indicators');
  });

  console.log('='.repeat(70));
  console.log(`RESULTS: ${passed} passed, ${failed} failed`);
  console.log('='.repeat(70));

  if (failed > 0) {
    process.exit(1);
  }
}

runBoundaryTests().catch(err => {
  console.error('Test execution failed:', err);
  process.exit(1);
});
