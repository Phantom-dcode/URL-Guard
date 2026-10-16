/**
 * URL Risk Classification and Decision Policy Module.
 * 
 * Configurable Operational Thresholds:
 *   - Score < 0.38  -> Safe / Low Risk
 *   - 0.38 <= Score <= 0.81 -> Suspicious
 *   - Score > 0.81 -> Malicious / High Risk
 *   - Active Threat Intelligence IOC Match -> Malicious
 */

/**
 * Score classifier strictly implementing operational thresholds.
 * @param {number} score
 * @param {number} lowThresh
 * @param {number} highThresh
 * @returns {'Safe' | 'Suspicious' | 'Malicious'}
 */
export function classifyScore(score, lowThresh = 0.38, highThresh = 0.81) {
  const s = Number(score);
  if (s > highThresh) {
    return 'Malicious';
  }
  if (s >= lowThresh) {
    return 'Suspicious';
  }
  return 'Safe';
}

/**
 * Make security decision based on model score, heuristic rules, and threat intelligence.
 */
export function makeDecision(modelScore, ruleFlags = [], intelResult = {}, lowThresh = 0.38, highThresh = 0.81) {
  const disclaimer = 'Zero-network lexical and heuristic inspection disclaimer: Analysis is conducted string-only without fetching the target or resolving DNS. Safe verdicts reflect absence of known indicators, not a cryptographic guarantee.';

  // 1. Confirmed threat intelligence feed hit (IOC)
  if (intelResult && intelResult.hit) {
    return {
      verdict: 'Malicious',
      verdict_basis: 'confirmed_intel',
      confidence_band: 'Confirmed Threat Intelligence',
      model_score: modelScore,
      summary_text: 'URL is a confirmed malicious threat identified in active threat feeds.',
      recommended_action: 'Block access immediately. Do not navigate to this destination or enter sensitive data.',
      disclaimer
    };
  }

  // 2. Score-based verdict strictly adhering to the configured thresholds
  const verdict = classifyScore(modelScore, lowThresh, highThresh);

  if (verdict === 'Malicious') {
    return {
      verdict: 'Malicious',
      verdict_basis: 'predicted_high_risk',
      confidence_band: 'High-Risk Malicious Prediction',
      model_score: modelScore,
      summary_text: `Model score (${modelScore.toFixed(4)}) exceeds high-risk threshold (${highThresh}). Strong indicators of malicious attack signature.`,
      recommended_action: 'Block request. The URL structure exhibits high-risk malicious characteristics.',
      disclaimer
    };
  }

  if (verdict === 'Suspicious') {
    return {
      verdict: 'Suspicious',
      verdict_basis: 'boundary_risk',
      confidence_band: 'Elevated Vigilance Required',
      model_score: modelScore,
      summary_text: `Model score (${modelScore.toFixed(4)}) falls in the suspicious band [${lowThresh}, ${highThresh}]. Elevated caution required.`,
      recommended_action: 'Exercise caution. Avoid entering passwords, OTPs, or banking details.',
      disclaimer
    };
  }

  // 3. Safe / Low Risk: score strictly below low threshold (score < 0.38)
  return {
    verdict: 'Safe',
    verdict_basis: 'clean_lexical_profile',
    confidence_band: 'Low Risk / Benign Profile',
    model_score: modelScore,
    summary_text: `Model score (${modelScore.toFixed(4)}) is below suspicious threshold (${lowThresh}). No malicious warning signs detected.`,
    recommended_action: 'URL exhibits standard benign characteristics. Maintain normal browsing security hygiene.',
    disclaimer
  };
}
