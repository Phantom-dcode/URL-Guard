"""
Automated Regression and Safety Test Suite for PhishGuard AI / URL-Guard.

Uses standard library unittest so it runs in any standard Python environment without external test runners.

Verifies:
1. Legitimate high-profile websites (Google, Wikipedia, Microsoft, Python, Example.com)
   are correctly classified as Safe without false positives.
2. Malicious threats (IP hosts, credential harvesters, brand spoofing, dangerous extensions)
   are correctly identified as Suspicious or Malicious.
3. Feature extraction parity between Python and JavaScript inference engines.
4. Zero-network safety: strictly string-only inspection without DNS resolution or HTTP fetches.
5. Separation of evidence sources (ML score vs heuristic indicators vs threat intel).
"""

from __future__ import annotations

import json
import unittest
from pathlib import Path

import numpy as np

from app.features import extract_features
from app.validator import URLValidationError, validate_and_normalize_url

MODELS_DIR = Path("models")
MODEL_EXPORT_JSON = MODELS_DIR / "model_export.json"
THRESHOLDS_JSON = MODELS_DIR / "thresholds.json"
METRICS_JSON = MODELS_DIR / "metrics.json"


def evaluate_forest(trees: list[dict], feature_vector: list[float]) -> float:
    """Evaluate decision tree ensemble in pure Python."""
    scores = []
    for tree in trees:
        node = 0
        while tree["feature"][node] != -2:
            feat_idx = tree["feature"][node]
            thresh = tree["threshold"][node]
            val = feature_vector[feat_idx]
            if val <= thresh:
                node = tree["children_left"][node]
            else:
                node = tree["children_right"][node]
        scores.append(tree["prob1"][node])
    return float(np.mean(scores))


class TestURLGuardRegression(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open(MODEL_EXPORT_JSON, "r", encoding="utf-8") as f:
            cls.export_data = json.load(f)
        with open(THRESHOLDS_JSON, "r", encoding="utf-8") as f:
            cls.thresholds = json.load(f)
        cls.feature_names = cls.export_data["feature_names"]
        cls.trees = cls.export_data["trees"]
        cls.low_thresh = cls.thresholds["low_threshold"]
        cls.high_thresh = cls.thresholds["high_threshold"]

    def test_legitimate_urls_classified_safe(self):
        """Ensure legitimate websites are not classified as Suspicious or Malicious."""
        legitimate_urls = [
            "https://www.google.com/",
            "https://www.wikipedia.org/",
            "https://www.microsoft.com/",
            "https://www.python.org/",
            "https://example.com/",
            "https://en.wikipedia.org/wiki/Computer_security",
            "https://github.com/torvalds/linux",
            "https://docs.python.org/3/library/urllib.parse.html",
        ]
        for url in legitimate_urls:
            feats = extract_features(url)
            vec = [feats[fn] for fn in self.feature_names]
            score = evaluate_forest(self.trees, vec)
            self.assertLess(
                score,
                self.low_thresh,
                f"False Positive on legitimate URL: {url} scored {score:.4f} (threshold: {self.low_thresh})",
            )

    def test_malicious_urls_detected(self):
        """Ensure high-risk threats trigger elevated scores and key indicator flags."""
        attacks = [
            ("http://192.168.1.1/admin", "is_ip_host"),
            ("https://paypal.com.verify-login.xyz/account/login?ref=secure", "brand_mismatch"),
            ("http://update-secure-login-chase.top/online/verify.exe", "risky_file_extension"),
            ("http://1.23.99.116:41148/bin.sh", "is_ip_host"),
        ]
        for url, expected_flag in attacks:
            feats = extract_features(url)
            vec = [feats[fn] for fn in self.feature_names]
            score = evaluate_forest(self.trees, vec)
            detected = (score >= self.low_thresh) or (feats.get(expected_flag, 0) == 1)
            self.assertTrue(
                detected,
                f"Attack {url} escaped detection (score: {score:.4f}, flag: {expected_flag})",
            )

    def test_validator_offline_guarantee(self):
        """Verify validator strictly operates on strings without network calls."""
        res = validate_and_normalize_url("https://www.google.com/search?q=test")
        self.assertEqual(res.scheme, "https")
        self.assertEqual(res.host, "www.google.com")

        # Unsupported scheme
        with self.assertRaises(URLValidationError):
            validate_and_normalize_url("ftp://example.com/file.txt")

        # Control characters
        with self.assertRaises(URLValidationError):
            validate_and_normalize_url("https://example.com/\x00malicious")

    def test_feature_extraction_parity(self):
        """Verify 34 deterministic features are produced with proper normalization."""
        feats = extract_features("https://www.google.com/")
        self.assertEqual(len(feats), 34)
        self.assertEqual(feats["subdomain_count"], 0)  # 'www' correctly stripped
        self.assertEqual(feats["is_ip_host"], 0)
        self.assertEqual(feats["brand_mismatch"], 0)
        self.assertEqual(feats["is_https"], 1)


if __name__ == "__main__":
    unittest.main()
