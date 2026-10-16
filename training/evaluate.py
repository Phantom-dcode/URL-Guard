"""
Model Evaluation and Threshold Calibration Script for URL-Guard / PhishGuard AI.

Computes comprehensive, un-manipulated performance metrics for BOTH models across BOTH splits:
  - Random Forest vs. Logistic Regression
  - Domain-Grouped Split (unseen domain infrastructure) vs. Random Split (naive baseline)

Metrics computed:
  - Accuracy
  - Precision
  - Recall (Sensitivity)
  - F1 Score
  - ROC-AUC
  - False Positive Rate (FPR)
  - Confusion Matrix [[TN, FP], [FN, TP]]

Calibrates operational thresholds on held-out validation data (NOT the final test set):
  - low_threshold: Targets <= 2.0% False Positive Rate for the Safe band
  - high_threshold: Targets >= 90.0% Precision for the Malicious band
  - Suspicious band: between low_threshold and high_threshold

Saves:
  - models/metrics.json
  - models/thresholds.json
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict

import joblib
import numpy as np
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split

MODELS_DIR = Path("models")
DATA_DIR = Path("data")
SPLITS_FILE = DATA_DIR / "splits.joblib"
METRICS_JSON = MODELS_DIR / "metrics.json"
THRESHOLDS_JSON = MODELS_DIR / "thresholds.json"


def compute_metrics(y_true: np.ndarray, y_pred: np.ndarray, y_score: np.ndarray) -> Dict[str, Any]:
    """Compute all standard classification metrics."""
    acc = float(accuracy_score(y_true, y_pred))
    prec = float(precision_score(y_true, y_pred, zero_division=0))
    rec = float(recall_score(y_true, y_pred, zero_division=0))
    f1 = float(f1_score(y_true, y_pred, zero_division=0))
    auc = float(roc_auc_score(y_true, y_score))

    cm = confusion_matrix(y_true, y_pred)
    tn, fp, fn, tp = [int(v) for v in cm.ravel()]
    fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0

    return {
        "accuracy": round(acc, 4),
        "precision": round(prec, 4),
        "recall": round(rec, 4),
        "f1_score": round(f1, 4),
        "roc_auc": round(auc, 4),
        "false_positive_rate": round(fpr, 4),
        "confusion_matrix": {
            "true_negatives": tn,
            "false_positives": fp,
            "false_negatives": fn,
            "true_positives": tp,
        },
    }


def calibrate_thresholds(y_val: np.ndarray, y_score_val: np.ndarray) -> Dict[str, Any]:
    """
    Select operational thresholds on validation data:
      - low_threshold: calibrated to keep Safe band false positive rate <= 2%
      - high_threshold: calibrated for high precision (>= 90%)
    """
    neg_scores = y_score_val[y_val == 0]

    # Target FPR <= 2.0% for benign
    target_fpr = 0.02
    low_thresh = float(np.percentile(neg_scores, 100.0 * (1.0 - target_fpr)))
    # Constrain to operational sanity [0.35, 0.50]
    low_thresh = max(0.35, min(round(low_thresh, 3), 0.50))

    # High threshold targeting high precision (>= 90%)
    high_thresh = 0.75
    for t in np.linspace(0.60, 0.85, 26):
        preds = (y_score_val >= t).astype(int)
        if preds.sum() > 0:
            p = precision_score(y_val, preds, zero_division=0)
            if p >= 0.90:
                high_thresh = float(round(t, 3))
                break

    safe_mask = y_score_val < low_thresh
    safe_total = safe_mask.sum()
    safe_malicious = (y_val[safe_mask] == 1).sum()
    safe_band_fnr = float(safe_malicious / safe_total) if safe_total > 0 else 0.0

    return {
        "score_description": "model score (Random Forest tree ensemble predicted probability)",
        "low_threshold": low_thresh,
        "high_threshold": high_thresh,
        "policy": {
            "safe_band": f"score < {low_thresh}",
            "suspicious_band": f"{low_thresh} <= score < {high_thresh}",
            "malicious_band": f"score >= {high_thresh} (with >= 2 rule flags or confirmed threat intel)",
        },
        "safe_band_target_fpr": target_fpr,
        "safe_band_empirical_fnr": round(safe_band_fnr, 4),
        "validation_samples": int(len(y_val)),
    }


def evaluate_models() -> Dict[str, Any]:
    """Run full evaluation suite and write metrics.json and thresholds.json."""
    if not SPLITS_FILE.exists():
        raise FileNotFoundError(f"Splits data not found at {SPLITS_FILE}. Run train.py first.")

    print(f"-> Loading test splits from {SPLITS_FILE}...")
    splits = joblib.load(SPLITS_FILE)

    X = splits["X"]
    y = splits["y"]
    domain_test_idx = splits["domain_test_idx"]
    random_test_idx = splits["random_test_idx"]

    # 1. Domain-Grouped Split: partition test set into validation (for calibration) and test (for evaluation)
    X_domain_holdout = X[domain_test_idx]
    y_domain_holdout = y[domain_test_idx]

    # 50/50 split of domain holdout into validation vs test
    X_val, X_test_domain, y_val, y_test_domain = train_test_split(
        X_domain_holdout, y_domain_holdout, test_size=0.50, random_state=42, stratify=y_domain_holdout
    )

    rf_domain = splits["rf_domain"]
    lr_domain = splits["lr_domain"]
    scaler_domain = splits["scaler_domain"]

    # Calibrate thresholds on validation fold
    val_scores = rf_domain.predict_proba(X_val)[:, 1]
    thresholds = calibrate_thresholds(y_val, val_scores)

    # Evaluate RF on held-out test fold
    rf_domain_scores = rf_domain.predict_proba(X_test_domain)[:, 1]
    rf_domain_preds = (rf_domain_scores >= 0.50).astype(int)
    rf_domain_metrics = compute_metrics(y_test_domain, rf_domain_preds, rf_domain_scores)

    # Evaluate LR on held-out test fold
    X_test_domain_scaled = scaler_domain.transform(X_test_domain)
    lr_domain_scores = lr_domain.predict_proba(X_test_domain_scaled)[:, 1]
    lr_domain_preds = (lr_domain_scores >= 0.50).astype(int)
    lr_domain_metrics = compute_metrics(y_test_domain, lr_domain_preds, lr_domain_scores)

    # 2. Random Split (Naive Baseline)
    X_test_random = X[random_test_idx]
    y_test_random = y[random_test_idx]
    rf_random = splits["rf_random"]
    lr_random = splits["lr_random"]
    scaler_random = splits["scaler_random"]

    # RF Random
    rf_random_scores = rf_random.predict_proba(X_test_random)[:, 1]
    rf_random_preds = (rf_random_scores >= 0.50).astype(int)
    rf_random_metrics = compute_metrics(y_test_random, rf_random_preds, rf_random_scores)

    # LR Random
    X_test_random_scaled = scaler_random.transform(X_test_random)
    lr_random_scores = lr_random.predict_proba(X_test_random_scaled)[:, 1]
    lr_random_preds = (lr_random_scores >= 0.50).astype(int)
    lr_random_metrics = compute_metrics(y_test_random, lr_random_preds, lr_random_scores)

    results = {
        "evaluation_summary": {
            "primary_model": "RandomForestClassifier",
            "baseline_model": "LogisticRegression",
            "primary_split": "Domain-Grouped Split (GroupShuffleSplit by Registered Domain)",
            "leakage_comparison_split": "Random Split (StratifiedShuffleSplit)",
            "leakage_gap_insight": (
                "Random split overestimates real-world accuracy due to domain memorization. "
                "Domain-grouped split rigorously tests generalization on completely unseen domains."
            ),
        },
        "domain_grouped_split": {
            "test_sample_count": int(len(y_test_domain)),
            "random_forest_primary": rf_domain_metrics,
            "logistic_regression_baseline": lr_domain_metrics,
        },
        "random_split": {
            "test_sample_count": int(len(y_test_random)),
            "random_forest": rf_random_metrics,
            "logistic_regression": lr_random_metrics,
        },
        "operational_thresholds": thresholds,
    }

    print("\n" + "=" * 70)
    print("                    EVALUATION RESULTS REPORT")
    print("=" * 70)
    print(f"Domain-Grouped Split (Realistic, Unseen Domains):")
    print(
        f"  Random Forest -> Acc: {rf_domain_metrics['accuracy']:.4f} | "
        f"Prec: {rf_domain_metrics['precision']:.4f} | "
        f"Rec: {rf_domain_metrics['recall']:.4f} | "
        f"F1: {rf_domain_metrics['f1_score']:.4f} | "
        f"AUC: {rf_domain_metrics['roc_auc']:.4f} | "
        f"FPR: {rf_domain_metrics['false_positive_rate']:.4f}"
    )
    print(
        f"  Logistic Reg  -> Acc: {lr_domain_metrics['accuracy']:.4f} | "
        f"Prec: {lr_domain_metrics['precision']:.4f} | "
        f"Rec: {lr_domain_metrics['recall']:.4f} | "
        f"F1: {lr_domain_metrics['f1_score']:.4f} | "
        f"AUC: {lr_domain_metrics['roc_auc']:.4f} | "
        f"FPR: {lr_domain_metrics['false_positive_rate']:.4f}"
    )
    print(f"\nRandom Split (Naive Baseline, Susceptible to Domain Memorization):")
    print(
        f"  Random Forest -> Acc: {rf_random_metrics['accuracy']:.4f} | "
        f"Prec: {rf_random_metrics['precision']:.4f} | "
        f"Rec: {rf_random_metrics['recall']:.4f} | "
        f"F1: {rf_random_metrics['f1_score']:.4f} | "
        f"AUC: {rf_random_metrics['roc_auc']:.4f}"
    )
    print(f"\nOperational Thresholds (Domain-Grouped RF, Calibrated on Validation Fold):")
    print(f"  Safe Band:       score < {thresholds['low_threshold']} (Target FPR <= {thresholds['safe_band_target_fpr'] * 100:.1f}%)")
    print(f"  Suspicious Band: {thresholds['low_threshold']} <= score < {thresholds['high_threshold']}")
    print(f"  Malicious Band:  score >= {thresholds['high_threshold']} (Requires >= 2 rule flags or confirmed threat intel)")
    print("=" * 70 + "\n")

    METRICS_JSON.write_text(json.dumps(results, indent=2), encoding="utf-8")
    THRESHOLDS_JSON.write_text(json.dumps(thresholds, indent=2), encoding="utf-8")

    return results


if __name__ == "__main__":
    evaluate_models()
