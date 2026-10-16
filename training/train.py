"""
Model Training Script for URL-Guard / PhishGuard AI.

Extracts 34 deterministic lexical and structural features.
Implements rigorous evaluation methodology:
  1. Domain-Grouped Split (GroupShuffleSplit on registered domain): prevents domain leakage
     and rigorously measures real-world detection of novel infrastructure.
  2. Random Split (StratifiedShuffleSplit): standard naive baseline to demonstrate leakage gap.

Trains:
  - Primary: Random Forest Classifier (n_estimators=60, max_depth=12, min_samples_leaf=4, class_weight='balanced')
  - Baseline: Scaled Logistic Regression (class_weight='balanced')

Artifacts saved:
  - models/model.joblib (RandomForest primary)
  - models/lr_model.joblib (LogisticRegression baseline)
  - models/scaler.joblib (StandardScaler)
  - models/feature_names.json (strict ordering verification)
  - models/model_metadata.json (versioning, timestamp, training parameters)
  - models/model_export.json (compact tree ensemble for native fast Node.js runtime)
  - data/splits.joblib (held-out test sets for evaluate.py)
"""

from __future__ import annotations

import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

import joblib
import numpy as np
import pandas as pd
import tldextract
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import GroupShuffleSplit, StratifiedShuffleSplit
from sklearn.preprocessing import StandardScaler

# Ensure app package is discoverable
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.features import extract_features

MODELS_DIR = Path("models")
DATA_DIR = Path("data")
PREPARED_CSV = DATA_DIR / "prepared_urls.csv"
SPLITS_FILE = DATA_DIR / "splits.joblib"

_EXTRACTOR = tldextract.TLDExtract(cache_dir=None, suffix_list_urls=None)


def get_registered_domain(url: str) -> str:
    """Extract registered domain grouping key for GroupShuffleSplit."""
    try:
        parts = urlsplit(url)
        netloc = parts.netloc.lower()
    except Exception:
        after = str(url).split("://", 1)[-1]
        netloc = after.split("/", 1)[0].split("?", 1)[0].lower()

    try:
        if "@" in netloc:
            netloc = netloc.split("@")[-1]
        if ":" in netloc and not netloc.endswith("]"):
            netloc = netloc.split(":")[0]
        ext = _EXTRACTOR(netloc)
        reg = f"{ext.domain}.{ext.suffix}" if ext.suffix else (ext.domain or netloc)
        return reg or "unknown"
    except Exception:
        return "unknown"


def export_forest_to_json(
    rf: RandomForestClassifier,
    fns: list[str],
    scaler: StandardScaler,
    lr: LogisticRegression,
    n_trees: int = 60,
) -> dict:
    """Export compact decision tree ensemble and linear baseline to JSON."""
    exported_trees = []
    estimators = rf.estimators_[:n_trees]

    for est in estimators:
        tree = est.tree_
        # value has shape (node_count, 1, 2)
        val = tree.value[:, 0, :]
        total = np.sum(val, axis=1)
        prob1 = np.where(total > 0, val[:, 1] / total, 0.0).round(4).tolist()

        exported_trees.append({
            "children_left": tree.children_left.tolist(),
            "children_right": tree.children_right.tolist(),
            "feature": tree.feature.tolist(),
            "threshold": tree.threshold.round(4).tolist(),
            "prob1": prob1,
        })

    return {
        "model_name": f"RandomForestClassifier ({len(exported_trees)} trees)",
        "version": "1.0.0",
        "n_trees": len(exported_trees),
        "feature_names": fns,
        "trees": exported_trees,
        "scaler_mean": scaler.mean_.round(4).tolist(),
        "scaler_scale": scaler.scale_.round(4).tolist(),
        "lr_coef": lr.coef_[0].round(4).tolist(),
        "lr_intercept": round(float(lr.intercept_[0]), 4),
    }


def train_models(sample_size: int = 24000) -> None:
    """Run full feature extraction, train Random Forest and Logistic Regression, and persist artifacts."""
    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    DATA_DIR.mkdir(parents=True, exist_ok=True)

    if not PREPARED_CSV.exists():
        print(f"Prepared dataset not found at {PREPARED_CSV}. Running training/prepare_data.py...")
        from training.prepare_data import prepare_dataset
        prepare_dataset(max_rows=sample_size)

    print(f"-> Reading dataset from {PREPARED_CSV}...")
    df = pd.read_csv(PREPARED_CSV)
    if len(df) > sample_size:
        print(f"   Subsampling to {sample_size:,} records...")
        benign = df[df["label"] == 0]
        malicious = df[df["label"] == 1]
        half = sample_size // 2
        df = pd.concat([
            benign.sample(n=min(len(benign), half), random_state=42),
            malicious.sample(n=min(len(malicious), half), random_state=42),
        ]).sample(frac=1.0, random_state=42).reset_index(drop=True)

    print(f"   Total samples: {len(df):,} (Benign: {(df['label'] == 0).sum():,}, Malicious: {(df['label'] == 1).sum():,})")

    # Step 1: Feature Extraction
    print("-> Extracting 34 features for all URLs using app.features.extract_features...")
    t0 = time.time()
    feature_dicts = []
    urls = df["url"].tolist()
    labels = df["label"].to_numpy(dtype=np.int32)

    for i, u in enumerate(urls):
        feat = extract_features(u)
        feature_dicts.append(feat)
        if (i + 1) % 5000 == 0 or (i + 1) == len(urls):
            print(f"   Extracted {i + 1:,} / {len(urls):,} URLs ({time.time() - t0:.1f}s)")

    feat_df = pd.DataFrame(feature_dicts)
    feature_names = list(feat_df.columns)
    X = feat_df.to_numpy(dtype=np.float32)
    y = labels

    print(f"   Feature matrix shape: {X.shape}")

    # Step 2: Compute Domain Groups for GroupShuffleSplit
    print("-> Computing registered domain groups to prevent data leakage...")
    domains = np.array([get_registered_domain(u) for u in urls])
    unique_domains = len(np.unique(domains))
    print(f"   Found {unique_domains:,} distinct registered domains across {len(urls):,} URLs.")

    # Domain Group Split (20% test)
    gss = GroupShuffleSplit(n_splits=1, test_size=0.20, random_state=42)
    domain_train_idx, domain_test_idx = next(gss.split(X, y, groups=domains))

    # Plain Random Stratified Split (20% test)
    sss = StratifiedShuffleSplit(n_splits=1, test_size=0.20, random_state=42)
    random_train_idx, random_test_idx = next(sss.split(X, y))

    print(f"   Domain-grouped split: {len(domain_train_idx):,} train, {len(domain_test_idx):,} test")
    print(f"   Random split:         {len(random_train_idx):,} train, {len(random_test_idx):,} test")

    # Step 3: Train Models on Domain-Grouped Train Set
    X_train_domain = X[domain_train_idx]
    y_train_domain = y[domain_train_idx]

    # Fit Scaler
    scaler = StandardScaler()
    X_train_domain_scaled = scaler.fit_transform(X_train_domain)

    # Train Baseline Logistic Regression
    print("-> Training Baseline: Logistic Regression (scaled, class_weight='balanced')...")
    lr = LogisticRegression(
        max_iter=1000,
        class_weight="balanced",
        random_state=42,
        solver="lbfgs",
    )
    lr.fit(X_train_domain_scaled, y_train_domain)

    # Train Primary Random Forest
    print("-> Training Primary: Random Forest Classifier (60 trees, max_depth=12, min_samples_leaf=4, class_weight='balanced')...")
    rf = RandomForestClassifier(
        n_estimators=60,
        max_depth=12,
        min_samples_leaf=4,
        class_weight="balanced",
        random_state=42,
        n_jobs=-1,
    )
    rf.fit(X_train_domain, y_train_domain)

    # Train on Random Split for comparison
    X_train_random = X[random_train_idx]
    y_train_random = y[random_train_idx]
    scaler_random = StandardScaler()
    X_train_random_scaled = scaler_random.fit_transform(X_train_random)

    lr_random = LogisticRegression(max_iter=1000, class_weight="balanced", random_state=42)
    lr_random.fit(X_train_random_scaled, y_train_random)

    rf_random = RandomForestClassifier(
        n_estimators=60,
        max_depth=12,
        min_samples_leaf=4,
        class_weight="balanced",
        random_state=42,
        n_jobs=-1,
    )
    rf_random.fit(X_train_random, y_train_random)

    # Step 4: Persist Artifacts
    print("-> Saving model artifacts...")
    version = "1.0.0"
    joblib.dump(rf, MODELS_DIR / "model.joblib")
    joblib.dump(lr, MODELS_DIR / "lr_model.joblib")
    joblib.dump(scaler, MODELS_DIR / "scaler.joblib")

    (MODELS_DIR / "feature_names.json").write_text(json.dumps(feature_names, indent=2), encoding="utf-8")

    meta = {
        "model_name": "RandomForestClassifier",
        "baseline_model_name": "LogisticRegression",
        "version": version,
        "n_features": len(feature_names),
        "feature_names": feature_names,
        "n_samples": len(df),
        "n_unique_domains": unique_domains,
        "trained_at_utc": datetime.now(timezone.utc).isoformat(),
        "random_forest_params": {
            "n_estimators": 60,
            "max_depth": 12,
            "min_samples_leaf": 4,
            "class_weight": "balanced",
            "random_state": 42,
        },
    }
    (MODELS_DIR / "model_metadata.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")

    # Export compact tree ensemble for native fast Node.js runtime
    export_payload = export_forest_to_json(rf, feature_names, scaler, lr, n_trees=60)
    (MODELS_DIR / "model_export.json").write_text(json.dumps(export_payload), encoding="utf-8")
    print(f"-> Exported native Node.js tree ensemble to {MODELS_DIR / 'model_export.json'} ({len(export_payload['trees'])} trees)")

    # Save splits for evaluation script
    splits_payload = {
        "X": X,
        "y": y,
        "feature_names": feature_names,
        "domain_train_idx": domain_train_idx,
        "domain_test_idx": domain_test_idx,
        "random_train_idx": random_train_idx,
        "random_test_idx": random_test_idx,
        "rf_domain": rf,
        "lr_domain": lr,
        "scaler_domain": scaler,
        "rf_random": rf_random,
        "lr_random": lr_random,
        "scaler_random": scaler_random,
    }
    joblib.dump(splits_payload, SPLITS_FILE)
    print(f"-> Successfully saved splits to {SPLITS_FILE}")


if __name__ == "__main__":
    size = 24000
    if len(sys.argv) > 1:
        try:
            size = int(sys.argv[1])
        except ValueError:
            pass
    train_models(sample_size=size)
