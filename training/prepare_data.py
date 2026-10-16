"""
Data Preparation Script for URL-Guard / PhishGuard AI.

Loads an authentic, publicly accessible malicious URL dataset where BOTH classes
consist of full URLs.

Root-Cause Fixes:
1. Excludes contaminated 'defacement' records:
   - In legacy datasets (ISCX / Kaggle), the 'defacement' category contained ordinary,
     legitimate websites (e.g., census.gov, university, and public utility sites) that
     suffered transient CMS defacements a decade ago.
   - Including them poisoned the feature space, teaching the model that legitimate clean
     domains are malicious.
   - We focus exclusively on authentic Phishing and Malware URLs (plus active feeds).

2. Corrects Spurious Scheme ('is_https') Bias:
   - In raw crawls, naked domains defaulted to missing schemes while attacks had explicit schemes.
   - Modern web traffic: >85% of both legitimate websites and phishing sites use HTTPS.
   - We balance the scheme distribution across both classes (~85% HTTPS, ~15% HTTP) so the
     model is forced to learn structural, lexical, token, and domain indicators rather than
     using protocol as a false shortcut.

3. Structural Representativeness:
   - Crawlers only collect deep subpages, leaving apex/homepages underrepresented in benign data.
   - We ensure the benign dataset contains both apex homepages (e.g., google.com, example.com)
     and deep-path URLs.
"""

from __future__ import annotations

import os
import random
import sys
import urllib.request
from pathlib import Path
from urllib.parse import urlsplit

import pandas as pd
import tldextract

DATA_DIR = Path("data")
PREPARED_CSV = DATA_DIR / "prepared_urls.csv"
INTEL_FEED_FILE = DATA_DIR / "intel_feed.txt"
RAW_DATASET_PARQUET = DATA_DIR / "raw_dataset.parquet"

PRIMARY_DATASET_URL = (
    "https://huggingface.co/datasets/EustassKidman/malicious-url/resolve/main/data/train-00000-of-00001.parquet"
)

URLHAUS_RECENT_CSV = "https://urlhaus.abuse.ch/downloads/csv_recent/"
OPENPHISH_FEED = "https://openphish.com/feed.txt"

_EXTRACTOR = tldextract.TLDExtract(cache_dir=None, suffix_list_urls=None)


def fix_url_scheme(url: str, is_https: bool) -> str:
    """Standardize URL string with designated scheme."""
    s = str(url).strip()
    if s.startswith("http://"):
        s = s[7:]
    elif s.startswith("https://"):
        s = s[8:]
    scheme = "https://" if is_https else "http://"
    return f"{scheme}{s}"


def safe_extract_path(url: str) -> str:
    """Safely extract path without throwing on malformed notations."""
    try:
        return urlsplit(url).path or "/"
    except Exception:
        after_scheme = str(url).split("://", 1)[-1]
        if "/" in after_scheme:
            return "/" + after_scheme.split("/", 1)[-1].split("?", 1)[0]
        return "/"


def normalize_for_dedup(url: str) -> str:
    """Canonicalize URL string for duplicate detection without resolving DNS."""
    try:
        parts = urlsplit(url.strip())
        netloc = parts.netloc.lower()
        path = parts.path or "/"
        return f"{parts.scheme.lower()}://{netloc}{path}?{parts.query}"
    except Exception:
        return url.strip().lower()


def download_threat_intel_feed() -> None:
    """Download authentic offline threat feed snapshot."""
    print("-> Downloading local threat intel feed snapshot...")
    feed_urls: set[str] = set()

    try:
        req = urllib.request.Request(OPENPHISH_FEED, headers={"User-Agent": "URL-Guard/1.0"})
        with urllib.request.urlopen(req, timeout=8) as resp:
            for line in resp.read().decode("utf-8", errors="ignore").splitlines():
                line = line.strip()
                if line and (line.startswith("http://") or line.startswith("https://")):
                    feed_urls.add(line)
        print(f"   Collected {len(feed_urls)} URLs from OpenPhish community feed.")
    except Exception as e:
        print(f"   Note: OpenPhish feed unreachable ({e}); using secondary...")

    try:
        req = urllib.request.Request(URLHAUS_RECENT_CSV, headers={"User-Agent": "URL-Guard/1.0"})
        with urllib.request.urlopen(req, timeout=8) as resp:
            content = resp.read().decode("utf-8", errors="ignore")
            for line in content.splitlines():
                if line.startswith("#") or not line.strip():
                    continue
                parts = line.split('","')
                if len(parts) >= 3:
                    u = parts[2].replace('"', '').strip()
                    if u.startswith("http://") or u.startswith("https://"):
                        feed_urls.add(u)
        print(f"   Total local threat intel URLs cached: {len(feed_urls)}")
    except Exception as e:
        print(f"   Note: URLhaus feed unreachable ({e})")

    if not feed_urls:
        feed_urls.update([
            "http://1.23.99.116:41148/bin.sh",
            "http://115.49.27.218:43869/bin.sh",
            "http://175.107.208.199:44126/Mozi.a",
            "http://api.9hits.com/test",
            "http://paypal.account-verification-service.xyz/login.php",
            "http://chase-security-update.com/online/verify",
        ])

    INTEL_FEED_FILE.write_text("\n".join(sorted(feed_urls)), encoding="utf-8")
    print(f"   Threat feed saved to {INTEL_FEED_FILE} ({len(feed_urls)} entries).")


def prepare_dataset(max_rows: int = 24000, random_seed: int = 42) -> pd.DataFrame:
    """Load, clean, balance, and structurally calibrate the dataset."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    random.seed(random_seed)

    if not RAW_DATASET_PARQUET.exists():
        print(f"-> Downloading raw parquet dataset from {PRIMARY_DATASET_URL}...")
        urllib.request.urlretrieve(PRIMARY_DATASET_URL, RAW_DATASET_PARQUET)
        print(f"   Downloaded {RAW_DATASET_PARQUET.stat().st_size:,} bytes.")

    print(f"-> Reading raw parquet from {RAW_DATASET_PARQUET}...")
    df_raw = pd.read_parquet(RAW_DATASET_PARQUET)
    print(f"   Raw dataset shape: {df_raw.shape}")
    print(f"   Type distribution:\n{df_raw['type'].value_counts()}")

    # 1. Filter out 'defacement' to fix the false-positive poisoning issue
    benign_pool = df_raw[df_raw["type"] == "benign"]["url"].dropna().unique().tolist()
    phish_pool = df_raw[df_raw["type"] == "phishing"]["url"].dropna().unique().tolist()
    malware_pool = df_raw[df_raw["type"] == "malware"]["url"].dropna().unique().tolist()

    print(f"   Cleaned pools: {len(benign_pool):,} Benign, {len(phish_pool):,} Phishing, {len(malware_pool):,} Malware.")

    # 2. Extract unique benign domains to construct representative benign root/homepages
    unique_domains: set[str] = set()
    for u in benign_pool[:80000]:
        try:
            s = str(u).split("://")[-1].split("/")[0].split("?")[0].lower()
            if s and "." in s and not s.startswith("www."):
                unique_domains.add(s)
        except Exception:
            pass

    domain_list = sorted(list(unique_domains))
    random.shuffle(domain_list)

    # Construct benign homepages (apex and www)
    benign_homepages = [f"{d}/" for d in domain_list[:6000]] + [f"www.{d}/" for d in domain_list[:6000]]

    half = max_rows // 2

    # 3. Sample Benign: 65% deep paths from crawl + 35% apex/homepages
    n_benign_homepages = int(half * 0.35)
    n_benign_deep = half - n_benign_homepages

    b_deep = random.sample(benign_pool, min(len(benign_pool), n_benign_deep))
    b_home = random.sample(benign_homepages, min(len(benign_homepages), n_benign_homepages))
    b_raw = b_deep + b_home

    # 4. Sample Malicious: 80% Phishing + 20% Malware
    n_mal_phish = int(half * 0.80)
    n_mal_malware = half - n_mal_phish

    m_phish = random.sample(phish_pool, min(len(phish_pool), n_mal_phish))
    m_malware = random.sample(malware_pool, min(len(malware_pool), n_mal_malware))
    m_raw = m_phish + m_malware

    # 5. Standardize scheme distribution (~85% HTTPS, ~15% HTTP) across BOTH classes
    # This completely eliminates spurious scheme correlation.
    b_urls = [fix_url_scheme(u, random.random() < 0.85) for u in b_raw]
    m_urls = [fix_url_scheme(u, random.random() < 0.85) for u in m_raw]

    # Combine into DataFrame
    records = [{"url": u, "label": 0} for u in b_urls] + [{"url": u, "label": 1} for u in m_urls]
    df = pd.DataFrame(records)

    # 6. Deduplicate exact and normalized
    initial_count = len(df)
    df = df.drop_duplicates(subset=["url"])
    df["norm_key"] = df["url"].apply(normalize_for_dedup)
    df = df.drop_duplicates(subset=["norm_key"]).drop(columns=["norm_key"])
    print(f"   Deduplication: reduced from {initial_count:,} to {len(df):,} unique URLs.")

    # Shuffle
    df = df.sample(frac=1.0, random_state=random_seed).reset_index(drop=True)

    # Audit path and scheme distributions
    print("-> Prepared dataset audit:")
    for label_val, name in [(0, "Benign"), (1, "Malicious")]:
        sub = df[df["label"] == label_val]
        paths = sub["url"].apply(safe_extract_path)
        is_root = (paths.isin(["", "/"])).mean()
        is_https = sub["url"].str.startswith("https://").mean()
        avg_len = sub["url"].apply(len).mean()
        print(f"   [{name}] Count: {len(sub):,} | Root URLs: {is_root * 100:.1f}% | HTTPS: {is_https * 100:.1f}% | Avg Length: {avg_len:.1f}")

    df.to_csv(PREPARED_CSV, index=False)
    print(f"-> Saved calibrated dataset to {PREPARED_CSV}")

    download_threat_intel_feed()
    return df


if __name__ == "__main__":
    cap = 24000
    if len(sys.argv) > 1:
        try:
            cap = int(sys.argv[1])
        except ValueError:
            pass
    prepare_dataset(max_rows=cap)
