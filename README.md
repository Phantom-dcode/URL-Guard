<p align="center">
<img src="https://raw.githubusercontent.com/tandpfun/skill-icons/main/icons/Shield.svg" width="80" height="80" alt="URL Guard Shield" />
</p>
<h1 align="center">URL Guard</h1>
<p align="center">
<strong>Production-Grade AI & Machine Learning Threat Defense for Web Addresses</strong>
</p>
<p align="center">
<a href="#-key-features"><img src="https://img.shields.io/badge/Model-Random%20Forest%20(34%20Features)-0284c7?style=for-the-badge&logo=scikitlearn&logoColor=white" alt="Random Forest"></a>
<a href="#-multilingual-elderly-friendly-explainer"><img src="https://img.shields.io/badge/AI%20Explainer-Gemini%20Flash-4f46e5?style=for-the-badge&logo=google&logoColor=white" alt="Gemini Explainer"></a>
<a href="#-browser-extension-manifest-v3"><img src="https://img.shields.io/badge/Extension-Manifest%20V3-10b981?style=for-the-badge&logo=googlechrome&logoColor=white" alt="Manifest V3"></a>
<a href="#-supported-languages"><img src="https://img.shields.io/badge/Languages-6%20Indian%20Languages-f59e0b?style=for-the-badge" alt="Languages"></a>
<a href="#-automated-test-suite"><img src="https://img.shields.io/badge/Tests-60%2F60%20Passing-emerald?style=for-the-badge&logo=checkmarx" alt="Tests"></a>
</p>
<p align="center">
<a href="#overview">Overview</a> •
<a href="#-key-features">Key Features</a> •
<a href="#-system-architecture">Architecture</a> •
<a href="#-quick-start">Quick Start</a> •
<a href="#-browser-extension-setup">Extension Setup</a> •
<a href="#-api-documentation">API Reference</a> •
<a href="#-deployment-guide">Public Deployment</a> •
<a href="#-testing">Testing</a>
</p>
🌟 Overview
URL Guard is an end-to-end cybersecurity solution that detects phishing, malware-distribution links, and brand-spoofing campaigns in real time.
Built with privacy as a foundational principle, URL Guard conducts pure string-only inspection without sending outbound HTTP requests to the target URL or resolving DNS, completely preventing IP leaks and tracking beacons.
The system combines:
A Trained Random Forest Machine Learning Model evaluating 34 lexical, structural, and infrastructure features with local Tree SHAP feature attributions.
A Multilingual Elderly-Friendly Explainer powered by Gemini AI and a deterministic NLP fallback engine across 6 major Indian languages (English, Tamil, Hindi, Telugu, Kannada, Malayalam).
A Manifest V3 Chrome Extension providing real-time tab badge indicators, circular score gauges, and in-page alert banners for suspicious pages.
An Interactive Defense Dashboard with historical trend analytics powered by Recharts.
🚀 Key Features
Capability	Description
🌲 Trained ML Ensemble	Domain-grouped Random Forest evaluating 34 structural features, providing Tree SHAP attribution values for exact explainability.
🛡️ 100% Unified Verdicts	The extension icon badge, popup score gauge, and in-page warning banner share the exact same backend ML classification.
🌐 6 Indian Languages	Calm, jargon-free explanations in English, தமிழ் (Tamil), हिन्दी (Hindi), తెలుగు (Telugu), ಕನ್ನಡ (Kannada), and മലയാളം (Malayalam).
🧩 Manifest V3 Extension	Lightweight browser extension with configurable API endpoints, offline-safe handling, and automated packaging.
⚠️ Zero False-Safe Fallbacks	If the backend ML engine or server is unavailable, the system safely renders "Analysis Unavailable" rather than giving false security.
📈 Recharts Visual Analytics	Visualizes historical model scores across user sessions, categorized into Safe, Suspicious, and Malicious confidence bands.
🔒 Strict Privacy Guarantee	Analyzes URLs purely via offline lexical parsing; only hostnames are recorded in server logs, never full URL paths or sensitive query parameters.
📐 System Architecture
code
Text
+--------------------------------------------------+
               |                  USER BROWSER                    |
               |                                                  |
               |  +--------------------+  +--------------------+  |
               |  | Chrome Extension   |  | Web Dashboard      |  |
               |  | Popup & Content JS |  | (React + Recharts) |  |
               |  +---------+----------+  +---------+----------+  |
               +------------|-----------------------|-------------+
                            |                       |
                            | HTTP POST /api/analyze|
                            v                       v
               +--------------------------------------------------+
               |           URL GUARD NODE.JS BACKEND              |
               |                                                  |
               |  [ 1. URL Normalization & Input Validation ]    |
               |                     |                            |
               |  [ 2. 34-Feature Vector Extraction ]             |
               |         (Lexical, Entropy, TLD, Punycode)        |
               |                     |                            |
               |  [ 3. Local Threat Intelligence Lookup ]         |
               |                     |                            |
               |  [ 4. Random Forest Model Tree Scoring ]         |
               |         (Tree SHAP Local Feature Attribution)    |
               |                     |                            |
               |  [ 5. Configurable Threshold Decision Policy ]   |
               |         Score < 0.38  -> Safe                    |
               |         0.38 - 0.81   -> Suspicious              |
               |         Score > 0.81  -> Malicious               |
               |                     |                            |
               |  [ 6. Multilingual Elderly Explainer ]           |
               |         (Gemini AI + Deterministic Fallback)     |
               +--------------------------------------------------+
🎯 Operational Threshold Bands
Risk thresholds are configured in models/thresholds.json and enforced consistently across the backend, extension, and UI:
Risk Level	Score Range	Color	Action Advice
Safe	< 0.38	Emerald	Normal browsing permitted. No system offers a 100% guarantee; maintain basic vigilance.
Suspicious	0.38 - 0.81	Amber	Exercise caution. Never enter passwords, bank credentials, OTPs, or PAN/Aadhaar cards.
Malicious	> 0.81	Red	High danger. Immediate threat detected. Close page immediately; do not download files.
Unavailable	N/A	Slate Gray	Backend or ML model offline. Safety unverified. Proceed with caution.
🗣️ Supported Languages
The explainer engine translates technical indicators (such as brand mismatch, raw IP hosts, or high-risk TLDs) into calm, elderly-friendly instructions:
Language	Native Name	Code	Sample Warning Headline
English	English	en	Warning: Suspicious Link
Tamil	தமிழ்	ta	எச்சரிக்கை: சந்தேகத்திற்குரிய இணைப்பு
Hindi	हिन्दी	hi	चेतावनी: संदिग्ध लिंक
Telugu	తెలుగు	te	హెచ్చరిక: అనుమానాస్పద లింక్
Kannada	ಕನ್ನಡ	kn	ಎಚ್ಚರಿಕೆ: ಸಂಶಯಾಸ್ಪದ ಲಿಂಕ್
Malayalam	മലയാളം	ml	മുന്നറിയിപ്പ്: സംശയാസ്പദമായ ലിങ്ക്
⚡ Quick Start
1. Prerequisites
Node.js v18.0.0 or higher
npm v9.0.0 or higher
2. Installation
code
Bash
# Clone or navigate to the project directory
cd url-guard

# Install dependencies
npm install
3. Environment Variables (Optional)
Copy .env.example to .env:
code
Bash
PORT=3000
HOST=0.0.0.0
NODE_ENV=production

# Optional: Add your Gemini API Key for dynamic AI explanations
# (Falls back to the built-in deterministic multilingual engine if omitted)
GEMINI_API_KEY=your_gemini_api_key_here
4. Run Development Server
code
Bash
npm run dev
Open http://localhost:3000 to view the cyber defense dashboard.
🧩 Browser Extension Setup
URL Guard includes a complete, self-contained Manifest V3 Chrome / Edge / Brave Extension:
code
Text
extension/
├── manifest.json       # Manifest V3 configuration with host_permissions
├── background.js       # Background service worker (central ML coordination & badge)
├── content.js          # In-page warning banner for suspicious/phishing sites
├── popup.html          # Interactive extension popup
├── popup.css           # Dark theme styling with gauge rings & badges
├── popup.js            # Direct backend API client & language selector
└── icons/              # Extension icons (16px, 48px, 128px)
Installing in Chrome / Edge:
Open Chrome and go to chrome://extensions/.
Toggle on Developer mode in the top-right corner.
Click Load unpacked.
Select the extension/ directory from this repository.
Alternatively, download the pre-packaged ZIP directly from the dashboard at http://localhost:3000/api/extension/download and unpack it.
Click the extension icon on any webpage to see real-time risk scores, or open the extension settings (⚙️) to configure the API URL.
📡 API Reference
1. Analyze URL
code
Http
POST /api/analyze
Content-Type: application/json

{
  "url": "https://paypal.com.verify-login.xyz/account/login?ref=secure",
  "language": "en"
}
Response (HTTP 200):
code
JSON
{
  "normalized_url": "https://paypal.com.verify-login.xyz/account/login?ref=secure",
  "verdict": "Suspicious",
  "verdict_basis": "model_score_suspicious_band",
  "confidence_band": "Suspicious",
  "model": {
    "score": 0.6842,
    "name": "RandomForestClassifier (Tree Ensemble)",
    "version": "1.0.0",
    "feature_count": 34
  },
  "evidence": {
    "threat_intel": { "hit": false },
    "rules": [
      { "id": "brand_mismatch", "name": "Brand mismatch in unverified domain" }
    ],
    "model_factors": [
      { "feature_name": "brand_mismatch", "human_name": "Brand Mismatch", "attribution": 0.28 }
    ]
  },
  "simple_explanation": {
    "language": "en",
    "verdict": "Suspicious",
    "title": "Warning: Suspicious Link",
    "summary": "This link looks unusual and may lead to a fake website. Do not enter passwords, OTPs, or banking details.",
    "what_to_do": "Do not enter passwords or OTPs here. Open the official website directly."
  }
}
2. Health & Model Status
code
Http
GET /api/health
code
JSON
{
  "status": "healthy",
  "service": "URL-Guard",
  "model_loaded": true,
  "feature_count": 34,
  "version": "1.0.0"
}
3. Model Information & Metrics
code
Http
GET /api/model-info
4. Supported Languages
code
Http
GET /api/languages
5. Download Extension ZIP
code
Http
GET /api/extension/download
🚢 Public Deployment Guide
The backend is 100% self-contained in Node.js and requires no external databases or Python runtimes.
Option 1: 1-Click Deploy on Render (Recommended)
Fork or push this repository to GitHub.
Sign in to render.com and click New + > Web Service.
Select your repository. Render will automatically detect render.yaml.
Add your GEMINI_API_KEY (optional) in Environment Variables.
Click Create Web Service. Your public HTTPS API will be live in 2 minutes (e.g., https://url-guard-api.onrender.com).
In your Chrome extension, click the Settings (⚙️) icon, paste the public URL, and click Test followed by Save!
Option 2: Google Cloud Run / Container Deploy
Deploy using the included production Dockerfile:
code
Bash
# Build container image
docker build -t url-guard:latest .

# Run container locally
docker run -p 3000:3000 url-guard:latest
🧪 Automated Test Suite
URL Guard includes 60 automated tests with zero external dependencies:
code
Bash
# Run all test suites
npm test
Test Breakdown:
tests/test_regression.mjs (34 tests): Verifies legitimate top-tier domains, known phishing attacks, IOC threat intelligence feeds, multi-language explainers, and non-HTTP scheme rejection.
tests/test_threshold_boundaries.mjs (17 tests): Tests exact floating-point boundary behavior (0.37, 0.38, 0.50, 0.81, 0.82) and indicator provenance.
tests/test_extension_sync.mjs (9 tests): Validates Manifest V3 compliance, backend error recovery, prevention of false Safe results, and end-to-end synchronization.
📁 Repository Structure
code
Text
├── app/
│   ├── classifier.js        # Core decision logic and threshold evaluator
│   ├── explainer.js         # Multilingual Gemini and deterministic NLP explainer
│   └── static/              # Web dashboard frontend assets and bundles
├── extension/               # Chrome Extension (Manifest V3)
│   ├── background.js        # Centralized service worker
│   ├── content.js           # In-page warning banner
│   ├── manifest.json        # Extension manifest
│   ├── popup.html / .js     # Popup UI & backend API client
│   └── icons/               # Extension icons
├── models/
│   ├── model_export.json    # Trained Random Forest model (tree ensemble)
│   ├── thresholds.json      # Operational threshold configuration
│   └── metrics.json         # Evaluation metrics and ROC-AUC scores
├── data/
│   └── intel_feed.txt       # Local Threat Intelligence IOCs
├── scripts/
│   ├── make_icons.js        # Programmatic icon generator
│   └── package_extension.js # Automatic JSZip extension packager
├── tests/                   # Automated test suites
├── Dockerfile               # Production container definition
├── render.yaml              # 1-click cloud deployment config
├── server.js                # Express backend server with CORS & rate limiting
└── package.json             # Build scripts and dependencies
🛡️ License
Distributed under the MIT License. Free for educational, commercial, and research use.
