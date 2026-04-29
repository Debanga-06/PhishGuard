# 🛡 PhishGuard — Phishing URL Detection System

> A production-grade, ML-powered phishing URL detection system with a real-time web UI, REST API, CLI tool, and full model explainability.

![Python](https://img.shields.io/badge/Python-3.9+-blue?logo=python)
![scikit-learn](https://img.shields.io/badge/scikit--learn-1.5-orange?logo=scikit-learn)
![XGBoost](https://img.shields.io/badge/XGBoost-2.1-red)
![Flask](https://img.shields.io/badge/Flask-3.0-black?logo=flask)
![Streamlit](https://img.shields.io/badge/Streamlit-1.40-red?logo=streamlit)

---

## 📋 Table of Contents

- [Features](#features)
- [Architecture](#architecture)
- [Project Structure](#project-structure)
- [Quick Start](#quick-start)
- [Usage](#usage)
- [ML Models](#ml-models)
- [Feature Engineering](#feature-engineering)
- [API Reference](#api-reference)
- [Evaluation Metrics](#evaluation-metrics)
- [Dataset](#dataset)
- [Deployment](#deployment)

---

## ✨ Features

| Feature | Description |
|---|---|
| 🤖 **3-Model Comparison** | Logistic Regression, Random Forest, XGBoost — best auto-selected |
| 🔍 **23 URL Features** | Rich feature engineering specific to phishing patterns |
| ⚡ **Fast Inference** | <100ms per prediction after model load |
| 🌐 **Flask Web App** | Full-stack web UI + REST API (`/predict`) |
| 📊 **Streamlit App** | Interactive data science dashboard with radar charts |
| 🖥 **CLI Tool** | Batch scanning from command line |
| 🚫 **Blacklist Check** | Domain blacklist + regex pattern matching |
| 📝 **Audit Logging** | Every scan logged with timestamp, result, features |
| 💡 **Explainability** | Why-is-this-phishing breakdown with severity levels |
| 🎨 **Risk Levels** | LOW / MEDIUM / HIGH risk classification |
| 🐳 **Docker Ready** | Dockerfile + docker-compose for instant deployment |
| 🔒 **Rate Limiting** | Per-IP rate limiting on API endpoints |

---

## 🏗 Architecture

```
URL Input
    │
    ▼
┌─────────────────────────────────────────┐
│         Feature Extraction Pipeline     │
│  (23 URL features: length, IP, TLD,     │
│   keywords, entropy, subdomains, ...)   │
└───────────────────┬─────────────────────┘
                    │
          ┌─────────▼──────────┐
          │   Blacklist Check  │ ←─ known phishing domains
          └─────────┬──────────┘
                    │
          ┌─────────▼──────────┐
          │   ML Model         │ ←─ best of LR / RF / XGB
          │   predict_proba()  │
          └─────────┬──────────┘
                    │
          ┌─────────▼──────────┐
          │   Risk Classifier  │
          │   LOW/MEDIUM/HIGH  │
          └─────────┬──────────┘
                    │
          ┌─────────▼──────────┐
          │   Explainer        │
          │   (why suspicious) │
          └─────────┬──────────┘
                    │
              ┌─────▼─────┐
              │   Logger  │
              └───────────┘
                    │
        ┌───────────┼───────────┐
        ▼           ▼           ▼
   Flask API   Streamlit    CLI Output
```

---

## 📁 Project Structure

```
phishing-detector/
│
├── 🧠 Core
│   ├── train.py              # Train & compare all models, save best
│   ├── predict.py            # Prediction engine + CLI tool
│   ├── app.py                # Flask web app + REST API
│   └── streamlit_app.py      # Streamlit interactive dashboard
│
├── 🔧 Utils
│   └── utils/
│       ├── __init__.py
│       ├── feature_extractor.py  # 23 URL feature functions
│       ├── blacklist.py           # Domain blacklist + regex checker
│       └── logger.py              # Scan audit logger
│
├── 📊 Data
│   └── dataset/
│       ├── generate_dataset.py   # Synthetic dataset generator
│       └── phishing_urls.csv     # Generated/downloaded dataset
│
├── 💾 Models (auto-generated)
│   └── models/
│       ├── best_model.pkl         # Best performing model
│       ├── scaler.pkl             # Feature scaler
│       ├── model_meta.pkl         # Model metadata & metrics
│       ├── logistic_regression.pkl
│       ├── random_forest.pkl
│       ├── xgboost.pkl
│       └── reports/               # Training visualizations
│           ├── confusion_matrices.png
│           ├── roc_curves.png
│           ├── metrics_comparison.png
│           └── feature_importance.png
│
├── 📝 Logs (auto-generated)
│   └── logs/
│       └── scan_history.jsonl     # Audit log of all URL scans
│
├── 🐳 Deployment
│   ├── Dockerfile
│   ├── .env.example
│   └── requirements.txt
│
└── 📖 README.md
```

---

## 🚀 Quick Start

### Option A: Local Setup

```bash
# 1. Clone / download the project
cd phishing-detector

# 2. Install dependencies
pip install -r requirements.txt

# 3. Generate dataset + train models
python train.py

# 4. Launch the web app
python app.py
# → Open http://localhost:5000
```

### Option B: Docker

```bash
# Build and run (trains the model inside the container)
docker build -t phishguard .
docker run -p 5000:5000 phishguard

# → Open http://localhost:5000
```

---

## 🎯 Usage

### 1. Web App (Flask)

```bash
python app.py
```
Open **http://localhost:5180** in your browser.

Features:
- URL input field with example presets
- Color-coded prediction banner (green/red)
- Confidence %, risk level, scan time
- Suspicious feature explanations
- Live scan history table
- Aggregate statistics

### 2. Interactive Dashboard (Streamlit)

```bash
streamlit run streamlit_app.py
```
Features:
- Gauge chart for phishing probability
- Feature risk radar chart
- Sidebar statistics panel
- Raw feature inspection table

### 3. CLI Tool

```bash
# Single URL
python predict.py "https://google.com"
python predict.py "http://paypa1-secure-verify.tk/login"

# Batch scanning from file
python predict.py --batch urls.txt

# JSON output (for pipelines)
python predict.py "https://example.com" --json

# Pipe-friendly exit code: 0 = safe, 1 = phishing
python predict.py "http://malicious.tk/login" ; echo $?
```

### 4. REST API

```bash
# Predict endpoint
curl -X POST http://localhost:5000/predict \
  -H "Content-Type: application/json" \
  -d '{"url": "http://paypa1-secure-verify.tk/login"}'
```

Response:
```json
{
  "url": "http://paypa1-secure-verify.tk/login",
  "prediction": "phishing",
  "confidence": 0.9987,
  "phishing_probability": 0.9987,
  "risk_level": "HIGH",
  "blacklisted": false,
  "blacklist_reason": null,
  "features": {
    "url_length": 38,
    "has_ip_address": 0,
    "suspicious_keyword_count": 3,
    ...
  },
  "explanations": [
    {"feature": "tld_suspicious", "message": "URL uses a suspicious TLD (.tk)", "severity": "high"},
    {"feature": "suspicious_keyword_count", "message": "Contains 3 suspicious keywords", "severity": "medium"}
  ],
  "model_name": "XGBoost",
  "prediction_time_ms": 4.2
}
```

Other endpoints:
```bash
GET /history   # Recent scan history (last 20)
GET /stats     # Aggregate statistics
GET /health    # Health check
```

---

## 🧠 ML Models

Three models trained and compared automatically. Best selected by F1-score.

| Model | Pros | Cons |
|---|---|---|
| **Logistic Regression** | Fast, interpretable, good baseline | Assumes linearity |
| **Random Forest** | Robust, feature importance, handles non-linearity | Slower inference |
| **XGBoost** | Best accuracy, gradient boosting, handles class imbalance | Needs tuning |

**Training pipeline:**
1. Load/generate labeled URL dataset
2. Extract 23 features per URL
3. StandardScaler normalization (for LR)
4. 80/20 stratified train/test split
5. Train all 3 models
6. Evaluate: Accuracy, Precision, Recall, F1, AUC-ROC
7. Save best model + scaler + metadata

---

## 🔬 Feature Engineering (23 Features)

| # | Feature | Description | Phishing Signal |
|---|---|---|---|
| 1 | `url_length` | Total URL character count | >75 chars = suspicious |
| 2 | `has_ip_address` | IP address instead of domain | ✅ Strong |
| 3 | `dot_count` | Number of dots in URL | Many dots = subdomain abuse |
| 4 | `uses_https` | HTTPS protocol | No HTTPS = insecure |
| 5 | `suspicious_keyword_count` | login, verify, secure, etc. | ✅ Strong |
| 6 | `brand_keyword_count` | paypal, apple, google, etc. | ✅ Strong |
| 7 | `at_symbol_count` | @ redirects to real host | ✅ Classic attack |
| 8 | `double_slash_count` | // outside scheme = redirect | ✅ Strong |
| 9 | `dash_count` | Dashes in domain | Typosquatting |
| 10 | `subdomain_count` | Number of subdomains | >3 = suspicious |
| 11 | `path_length` | Length of URL path | Very long = suspicious |
| 12 | `query_length` | Query string length | Long queries hide intent |
| 13 | `fragment_present` | # anchor fragment | Unusual presence |
| 14 | `num_query_params` | Count of query parameters | Many params = suspicious |
| 15 | `special_char_count` | !, $, %, ^, &, *, etc. | Obfuscation |
| 16 | `digit_ratio` | Ratio of digits to total chars | High ratio = suspicious |
| 17 | `path_depth` | Directory depth in path | Very deep = suspicious |
| 18 | `is_shortened` | bit.ly, tinyurl.com, etc. | ✅ Hides destination |
| 19 | `has_port` | Non-standard port in URL | Unusual in legit sites |
| 20 | `domain_length` | Length of domain name | Very short/long = suspicious |
| 21 | `tld_suspicious` | .tk, .ml, .xyz, .work, etc. | ✅ Strong |
| 22 | `entropy` | Shannon entropy of URL | High = random-looking |
| 23 | `has_redirect` | URL embedded in query string | ✅ Open redirect |

---

## 📊 Evaluation Metrics

After training, visualizations are saved to `models/reports/`:

- **`confusion_matrices.png`** — True/False positive breakdown per model
- **`roc_curves.png`** — ROC curves with AUC scores for all 3 models
- **`metrics_comparison.png`** — Side-by-side bar chart of all metrics
- **`feature_importance.png`** — Top 15 most important features

Run evaluation separately:
```bash
python train.py
# Check models/reports/ for all charts
```

---

## 📦 Dataset

### Built-in Synthetic Dataset (default)

Generated by `dataset/generate_dataset.py` — 10,000 URLs (5k legit, 5k phishing) with realistic patterns based on known phishing techniques.

```bash
python dataset/generate_dataset.py  # Regenerate
```

### Real-World Datasets (recommended for production)

| Dataset | Source | Size | Notes |
|---|---|---|---|
| **UCI Phishing Websites** | [Kaggle](https://www.kaggle.com/datasets/eswarchandt/phishing-website-detector) | 11k | Feature-rich |
| **PhishTank URLs** | [phishtank.org](https://www.phishtank.com/developer_info.php) | 1M+ | Live feed |
| **Malicious URLs Dataset** | [Kaggle](https://www.kaggle.com/datasets/sid321axn/malicious-urls-dataset) | 651k | 4 classes |
| **URLhaus** | [urlhaus.abuse.ch](https://urlhaus.abuse.ch/api/) | Live | Malware URLs |

To use a real dataset:
```bash
# Download CSV with 'url' and 'label' columns (0=legit, 1=phishing)
python train.py --csv /path/to/your/dataset.csv
```

---

## 🐳 Deployment

### Docker (Recommended)

```bash
# Build image
docker build -t phishguard:latest .

# Run
docker run -d \
  -p 5000:5000 \
  --name phishguard \
  phishguard:latest

# With environment variables
docker run -d \
  -p 5000:5000 \
  -e PORT=5000 \
  -e FLASK_DEBUG=false \
  --name phishguard \
  phishguard:latest
```

### Production with Gunicorn

```bash
pip install gunicorn
gunicorn --bind 0.0.0.0:5000 --workers 4 --timeout 60 app:app
```

### Environment Variables

| Variable | Default | Description |
|---|---|---|
| `PORT` | `5000` | Flask server port |
| `FLASK_DEBUG` | `false` | Enable debug mode |

---

## 🔒 Security Notes

- Rate limiting: 30 requests/minute per IP (configurable in `app.py`)
- URL length capped at 2048 characters
- No external DNS lookups by default (fast, offline-capable)
- All scan data stored locally in JSONL format
- For production, add authentication middleware before deploying publicly

---

## 🧪 Testing URLs

Safe:
```
https://google.com
https://github.com/login
https://en.wikipedia.org/wiki/Python
```

Phishing (test patterns):
```
http://paypa1-secure-verify.tk/login
http://192.168.1.1/banking/signin
http://apple.verify.account-secure.xyz/id/login
http://www.paypal-security.com/account/update
http://bit.ly/xK8pQr
```

---

## 📈 Performance

| Metric | Value |
|---|---|
| Prediction time | ~4-15ms (after model load) |
| Model load time | ~200ms (one-time, at startup) |
| Feature extraction | ~1ms per URL |
| API throughput | ~200 req/s (single worker) |

---

## 🤝 Contributing

1. Fork the repo
2. Add real URL datasets to `dataset/`
3. Improve features in `utils/feature_extractor.py`
4. Integrate WHOIS lookup for domain age feature
5. Add Google Safe Browsing API for production blacklist
6. Submit a PR!

---

## 📄 License

MIT License — Free to use, modify, and distribute.

---