"""
predict.py — Prediction engine and CLI tool.

Usage:
    python predict.py "https://example.com"
    python predict.py --batch urls.txt
"""

import sys
import os
import argparse
import time
import json

# ── Load .env first, before anything else ─────────────────────────────────────
from dotenv import load_dotenv
load_dotenv()

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)

import joblib
import numpy as np

from utils.feature_extractor import extract_features, features_to_vector, explain_features
from utils.blacklist import check_blacklist
from utils.logger import log_scan
from utils.phishtank import is_phishtank_phishing
from utils.safe_browsing import check_google_safe_browsing

MODELS_DIR  = os.path.join(BASE_DIR, "models")
BEST_MODEL  = os.path.join(MODELS_DIR, "best_model.pkl")
SCALER_PATH = os.path.join(MODELS_DIR, "scaler.pkl")
META_PATH   = os.path.join(MODELS_DIR, "model_meta.pkl")


# ── Singleton loader ───────────────────────────────────────────────────────────

_model  = None
_scaler = None
_meta   = None


def load_artifacts():
    global _model, _scaler, _meta
    if _model is not None:
        return _model, _scaler, _meta
    if not os.path.exists(BEST_MODEL):
        raise FileNotFoundError(
            "Model not found. Run 'python train.py' first."
        )
    _model  = joblib.load(BEST_MODEL)
    _scaler = joblib.load(SCALER_PATH)
    _meta   = joblib.load(META_PATH)
    return _model, _scaler, _meta


# ── Risk level helper ──────────────────────────────────────────────────────────

def get_risk_level(prob_phishing: float, is_blacklisted: bool) -> str:
    if is_blacklisted or prob_phishing >= 0.85:
        return "HIGH"
    if prob_phishing >= 0.55:
        return "MEDIUM"
    return "LOW"


# ── Core prediction ────────────────────────────────────────────────────────────

def predict(url: str, do_log: bool = True) -> dict:
    """
    4-layer detection pipeline:
      Layer 1 → Local blacklist       (fastest, no network)
      Layer 2 → Google Safe Browsing  (real-time, authoritative)
      Layer 3 → PhishTank database    (community-verified)
      Layer 4 → ML model              (catches new/unknown phishing)

    Returns:
    {
        "url": str,
        "prediction": "phishing" | "legitimate",
        "confidence": float,
        "phishing_probability": float,
        "risk_level": "LOW" | "MEDIUM" | "HIGH",
        "blacklisted": bool,
        "blacklist_reason": str | None,
        "detection_source": str,
        "features": dict,
        "explanations": list,
        "model_name": str,
        "prediction_time_ms": float,
    }
    """
    t0 = time.perf_counter()
    detection_source = "ml_model"

    # ── Layer 1: Local blacklist (no API call, ~0ms) ───────────────────────────
    is_blacklisted, bl_reason = check_blacklist(url)
    if is_blacklisted:
        detection_source = "local_blacklist"

    # ── Layer 2: Google Safe Browsing (~50ms, most authoritative) ─────────────
    if not is_blacklisted:
        gsb = check_google_safe_browsing(url)
        if gsb["is_threat"]:
            is_blacklisted = True
            bl_reason      = f"Google Safe Browsing: {gsb['threat_type']}"
            detection_source = "google_safe_browsing"

    # ── Layer 3: PhishTank database (~0ms cached, 200ms on refresh) ───────────
    if not is_blacklisted:
        if is_phishtank_phishing(url):
            is_blacklisted = True
            bl_reason      = "Found in PhishTank verified phishing database"
            detection_source = "phishtank"

    # ── Layer 4: ML model (catches new phishing not in any database) ──────────
    features = extract_features(url)
    vector   = np.array(features_to_vector(features)).reshape(1, -1)

    model, scaler, meta = load_artifacts()
    if meta.get("uses_scaler", False):
        vector = scaler.transform(vector)

    proba      = model.predict_proba(vector)[0]   # [p_legit, p_phishing]
    prob_phish = float(proba[1])
    prob_legit = float(proba[0])

    # Blacklist detection forces high phishing probability
    if is_blacklisted:
        prob_phish = max(prob_phish, 0.97)

    prediction = "phishing" if prob_phish >= 0.5 else "legitimate"
    confidence = prob_phish if prediction == "phishing" else prob_legit
    risk_level = get_risk_level(prob_phish, is_blacklisted)

    # ── Explanations ───────────────────────────────────────────────────────────
    explanations = explain_features(features)

    # Prepend blacklist explanation if triggered
    if is_blacklisted and bl_reason:
        explanations.insert(0, {
            "feature": "blacklist",
            "message": bl_reason,
            "severity": "high"
        })

    elapsed_ms = (time.perf_counter() - t0) * 1000

    result = {
        "url":                  url,
        "prediction":           prediction,
        "confidence":           round(confidence, 4),
        "phishing_probability": round(prob_phish, 4),
        "risk_level":           risk_level,
        "blacklisted":          is_blacklisted,
        "blacklist_reason":     bl_reason,
        "detection_source":     detection_source,
        "features":             features,
        "explanations":         explanations,
        "model_name":           meta.get("model_name", "unknown"),
        "prediction_time_ms":   round(elapsed_ms, 2),
    }

    if do_log:
        log_scan(
            url=url,
            prediction=prediction,
            confidence=confidence,
            risk_level=risk_level,
            blacklisted=is_blacklisted,
            model_used=detection_source,
        )

    return result


# CLI 

COLORS = {
    "red":    "\033[91m",
    "green":  "\033[92m",
    "yellow": "\033[93m",
    "blue":   "\033[94m",
    "cyan":   "\033[96m",
    "bold":   "\033[1m",
    "reset":  "\033[0m",
}

def c(text, color):
    return f"{COLORS[color]}{text}{COLORS['reset']}"


def print_result(res: dict):
    pred   = res["prediction"]
    conf   = res["confidence"] * 100
    risk   = res["risk_level"]
    bl     = res["blacklisted"]
    exps   = res["explanations"]
    ms     = res["prediction_time_ms"]
    source = res.get("detection_source", "ml_model")

    # Map detection source to readable label
    source_labels = {
        "local_blacklist":     "Local Blacklist",
        "google_safe_browsing":"Google Safe Browsing",
        "phishtank":           "PhishTank Database",
        "ml_model":            res["model_name"],
    }
    source_label = source_labels.get(source, source)

    print()
    print(c("━" * 60, "blue"))
    print(c("  PHISHGUARD — URL SAFETY ANALYZER", "bold"))
    print(c("━" * 60, "blue"))
    print(f"\n  URL         : {c(res['url'], 'cyan')}")

    if pred == "phishing":
        label = c("⚠  PHISHING", "red")
    else:
        label = c("✓  LEGITIMATE", "green")

    print(f"  Result      : {c(label, 'bold')}")
    print(f"  Confidence  : {conf:.1f}%")

    risk_color = {"HIGH": "red", "MEDIUM": "yellow", "LOW": "green"}[risk]
    print(f"  Risk Level  : {c(risk, risk_color)}")
    print(f"  Detected by : {source_label}")
    print(f"  Scan Time   : {ms:.1f}ms")

    if bl:
        print(f"\n  {c('🚫 BLACKLISTED', 'red')}: {res['blacklist_reason']}")

    if exps:
        print(f"\n  {c('Suspicious signals detected:', 'yellow')}")
        for exp in exps[:6]:
            sev_color = {"high": "red", "medium": "yellow", "low": "cyan"}[exp["severity"]]
            prefix    = {"high": "✗ HIGH", "medium": "! MED ", "low": "· LOW "}[exp["severity"]]
            print(f"    {c(prefix, sev_color)} {exp['message']}")

    print()
    print(c("━" * 60, "blue"))
    print()


def cli_main():
    parser = argparse.ArgumentParser(
        description="PhishGuard — Phishing URL Detector",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python predict.py https://google.com\n"
            "  python predict.py http://paypa1-secure.tk/login\n"
            "  python predict.py --batch urls.txt\n"
            "  python predict.py https://example.com --json"
        )
    )
    parser.add_argument("url", nargs="?", help="URL to analyze")
    parser.add_argument("--batch", help="Text file with one URL per line")
    parser.add_argument("--json", action="store_true", help="Output raw JSON")
    args = parser.parse_args()

    if args.batch:
        with open(args.batch) as f:
            urls = [line.strip() for line in f if line.strip()]

        results = []
        phishing_count = 0

        for url in urls:
            res = predict(url)
            results.append(res)
            if res["prediction"] == "phishing":
                phishing_count += 1
            if not args.json:
                print_result(res)

        if not args.json:
            print(c(f"\n  Batch complete: {len(urls)} scanned, "
                    f"{phishing_count} phishing detected\n", "bold"))
        else:
            print(json.dumps(results, indent=2))
        return

    if not args.url:
        parser.print_help()
        sys.exit(1)

    res = predict(args.url)

    if args.json:
        print(json.dumps(res, indent=2))
    else:
        print_result(res)

    sys.exit(0 if res["prediction"] == "legitimate" else 1)


if __name__ == "__main__":
    cli_main()