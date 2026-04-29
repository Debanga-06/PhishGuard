"""
Logging system — stores all URL checks with timestamps and results.
"""

import json
import os
from datetime import datetime, timezone
from typing import Dict, Optional

LOG_FILE = os.path.join(os.path.dirname(__file__), "..", "logs", "scan_history.jsonl")


def _ensure_log_dir():
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)


def log_scan(
    url: str,
    prediction: str,
    confidence: float,
    risk_level: str,
    blacklisted: bool = False,
    model_used: str = "ensemble",
    features: Optional[Dict] = None,
):
    _ensure_log_dir()
    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "url": url,
        "prediction": prediction,
        "confidence": round(confidence, 4),
        "risk_level": risk_level,
        "blacklisted": blacklisted,
        "model_used": model_used,
    }
    if features:
        record["features"] = features

    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(record) + "\n")


def get_recent_scans(limit: int = 50) -> list:
    _ensure_log_dir()
    if not os.path.exists(LOG_FILE):
        return []
    records = []
    with open(LOG_FILE, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    return list(reversed(records[-limit:]))


def get_stats() -> Dict:
    records = get_recent_scans(limit=10000)
    if not records:
        return {"total": 0, "phishing": 0, "legitimate": 0, "phishing_rate": 0}
    total = len(records)
    phishing = sum(1 for r in records if r.get("prediction") == "phishing")
    return {
        "total": total,
        "phishing": phishing,
        "legitimate": total - phishing,
        "phishing_rate": round(phishing / total * 100, 1),
    }