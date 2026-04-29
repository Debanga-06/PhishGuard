import requests
import json
import os
import time

API_KEY = os.getenv("PHISHTANK_API_KEY", "")
CACHE_FILE = os.path.join(os.path.dirname(__file__), "..", "dataset", "phishtank_cache.json")
CACHE_TTL = 1800  # refresh every 30 minutes

def fetch_phishtank_urls() -> set:
    # Use cached data if still fresh
    if os.path.exists(CACHE_FILE):
        age = time.time() - os.path.getmtime(CACHE_FILE)
        if age < CACHE_TTL:
            with open(CACHE_FILE) as f:
                return set(json.load(f))

    if not API_KEY:
        return set()

    try:
        url = f"http://data.phishtank.com/data/{API_KEY}/online-valid.json"
        response = requests.get(url, timeout=30)
        data = response.json()
        phishing_urls = {entry["url"] for entry in data}

        os.makedirs(os.path.dirname(CACHE_FILE), exist_ok=True)
        with open(CACHE_FILE, "w") as f:
            json.dump(list(phishing_urls), f)

        print(f"✅ PhishTank: loaded {len(phishing_urls)} URLs")
        return phishing_urls

    except Exception as e:
        print(f"⚠️ PhishTank fetch failed: {e}")
        return set()


def is_phishtank_phishing(url: str) -> bool:
    known = fetch_phishtank_urls()
    return url.strip() in known