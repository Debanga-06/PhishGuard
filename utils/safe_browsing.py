import requests
import os

API_KEY = os.getenv("GOOGLE_SAFE_BROWSING_KEY", "")
API_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

def check_google_safe_browsing(url: str) -> dict:
    if not API_KEY:
        return {"is_threat": False, "threat_type": None}

    payload = {
        "client": {
            "clientId": "phishguard",
            "clientVersion": "1.0"
        },
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION"
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }

    try:
        response = requests.post(
            API_URL,
            params={"key": API_KEY},
            json=payload,
            timeout=5
        )
        data = response.json()

        if data.get("matches"):
            threat_type = data["matches"][0]["threatType"]
            return {"is_threat": True, "threat_type": threat_type}

    except Exception as e:
        print(f"⚠️ Google Safe Browsing error: {e}")

    return {"is_threat": False, "threat_type": None}