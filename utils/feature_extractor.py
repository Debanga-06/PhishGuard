"""
URL Feature Extractor for Phishing Detection
Extracts 20+ engineered features from raw URLs
"""

import re
import urllib.parse
from typing import Dict, List, Optional
import tldextract
import math


# ── Suspicious keyword lists ──────────────────────────────────────────────────
SUSPICIOUS_KEYWORDS = [
    "login", "signin", "verify", "verification", "secure", "security",
    "account", "update", "banking", "paypal", "password", "credential",
    "confirm", "validate", "webscr", "ebayisapi", "free", "lucky",
    "winner", "prize", "urgent", "support", "service", "recover",
    "suspension", "limited", "unusual", "activity", "alert"
]

BRAND_KEYWORDS = [
    "paypal", "apple", "google", "amazon", "microsoft", "facebook",
    "netflix", "instagram", "twitter", "linkedin", "dropbox", "adobe",
    "chase", "wellsfargo", "bankofamerica", "citibank", "usps", "fedex"
]

SHORTENERS = [
    "bit.ly", "tinyurl.com", "goo.gl", "ow.ly", "t.co", "is.gd",
    "buff.ly", "adf.ly", "short.link", "rebrand.ly", "cutt.ly"
]


# ── Individual feature functions ──────────────────────────────────────────────

def _url_length(url: str) -> int:
    return len(url)


def _has_ip_address(url: str) -> int:
    ip_pattern = re.compile(
        r'(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)'
    )
    return int(bool(ip_pattern.search(url)))


def _dot_count(url: str) -> int:
    return url.count(".")


def _uses_https(url: str) -> int:
    return int(url.lower().startswith("https://"))


def _suspicious_keyword_count(url: str) -> int:
    url_lower = url.lower()
    return sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in url_lower)


def _brand_keyword_count(url: str) -> int:
    url_lower = url.lower()
    return sum(1 for kw in BRAND_KEYWORDS if kw in url_lower)


def _at_symbol_count(url: str) -> int:
    return url.count("@")


def _double_slash_count(url: str) -> int:
    # Count // after the scheme
    stripped = re.sub(r'^https?://', '', url)
    return stripped.count("//")


def _dash_count(url: str) -> int:
    parsed = urllib.parse.urlparse(url)
    return parsed.netloc.count("-")


def _subdomain_count(url: str) -> int:
    ext = tldextract.extract(url)
    if ext.subdomain:
        return len(ext.subdomain.split("."))
    return 0


def _path_length(url: str) -> int:
    parsed = urllib.parse.urlparse(url)
    return len(parsed.path)


def _query_length(url: str) -> int:
    parsed = urllib.parse.urlparse(url)
    return len(parsed.query)


def _fragment_present(url: str) -> int:
    parsed = urllib.parse.urlparse(url)
    return int(bool(parsed.fragment))


def _num_query_params(url: str) -> int:
    parsed = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qs(parsed.query)
    return len(params)


def _special_char_count(url: str) -> int:
    specials = re.findall(r'[!$%^&*()+|~=`{}\[\]:;<>?,\\]', url)
    return len(specials)


def _digit_ratio(url: str) -> float:
    if not url:
        return 0.0
    digits = sum(1 for c in url if c.isdigit())
    return round(digits / len(url), 4)


def _path_depth(url: str) -> int:
    parsed = urllib.parse.urlparse(url)
    parts = [p for p in parsed.path.split("/") if p]
    return len(parts)


def _is_shortened(url: str) -> int:
    url_lower = url.lower()
    return int(any(s in url_lower for s in SHORTENERS))


def _has_port(url: str) -> int:
    parsed = urllib.parse.urlparse(url)
    return int(bool(parsed.port))


def _domain_length(url: str) -> int:
    ext = tldextract.extract(url)
    return len(ext.domain)


def _tld_suspicious(url: str) -> int:
    suspicious_tlds = {
        ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".work",
        ".click", ".link", ".win", ".download", ".stream", ".party",
        ".review", ".science", ".loan", ".country"
    }
    ext = tldextract.extract(url)
    return int(f".{ext.suffix}" in suspicious_tlds)


def _entropy(url: str) -> float:
    """Shannon entropy of the URL string."""
    if not url:
        return 0.0
    freq = {}
    for c in url:
        freq[c] = freq.get(c, 0) + 1
    n = len(url)
    return round(-sum((f/n) * math.log2(f/n) for f in freq.values()), 4)


def _has_redirect(url: str) -> int:
    """Simple heuristic: URL contains another URL in query string."""
    parsed = urllib.parse.urlparse(url)
    return int("http" in parsed.query.lower())


# ── Main extractor ─────────────────────────────────────────────────────────────

FEATURE_NAMES = [
    "url_length",
    "has_ip_address",
    "dot_count",
    "uses_https",
    "suspicious_keyword_count",
    "brand_keyword_count",
    "at_symbol_count",
    "double_slash_count",
    "dash_count",
    "subdomain_count",
    "path_length",
    "query_length",
    "fragment_present",
    "num_query_params",
    "special_char_count",
    "digit_ratio",
    "path_depth",
    "is_shortened",
    "has_port",
    "domain_length",
    "tld_suspicious",
    "entropy",
    "has_redirect",
]


def extract_features(url: str) -> Dict[str, float]:
    """
    Extract all features from a URL.
    Returns ordered dict matching FEATURE_NAMES.
    """
    url = url.strip()

    # Add scheme if missing so urlparse works properly
    if not re.match(r'^https?://', url, re.I):
        url_for_parse = "http://" + url
    else:
        url_for_parse = url

    features = {
        "url_length":               _url_length(url),
        "has_ip_address":           _has_ip_address(url),
        "dot_count":                _dot_count(url),
        "uses_https":               _uses_https(url),
        "suspicious_keyword_count": _suspicious_keyword_count(url),
        "brand_keyword_count":      _brand_keyword_count(url),
        "at_symbol_count":          _at_symbol_count(url),
        "double_slash_count":       _double_slash_count(url),
        "dash_count":               _dash_count(url_for_parse),
        "subdomain_count":          _subdomain_count(url_for_parse),
        "path_length":              _path_length(url_for_parse),
        "query_length":             _query_length(url_for_parse),
        "fragment_present":         _fragment_present(url_for_parse),
        "num_query_params":         _num_query_params(url_for_parse),
        "special_char_count":       _special_char_count(url),
        "digit_ratio":              _digit_ratio(url),
        "path_depth":               _path_depth(url_for_parse),
        "is_shortened":             _is_shortened(url),
        "has_port":                 _has_port(url_for_parse),
        "domain_length":            _domain_length(url_for_parse),
        "tld_suspicious":           _tld_suspicious(url_for_parse),
        "entropy":                  _entropy(url),
        "has_redirect":             _has_redirect(url_for_parse),
    }
    return features


def features_to_vector(features: Dict[str, float]) -> List[float]:
    """Convert feature dict to ordered list matching FEATURE_NAMES."""
    return [features[name] for name in FEATURE_NAMES]


def explain_features(features: Dict[str, float]) -> List[Dict]:
    """
    Return human-readable explanations of suspicious features.
    """
    explanations = []

    checks = [
        ("has_ip_address",            lambda v: v == 1,
         "URL uses an IP address instead of a domain name (classic phishing tactic)"),
        ("uses_https",                lambda v: v == 0,
         "URL does not use HTTPS — connection is unencrypted"),
        ("suspicious_keyword_count",  lambda v: v >= 2,
         f"Contains {int(features['suspicious_keyword_count'])} suspicious keywords (e.g. login, verify, secure)"),
        ("brand_keyword_count",       lambda v: v >= 1,
         f"Mentions {int(features['brand_keyword_count'])} well-known brand(s) — possible impersonation"),
        ("at_symbol_count",           lambda v: v >= 1,
         "URL contains '@' symbol — used to redirect to a different host"),
        ("double_slash_count",        lambda v: v >= 1,
         "URL contains '//' redirection outside the scheme"),
        ("tld_suspicious",            lambda v: v == 1,
         "URL uses a suspicious TLD (e.g. .tk, .xyz, .ml)"),
        ("is_shortened",              lambda v: v == 1,
         "URL uses a link shortener — hides the real destination"),
        ("subdomain_count",           lambda v: v >= 3,
         f"Unusually many subdomains ({int(features['subdomain_count'])}) — may mask real domain"),
        ("dash_count",                lambda v: v >= 3,
         f"Domain has {int(features['dash_count'])} dashes — common in typosquatting"),
        ("url_length",                lambda v: v > 75,
         f"URL is very long ({int(features['url_length'])} chars) — often used to hide intent"),
        ("entropy",                   lambda v: v > 4.5,
         f"High character entropy ({features['entropy']:.2f}) — URL looks randomly generated"),
        ("has_redirect",              lambda v: v == 1,
         "Query string contains another URL — possible open redirect"),
        ("has_ip_address",            lambda v: v == 1,
         "IP-based URL bypasses DNS and reputation systems"),
        ("has_port",                  lambda v: v == 1,
         "Non-standard port used — legitimate sites rarely expose custom ports"),
        ("digit_ratio",               lambda v: v > 0.25,
         f"High proportion of digits ({features['digit_ratio']*100:.0f}%) — suspicious pattern"),
    ]

    seen = set()
    for key, condition, message in checks:
        if key not in seen and condition(features[key]):
            explanations.append({"feature": key, "message": message, "severity": _severity(key)})
            seen.add(key)

    return explanations


def _severity(feature_key: str) -> str:
    high = {"has_ip_address", "at_symbol_count", "double_slash_count",
            "tld_suspicious", "brand_keyword_count", "has_redirect"}
    medium = {"suspicious_keyword_count", "is_shortened", "subdomain_count",
               "uses_https", "dash_count", "entropy"}
    if feature_key in high:
        return "high"
    if feature_key in medium:
        return "medium"
    return "low"