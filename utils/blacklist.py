"""
Blacklist checker — checks domain against known phishing domain lists.
In production, replace with live feeds (PhishTank, OpenPhish, Google Safe Browsing API).
"""

import tldextract
from typing import Tuple, Optional
import re

# Static known-bad domain list 
KNOWN_PHISHING_DOMAINS = {
    # PayPal phishing
    "paypa1.com", "paypal-security.com", "paypalverify.net",
    "secure-paypal.com", "paypal-login.net",

    # Apple phishing
    "apple-verify.com", "appleid-locked.com", "icloud-signin.net",
    "apple-account-support.com",

    # Banking
    "bank0famerica.com", "wellsfargo-secure.com", "chase-verify.com",
    "citibank-update.net",

    # Generic phishing infrastructure
    "secure-login-verify.com", "account-verification.net",
    "update-account-info.com", "verify-now.net",
    "login-secure-update.com", "signin-verification.com",

    # Known test/demo malicious URLs (for demo purposes)
    "phishing-demo.com", "malicious-site.net",
}

# Malicious patterns 
MALICIOUS_PATTERNS = [
    re.compile(r'paypa[l1].*\.(com|net|org)', re.I),
    re.compile(r'app[l1]e.*secur', re.I),
    re.compile(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}.*login', re.I),
    re.compile(r'(login|signin|verify).*-.*\.(tk|ml|ga|cf|xyz)', re.I),
    re.compile(r'(secure|account|update).*paypal', re.I),
]


def check_blacklist(url: str) -> Tuple[bool, Optional[str]]:
    """
    Returns (is_blacklisted, reason_or_None).
    """
    url_lower = url.lower().strip()

    # Extract domain
    try:
        ext = tldextract.extract(url_lower)
        domain = f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain
        full_domain = f"{ext.subdomain}.{domain}" if ext.subdomain else domain
    except Exception:
        domain = url_lower
        full_domain = url_lower

    # Check exact domain match
    if domain in KNOWN_PHISHING_DOMAINS or full_domain in KNOWN_PHISHING_DOMAINS:
        return True, f"Domain '{domain}' is on the phishing blacklist"

    # Check regex patterns
    for pattern in MALICIOUS_PATTERNS:
        if pattern.search(url_lower):
            return True, f"URL matches known phishing pattern: {pattern.pattern}"

    return False, None


def get_domain(url: str) -> str:
    try:
        ext = tldextract.extract(url)
        if ext.suffix:
            return f"{ext.domain}.{ext.suffix}"
        return ext.domain
    except Exception:
        return url