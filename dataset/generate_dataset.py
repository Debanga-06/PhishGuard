"""
Synthetic Dataset Generator for Phishing URL Detection.

Generates a realistic labeled dataset of phishing and legitimate URLs
based on statistical properties observed in real-world datasets
(UCI Phishing Dataset, PhishTank, Alexa Top 1M).

Run: python dataset/generate_dataset.py
"""

import random
import csv
import os
import string

random.seed(42)

OUTPUT_FILE = os.path.join(os.path.dirname(__file__), "phishing_urls.csv")

# ── Legitimate URL components ──────────────────────────────────────────────────
LEGIT_DOMAINS = [
    "google.com", "youtube.com", "facebook.com", "wikipedia.org",
    "amazon.com", "reddit.com", "twitter.com", "instagram.com",
    "linkedin.com", "github.com", "stackoverflow.com", "medium.com",
    "bbc.co.uk", "cnn.com", "nytimes.com", "theguardian.com",
    "apple.com", "microsoft.com", "netflix.com", "spotify.com",
    "airbnb.com", "booking.com", "tripadvisor.com", "yelp.com",
    "shopify.com", "etsy.com", "ebay.com", "walmart.com",
    "coursera.org", "udemy.com", "khanacademy.org", "edx.org",
    "healthline.com", "webmd.com", "mayoclinic.org", "nih.gov",
    "nasa.gov", "whitehouse.gov", "canada.ca", "gov.uk",
]

LEGIT_PATHS = [
    "/", "/about", "/contact", "/products", "/services",
    "/blog", "/news", "/faq", "/help", "/support",
    "/search?q=weather", "/article/12345", "/user/profile",
    "/category/technology", "/page/privacy-policy",
]

SUSPICIOUS_KEYWORDS = [
    "login", "signin", "verify", "secure", "account", "update",
    "banking", "password", "confirm", "validate", "free", "winner",
    "prize", "urgent", "alert", "suspend", "recover", "unlock"
]

BRAND_NAMES = [
    "paypal", "apple", "google", "amazon", "microsoft", "facebook",
    "netflix", "instagram", "twitter", "chase", "wellsfargo", "citibank"
]

SUSPICIOUS_TLDS = [".tk", ".ml", ".ga", ".cf", ".xyz", ".top", ".work", ".click"]

SHORTENERS = ["bit.ly", "tinyurl.com", "goo.gl", "ow.ly"]


def random_string(length: int, chars=string.ascii_lowercase + string.digits) -> str:
    return "".join(random.choices(chars, k=length))


def random_ip() -> str:
    return ".".join(str(random.randint(1, 254)) for _ in range(4))


# ── Legitimate URL generators ─────────────────────────────────────────────────

def gen_legit_url() -> str:
    scheme = "https://" if random.random() > 0.05 else "http://"
    domain = random.choice(LEGIT_DOMAINS)
    path = random.choice(LEGIT_PATHS)
    sub = random.choice(["", "www.", "m.", "en."])
    return f"{scheme}{sub}{domain}{path}"


def gen_legit_blog() -> str:
    words = ["how-to", "best", "guide", "top10", "review", "tutorial"]
    domain = random.choice(LEGIT_DOMAINS)
    slug = "-".join(random.choices(words, k=random.randint(2, 4)))
    return f"https://www.{domain}/blog/{slug}"


# ── Phishing URL generators ───────────────────────────────────────────────────

def gen_phishing_ip() -> str:
    """IP-based phishing URL."""
    ip = random_ip()
    kw = random.choice(SUSPICIOUS_KEYWORDS)
    return f"http://{ip}/{kw}/index.php"


def gen_phishing_typosquat() -> str:
    """Typosquatted brand + suspicious TLD."""
    brand = random.choice(BRAND_NAMES)
    tld = random.choice(SUSPICIOUS_TLDS)
    action = random.choice(SUSPICIOUS_KEYWORDS)
    return f"http://www.{brand}-{action}{tld}/{action}.php"


def gen_phishing_subdomain_abuse() -> str:
    """Brand in subdomain, random domain."""
    brand = random.choice(BRAND_NAMES)
    kw = random.choice(SUSPICIOUS_KEYWORDS)
    garbage = random_string(8)
    return f"http://{brand}.{kw}.{garbage}.com/auth/login"


def gen_phishing_long_url() -> str:
    """Very long obfuscated phishing URL."""
    brand = random.choice(BRAND_NAMES)
    kw = random.choice(SUSPICIOUS_KEYWORDS)
    garbage = random_string(random.randint(20, 40))
    tld = random.choice(SUSPICIOUS_TLDS)
    token = random_string(16, string.hexdigits)
    return (
        f"http://secure-{brand}-{kw}-{garbage}{tld}"
        f"/redirect?token={token}&src=email&lang=en"
    )


def gen_phishing_at_symbol() -> str:
    """@ symbol trick."""
    brand = random.choice(BRAND_NAMES)
    kw = random.choice(SUSPICIOUS_KEYWORDS)
    real_target = random_string(10)
    return f"http://www.{brand}.com@{real_target}.xyz/{kw}"


def gen_phishing_redirect() -> str:
    """Open redirect with URL in query string."""
    kw = random.choice(SUSPICIOUS_KEYWORDS)
    brand = random.choice(BRAND_NAMES)
    target = f"http%3A%2F%2Fmalicious-{random_string(6)}.tk%2Fsteal"
    return f"http://{brand}-{kw}.net/redirect?url={target}"


def gen_phishing_shortener() -> str:
    """Link shortener hiding phishing URL."""
    shortener = random.choice(SHORTENERS)
    code = random_string(6)
    return f"http://{shortener}/{code}"


def gen_phishing_keyword_stuffed() -> str:
    """Many suspicious keywords in path."""
    kws = random.sample(SUSPICIOUS_KEYWORDS, k=random.randint(3, 5))
    brand = random.choice(BRAND_NAMES)
    path = "/".join(kws)
    tld = random.choice(SUSPICIOUS_TLDS)
    return f"http://{brand}-secure-update{tld}/{path}/form.html"


PHISHING_GENERATORS = [
    gen_phishing_ip,
    gen_phishing_typosquat,
    gen_phishing_subdomain_abuse,
    gen_phishing_long_url,
    gen_phishing_at_symbol,
    gen_phishing_redirect,
    gen_phishing_shortener,
    gen_phishing_keyword_stuffed,
]

LEGIT_GENERATORS = [gen_legit_url, gen_legit_blog]


def generate_dataset(n_legit: int = 5000, n_phishing: int = 5000) -> str:
    rows = []

    print(f"Generating {n_legit} legitimate URLs...")
    for _ in range(n_legit):
        gen = random.choice(LEGIT_GENERATORS)
        rows.append({"url": gen(), "label": 0})  # 0 = legitimate

    print(f"Generating {n_phishing} phishing URLs...")
    for _ in range(n_phishing):
        gen = random.choice(PHISHING_GENERATORS)
        rows.append({"url": gen(), "label": 1})  # 1 = phishing

    random.shuffle(rows)

    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
    with open(OUTPUT_FILE, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["url", "label"])
        writer.writeheader()
        writer.writerows(rows)

    print(f"\n✅ Dataset saved to: {OUTPUT_FILE}")
    print(f"   Total samples : {len(rows)}")
    print(f"   Legitimate    : {n_legit}")
    print(f"   Phishing      : {n_phishing}")
    return OUTPUT_FILE


if __name__ == "__main__":
    generate_dataset()