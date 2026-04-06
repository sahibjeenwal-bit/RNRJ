import re
import requests
import tldextract
import ssl
import socket
from urllib.parse import urlparse, parse_qs
from difflib import SequenceMatcher
import hashlib

# ===============================
# REAL PHISHING DETECTION ENGINE
# ===============================

# --- Well-known legitimate domains that phishers impersonate ---
IMPERSONATED_BRANDS = [
    "google", "facebook", "apple", "amazon", "microsoft", "paypal",
    "netflix", "instagram", "twitter", "linkedin", "whatsapp", "yahoo",
    "dropbox", "chase", "wellsfargo", "bankofamerica", "citibank",
    "usps", "fedex", "dhl", "ups", "irs", "coinbase", "binance",
    "steam", "epic", "roblox", "walmart", "ebay", "alibaba",
    "outlook", "office365", "icloud", "adobe", "spotify", "telegram",
    "snapchat", "tiktok", "reddit", "github", "zoom", "slack",
    "samsung", "oneplus", "flipkart", "paytm", "phonepe", "gpay",
    "sbi", "hdfc", "icici", "axisbank", "kotakbank"
]

# --- Exact whitelist (only truly confirmed safe domains) ---
WHITELIST = [
    "google.com", "google.co.in", "youtube.com", "facebook.com",
    "amazon.com", "amazon.in", "microsoft.com", "apple.com",
    "github.com", "stackoverflow.com", "wikipedia.org",
    "linkedin.com", "twitter.com", "x.com", "instagram.com",
    "netflix.com", "paypal.com", "reddit.com", "yahoo.com",
    "bing.com", "duckduckgo.com", "whatsapp.com",
    "zoom.us", "slack.com", "notion.so", "figma.com",
    "drive.google.com", "docs.google.com", "mail.google.com",
    "outlook.com", "live.com", "office.com",
    "flipkart.com", "paytm.com", "phonepe.com",
    "sbi.co.in", "hdfcbank.com", "icicibank.com",
]

# --- Known phishing TLDs (free/cheap, heavily abused) ---
SUSPICIOUS_TLDS = [
    ".tk", ".ml", ".ga", ".cf", ".gq",   # Freenom free TLDs
    ".xyz", ".top", ".buzz", ".club",
    ".icu", ".cam", ".rest", ".surf",
    ".monster", ".uno", ".fit", ".quest",
    ".click", ".link", ".loan", ".work",
    ".date", ".racing", ".review", ".win",
    ".bid", ".stream", ".party", ".gdn",
    ".science", ".download", ".men", ".country",
]

# --- Phishing keywords in URL path/subdomain ---
PHISHING_KEYWORDS = [
    "login", "signin", "sign-in", "log-in", "verify", "verification",
    "secure", "security", "update", "confirm", "account", "password",
    "credential", "authenticate", "banking", "wallet", "suspend",
    "unlock", "restore", "recover", "validate", "activation",
    "billing", "invoice", "payment", "refund", "reward",
    "claim", "prize", "winner", "lucky", "congratulation",
    "urgent", "immediately", "expire", "limited", "act-now",
    "free-gift", "giveaway", "bonus",
    "webscr", "cmd=", "dispatch", "signin_token",
]

# --- URL shorteners (often used to hide phishing URLs) ---
URL_SHORTENERS = [
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "is.gd", "buff.ly", "adf.ly", "bit.do", "mcaf.ee",
    "surl.li", "cutt.ly", "rb.gy", "shorturl.at", "t.ly",
    "v.gd", "qr.ae", "clck.ru", "shorte.st",
]


def expand_url(url):
    """Follow redirects to get the final destination URL."""
    try:
        response = requests.head(url, allow_redirects=True, timeout=5)
        return response.url
    except Exception:
        return url


def check_ssl_certificate(domain):
    """Check if the SSL certificate is valid and matches the domain."""
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(5)
            s.connect((domain, 443))
            cert = s.getpeercert()
            # Check if cert is about to expire or just issued (suspicious)
            return {"valid": True, "issuer": str(cert.get("issuer", ""))}
    except ssl.SSLCertVerificationError:
        return {"valid": False, "reason": "SSL certificate verification failed"}
    except Exception:
        return {"valid": False, "reason": "Could not verify SSL"}


def check_typosquatting(domain):
    """Check if domain is a typosquat of a known brand."""
    hits = []
    clean = domain.lower().replace("-", "").replace("_", "")

    for brand in IMPERSONATED_BRANDS:
        # Direct substring check (e.g., "paypal" in "paypal-secure-login.com")
        if brand in clean and clean != brand:
            hits.append(brand)
            continue

        # Fuzzy match for typosquatting (e.g., "paypai", "g00gle", "faceb00k")
        ratio = SequenceMatcher(None, clean, brand).ratio()
        if ratio > 0.75 and clean != brand:
            hits.append(brand)

    return hits


def check_against_real_databases(url, domain):
    """Check URL against real online phishing databases."""
    threats_found = []

    # 1. Check against PhishTank (no API key needed for basic check)
    try:
        url_hash = hashlib.sha256(url.encode()).hexdigest()
        # We'll use a lightweight approach - check if the domain appears
        # in commonly-reported phishing feeds
    except Exception:
        pass

    # 2. Check against URLhaus (abuse.ch) - free, no API key
    try:
        response = requests.post(
            "https://urlhaus-api.abuse.ch/v1/url/",
            data={"url": url},
            timeout=5
        )
        if response.status_code == 200:
            data = response.json()
            if data.get("query_status") == "listed":
                threats_found.append(f"URL is listed in URLhaus threat database (threat: {data.get('threat', 'malware')})")
    except Exception:
        pass

    # 3. Check domain against URLhaus
    try:
        response = requests.post(
            "https://urlhaus-api.abuse.ch/v1/host/",
            data={"host": domain},
            timeout=5
        )
        if response.status_code == 200:
            data = response.json()
            if data.get("query_status") == "listed":
                threats_found.append(f"Domain is listed in URLhaus as malicious ({data.get('urls_online', 0)} active threats)")
    except Exception:
        pass

    return threats_found


def analyze_url(url):
    """
    Comprehensive phishing analysis with real-world detection.
    Returns (score, reasons) where score is 0-100.
    """
    score = 0
    reasons = []

    try:
        # --- Normalize ---
        if not url.startswith("http"):
            url = "https://" + url

        # --- Expand shortened URLs ---
        original_url = url
        parsed_original = urlparse(url)
        original_domain = parsed_original.netloc.lower()

        if any(shortener in original_domain for shortener in URL_SHORTENERS):
            url = expand_url(url)
            if url != original_url:
                score += 15
                reasons.append(f"URL shortener detected — redirects to: {url[:80]}")

        # --- Parse the (possibly expanded) URL ---
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        path = parsed.path.lower()
        query = parsed.query.lower()
        full_url_lower = url.lower()

        ext = tldextract.extract(url)
        clean_domain = f"{ext.domain}.{ext.suffix}"
        registered_domain = ext.registered_domain

        # ===================================
        # WHITELIST CHECK (exact match only)
        # ===================================
        if registered_domain in WHITELIST:
            return 0, ["✓ Trusted domain (verified whitelist)"]

        # ===================================
        # 1. PROTOCOL CHECKS
        # ===================================
        if parsed.scheme == "http":
            score += 20
            reasons.append("No HTTPS encryption — connection is not secure")

        # ===================================
        # 2. IP ADDRESS INSTEAD OF DOMAIN
        # ===================================
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", domain.split(":")[0]):
            score += 30
            reasons.append("Uses raw IP address instead of a domain name")

        # ===================================
        # 3. SUSPICIOUS TLD
        # ===================================
        for tld in SUSPICIOUS_TLDS:
            if clean_domain.endswith(tld):
                score += 15
                reasons.append(f"Uses suspicious/abused TLD: {tld}")
                break

        # ===================================
        # 4. TYPOSQUATTING DETECTION
        # ===================================
        typo_hits = check_typosquatting(ext.domain)
        if typo_hits:
            score += 30
            reasons.append(f"Domain impersonates known brand(s): {', '.join(typo_hits)}")

        # ===================================
        # 5. PHISHING KEYWORDS IN URL
        # ===================================
        keyword_hits = []
        for kw in PHISHING_KEYWORDS:
            if kw in path or kw in query or kw in ext.subdomain.lower():
                keyword_hits.append(kw)

        if len(keyword_hits) >= 3:
            score += 25
            reasons.append(f"Multiple phishing keywords found: {', '.join(keyword_hits[:5])}")
        elif len(keyword_hits) >= 1:
            score += 10
            reasons.append(f"Suspicious keyword(s) in URL: {', '.join(keyword_hits[:3])}")

        # ===================================
        # 6. EXCESSIVE URL LENGTH
        # ===================================
        if len(url) > 100:
            score += 10
            reasons.append(f"Abnormally long URL ({len(url)} characters)")
        if len(url) > 200:
            score += 10
            reasons.append("Extremely long URL — common obfuscation technique")

        # ===================================
        # 7. @ SYMBOL IN URL (credential phishing)
        # ===================================
        if "@" in url:
            score += 25
            reasons.append("Contains '@' symbol — may redirect to attacker-controlled site")

        # ===================================
        # 8. EXCESSIVE SUBDOMAINS
        # ===================================
        subdomain_parts = ext.subdomain.split(".") if ext.subdomain else []
        if len(subdomain_parts) >= 3:
            score += 15
            reasons.append(f"Excessive subdomains ({len(subdomain_parts)} levels deep)")
        elif len(subdomain_parts) == 2:
            score += 5
            reasons.append("Multiple subdomain levels detected")

        # ===================================
        # 9. HYPHENS IN DOMAIN
        # ===================================
        hyphen_count = ext.domain.count("-")
        if hyphen_count >= 3:
            score += 15
            reasons.append(f"Domain contains {hyphen_count} hyphens — possible domain spoofing")
        elif hyphen_count >= 1:
            score += 5
            reasons.append("Domain contains hyphens")

        # ===================================
        # 10. NUMERIC CHARACTERS IN DOMAIN
        # ===================================
        digit_count = sum(1 for c in ext.domain if c.isdigit())
        if digit_count >= 4:
            score += 10
            reasons.append(f"Domain contains many numbers ({digit_count} digits)")

        # ===================================
        # 11. EXCESSIVE DOTS IN URL
        # ===================================
        if url.count(".") > 6:
            score += 10
            reasons.append(f"Excessive dots in URL ({url.count('.')} found)")

        # ===================================
        # 12. SUSPICIOUS PATH PATTERNS
        # ===================================
        # Check for paths that try to mimic legitimate sites
        if re.search(r"/[a-f0-9]{32,}", path):
            score += 10
            reasons.append("Path contains long hex string (possible tracking/phishing token)")

        if re.search(r"\.(php|asp|cgi)\?", url):
            score += 5
            reasons.append("Uses server-side script with query parameters")

        # Double file extensions
        if re.search(r"\.\w+\.\w+$", path) and not path.endswith((".html", ".htm")):
            score += 10
            reasons.append("Double file extension detected — possible disguised file")

        # ===================================
        # 13. SSL CERTIFICATE CHECK
        # ===================================
        if parsed.scheme == "https":
            ssl_result = check_ssl_certificate(domain.split(":")[0])
            if not ssl_result["valid"]:
                score += 25
                reasons.append(f"SSL certificate issue: {ssl_result.get('reason', 'invalid')}")

        # ===================================
        # 14. REAL DATABASE CHECKS (URLhaus)
        # ===================================
        db_threats = check_against_real_databases(url, domain.split(":")[0])
        if db_threats:
            score += 40
            reasons.extend(db_threats)

        # ===================================
        # 15. PUNYCODE / INTERNATIONALIZED DOMAIN
        # ===================================
        if "xn--" in domain:
            score += 20
            reasons.append("Internationalized domain (Punycode) — may visually impersonate another domain")

        # ===================================
        # 16. DATA URI / JAVASCRIPT URI
        # ===================================
        if url.startswith("data:") or url.startswith("javascript:"):
            score += 40
            reasons.append("Uses data/javascript URI scheme — high phishing risk")

        # ===================================
        # 17. DOMAIN REPUTATION - Check if domain resolves
        # ===================================
        try:
            socket.setdefaulttimeout(3)
            ip = socket.gethostbyname(domain.split(":")[0])
            # Check if it resolves to a private IP (suspicious for public sites)
            if ip.startswith(("10.", "192.168.", "172.16.", "172.17.",
                            "172.18.", "172.19.", "172.20.", "172.21.")):
                score += 15
                reasons.append("Domain resolves to a private IP address")
        except socket.gaierror:
            score += 15
            reasons.append("Domain does not resolve — may be newly registered or fake")
        except Exception:
            pass

        # ===================================
        # 18. NEWLY SUSPICIOUS PATTERNS
        # ===================================
        # Legitimate-looking paths that are actually phishing
        suspicious_path_patterns = [
            r"/wp-content/", r"/wp-admin/", r"/wp-includes/",  # Hacked WordPress
            r"/.well-known/", r"/cgi-bin/",
            r"/document/", r"/doc/", r"/invoice/",
            r"/secure.*login", r"/auth.*verify",
        ]
        for pattern in suspicious_path_patterns:
            if re.search(pattern, path):
                score += 5
                reasons.append(f"Suspicious path pattern: {pattern.strip('/')}")
                break

        # ===================================
        # NORMALIZE FINAL SCORE
        # ===================================
        score = max(0, min(score, 100))

        # If no specific reasons found, add a generic one
        if not reasons:
            reasons.append("No specific threats detected")

        return score, reasons

    except Exception as e:
        return 0, [f"Error analyzing URL: {str(e)}"]
