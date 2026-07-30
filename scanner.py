import socket
import requests
import time
import ssl
import re
import unicodedata
import math
from urllib.parse import urlparse


# ═══════════════════════════════════════════════════════════════
#  DATABASES
# ═══════════════════════════════════════════════════════════════

SUSPICIOUS_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top",
    ".click", ".loan", ".work", ".party", ".win", ".download",
    ".zip", ".mov", ".men", ".gdn", ".stream", ".racing",
    ".accountant", ".faith", ".review", ".trade", ".date"
}

TUNNEL_SERVICES = {
    "loclx.io", "ngrok.io", "ngrok-free.app", "ngrok.app",
    "serveo.net", "localhost.run", "trycloudflare.com",
    "pagekite.me", "bore.pub", "localtunnel.me",
    "telebit.io", "expose.sh", "tunnel.us.ngrok.com",
    "loca.lt", "forward.example.com", "hookdeck.com",
    "webhookrelay.com", "tunnelto.dev", "pinggy.io"
}

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "short.link", "rb.gy", "cutt.ly", "shorturl.at",
    "is.gd", "buff.ly", "tiny.cc", "lnkd.in", "bl.ink",
    "rebrand.ly", "switchy.io", "clck.ru", "qps.ru"
}

KNOWN_BRANDS = [
    "google", "facebook", "paypal", "apple", "microsoft",
    "amazon", "netflix", "instagram", "twitter", "whatsapp",
    "youtube", "linkedin", "tiktok", "snapchat", "discord",
    "github", "binance", "coinbase", "ebay", "yahoo",
    "dropbox", "spotify", "twitch", "reddit", "pinterest",
    "telegram", "outlook", "office365", "onedrive", "icloud",
    "chase", "wellsfargo", "citibank", "bankofamerica"
]

SUSPICIOUS_KEYWORDS = [
    "login", "verify", "update", "password", "account",
    "bank", "confirm", "secure", "signin", "validation",
    "authenticate", "free", "winner", "prize", "urgent",
    "suspended", "unusual", "activity", "limited", "access",
    "click", "here", "now", "alert", "immediately",
    "recover", "unlock", "billing", "invoice", "refund"
]

# ═══════════════════════════════════════════════════════════════
#  HELPERS
# ═══════════════════════════════════════════════════════════════

def _get_hostname(url):
    try:
        return urlparse(url).hostname or ""
    except Exception:
        return ""


def _get_root_domain(hostname):
    """Returns root domain e.g. 'evil.loclx.io' -> 'loclx.io'"""
    parts = hostname.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return hostname


def _entropy(s):
    """Shannon entropy — high entropy = random-looking string"""
    if not s:
        return 0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    length = len(s)
    return -sum((f / length) * math.log2(f / length) for f in freq.values())


# ═══════════════════════════════════════════════════════════════
#  DETECTION FUNCTIONS
# ═══════════════════════════════════════════════════════════════

def has_homograph_attack(hostname):
    try:
        scripts = set()
        for char in hostname:
            if char in ".-":
                continue
            name = unicodedata.name(char, "")
            if "LATIN" in name:
                scripts.add("LATIN")
            elif "CYRILLIC" in name:
                scripts.add("CYRILLIC")
            elif "GREEK" in name:
                scripts.add("GREEK")
            elif "ARABIC" in name:
                scripts.add("ARABIC")
        return len(scripts) > 1
    except Exception:
        return False


def levenshtein(s1, s2):
    if len(s1) < len(s2):
        return levenshtein(s2, s1)
    if len(s2) == 0:
        return len(s1)
    prev = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        curr = [i + 1]
        for j, c2 in enumerate(s2):
            curr.append(min(prev[j + 1] + 1, curr[j] + 1, prev[j] + (c1 != c2)))
        prev = curr
    return prev[len(s2)]


def check_typosquatting(hostname):
    """
    Checks root domain core against known brands.
    'paypa1.com' -> catches 'paypal'
    Also checks if brand name is embedded in a longer domain.
    """
    root = _get_root_domain(hostname)
    core = root.split(".")[0].lower()

    for brand in KNOWN_BRANDS:
        if core == brand:
            return None  # exact = legit
        # Levenshtein distance
        if len(core) >= len(brand) - 2:
            dist = levenshtein(core, brand)
            if 0 < dist <= 2:
                return brand
        # Brand embedded in longer domain: "paypal-secure.com"
        if brand in core and core != brand:
            return brand

    return None


def has_ip_in_url(url):
    return bool(re.match(r"https?://(\d{1,3}\.){3}\d{1,3}", url))


def count_subdomains(hostname):
    parts = hostname.split(".")
    return max(0, len(parts) - 2)


def has_suspicious_tld(hostname):
    for tld in SUSPICIOUS_TLDS:
        if hostname.endswith(tld):
            return tld
    return None


def is_tunnel_service(hostname):
    root = _get_root_domain(hostname)
    return root if root in TUNNEL_SERVICES else None


def is_url_shortener(hostname):
    root = _get_root_domain(hostname)
    return root if root in URL_SHORTENERS else None


def has_random_subdomain(hostname):
    """
    Detects high-entropy subdomains like 'ppiybxtccq.loclx.io'
    """
    parts = hostname.split(".")
    if len(parts) >= 3:
        sub = parts[0]
        if len(sub) >= 7 and re.match(r'^[a-z0-9]+$', sub):
            ent = _entropy(sub)
            if ent >= 3.2:  # high entropy threshold
                return sub
    return None


def has_misleading_domain(hostname):
    """
    Detects tricks like 'google.com.evil.xyz' where brand
    appears as subdomain but real domain is different.
    """
    root = _get_root_domain(hostname)
    subdomains = hostname.replace("." + root, "")
    for brand in KNOWN_BRANDS:
        if brand in subdomains.lower():
            return brand
    return None


def check_ssl_mismatch(status_online, ssl_valid):
    """Online but SSL invalid = suspicious"""
    return status_online and not ssl_valid


def has_special_chars_in_domain(hostname):
    """Detects encoded tricks like %20, -- patterns, etc."""
    if "%" in hostname:
        return True
    if "--" in hostname and not hostname.startswith("xn--"):
        return True
    return False


def count_dots_in_url(url):
    """Too many dots = suspicious"""
    parsed = urlparse(url)
    return parsed.hostname.count(".") if parsed.hostname else 0


# ═══════════════════════════════════════════════════════════════
#  MAIN PHISHING ENGINE
# ═══════════════════════════════════════════════════════════════

def check_phishing(url, ssl_valid=None, status_online=None):
    """
    Returns:
    {
        "score": int (0-100),
        "level": str,
        "warnings": [str],
        "details": {category: [findings]}
    }
    """
    warnings = []
    score = 0
    details = {}

    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    lower_url = url.lower()

    # ── 1. Protocol ──────────────────────────────────────────
    if url.startswith("http://"):
        warnings.append("No HTTPS — connection is unencrypted")
        score += 20
        details["Protocol"] = ["HTTP (no encryption)"]

    # ── 2. IP in URL ─────────────────────────────────────────
    if has_ip_in_url(url):
        warnings.append("Raw IP address used instead of domain")
        score += 35

    # ── 3. @ symbol ──────────────────────────────────────────
    if "@" in url:
        warnings.append("Contains @ — browser ignores everything before it")
        score += 30

    # ── 4. URL length ────────────────────────────────────────
    url_len = len(url)
    if url_len > 100:
        warnings.append(f"Suspicious URL length ({url_len} chars)")
        score += 10
    if url_len > 150:
        score += 10  # extra penalty

    # ── 5. Dots count ────────────────────────────────────────
    dots = count_dots_in_url(url)
    if dots >= 4:
        warnings.append(f"Too many dots in URL ({dots}) — redirection trick")
        score += 15

    # ── 6. Subdomain count ───────────────────────────────────
    sub_count = count_subdomains(hostname)
    if sub_count >= 3:
        warnings.append(f"Excessive subdomains ({sub_count})")
        score += 20

    # ── 7. Suspicious TLD ────────────────────────────────────
    bad_tld = has_suspicious_tld(hostname)
    if bad_tld:
        warnings.append(f"High-risk TLD: {bad_tld}")
        score += 25

    # ── 8. Tunnel service ────────────────────────────────────
    tunnel = is_tunnel_service(hostname)
    if tunnel:
        warnings.append(f"Tunnel service detected: {tunnel} — hides real server identity")
        score += 40

    # ── 9. Random subdomain (high entropy) ───────────────────
    rand_sub = has_random_subdomain(hostname)
    if rand_sub:
        warnings.append(f"Random-looking subdomain: '{rand_sub}' — typical in auto-generated phishing URLs")
        score += 30

    # ── 10. URL shortener ────────────────────────────────────
    shortener = is_url_shortener(hostname)
    if shortener:
        warnings.append(f"URL shortener: {shortener} — hides real destination")
        score += 20

    # ── 11. Homograph attack ─────────────────────────────────
    if has_homograph_attack(hostname):
        warnings.append("Homograph attack — mixed character scripts in domain")
        score += 45

    # ── 12. Typosquatting ────────────────────────────────────
    typo_brand = check_typosquatting(hostname)
    if typo_brand:
        warnings.append(f"Typosquatting of '{typo_brand}' detected")
        score += 40

    # ── 13. Brand as subdomain trick ─────────────────────────
    misleading = has_misleading_domain(hostname)
    if misleading:
        warnings.append(f"Brand '{misleading}' used as subdomain to appear legitimate")
        score += 45

    # ── 14. Suspicious keywords ──────────────────────────────
    found_kw = [w for w in SUSPICIOUS_KEYWORDS if w in lower_url]
    if found_kw:
        warnings.append(f"Suspicious keywords in URL: {', '.join(found_kw)}")
        score += min(len(found_kw) * 5, 25)

    # ── 15. Double slash trick ───────────────────────────────
    if re.search(r"https?://[^/]+//", url):
        warnings.append("Double slash in path — redirection trick")
        score += 15

    # ── 16. Special chars in domain ──────────────────────────
    if has_special_chars_in_domain(hostname):
        warnings.append("Special characters in domain — encoding trick")
        score += 20

    # ── 17. SSL mismatch (needs external data) ───────────────
    if ssl_valid is not None and status_online is not None:
        if check_ssl_mismatch(status_online, ssl_valid):
            warnings.append("Site is online but SSL certificate is invalid — high risk")
            score += 30

    # ── Cap & Level ──────────────────────────────────────────
    score = min(score, 100)

    if score == 0:
        level = "Safe ✅"
    elif score <= 20:
        level = "Low Risk 🟢"
    elif score <= 45:
        level = "Suspicious 🟡"
    elif score <= 70:
        level = "High Risk 🟠"
    else:
        level = "Dangerous 🔴"

    return {
        "score": score,
        "level": level,
        "warnings": warnings if warnings else ["No phishing indicators found"]
    }


# ═══════════════════════════════════════════════════════════════
#  NETWORK FUNCTIONS
# ═══════════════════════════════════════════════════════════════

def get_ip(domain):
    try:
        return socket.gethostbyname(domain)
    except Exception:
        return "Unavailable"


def check_status(url):
    try:
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            return "Online ✅", True
        return f"Online (Status: {response.status_code})", True
    except Exception:
        return "Offline ❌", False


def get_response_time(url):
    try:
        start = time.time()
        requests.get(url, timeout=5)
        return round(time.time() - start, 3)
    except Exception:
        return None


def check_ssl(domain):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain):
                return "Valid ✅", True
    except Exception:
        return "Invalid ❌", False


def calculate_risk(phishing_score):
    if phishing_score <= 10:
        return "Low 🟢"
    elif phishing_score <= 40:
        return "Medium 🟡"
    elif phishing_score <= 70:
        return "High 🟠"
    else:
        return "Critical 🔴"
