from banner import show_banner
from scanner import (
    get_ip,
    check_status,
    get_response_time,
    check_ssl,
    calculate_risk,
    check_phishing
)

import time
import validators
import tldextract
from urllib.parse import urlparse


show_banner()
time.sleep(1)

url = input("🔗 Enter URL to scan: ")
print("\nStarting Scan...\n")
time.sleep(1)

if validators.url(url):

    extract  = tldextract.extract(url)
    domain   = extract.domain + "." + extract.suffix        # root: loclx.io
    hostname = urlparse(url).hostname or domain             # full: ppiybxtccq.loclx.io

    protocol = "HTTPS ✅" if url.startswith("https://") else "HTTP ⚠️"

    ip                    = get_ip(hostname)
    status, is_online     = check_status(url)
    response_time         = get_response_time(url)
    ssl_status, ssl_valid = check_ssl(hostname)

    # Pass SSL + online status to phishing engine
    phishing = check_phishing(url, ssl_valid=ssl_valid, status_online=is_online)
    risk     = calculate_risk(phishing["score"])

    print("""
================================
       LinkShield Report
================================
""")

    print(f"URL            : {url}")
    print(f"Protocol       : {protocol}")
    print(f"Domain         : {hostname}")
    print(f"IP Address     : {ip}")
    print(f"Website Status : {status}")

    if response_time:
        print(f"Response Time  : {response_time}s")
    else:
        print("Response Time  : Unknown")

    print(f"SSL Certificate: {ssl_status}")
    print(f"Risk Level     : {risk}")
    print(f"\nPhishing Score : {phishing['score']}/100 — {phishing['level']}")

    print("\nPhishing Analysis:")
    for item in phishing["warnings"]:
        print("  -", item)

    print("""
================================
     Scan Completed 🛡️
================================
""")

else:
    print("Invalid URL ❌")
