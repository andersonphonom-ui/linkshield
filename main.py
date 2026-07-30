#!/usr/bin/env python3
import time
import argparse
import validators
import tldextract
from urllib.parse import urlparse
from rich.console import Console
from rich.table import Table
from rich import box

from banner import show_banner
from scanner import (
    get_ip,
    check_status,
    get_response_time,
    check_ssl,
    calculate_risk,
    check_phishing
)

console = Console()

VERSION = "1.0.0"

# ─── Argument Parser ──────────────────────────────────────────
parser = argparse.ArgumentParser(
    prog="linkshield",
    description="LinkShield — Python URL Phishing Analyzer",
    epilog="Example: python3 main.py -u https://example.com"
)
parser.add_argument(
    "-u", "--url",
    help="URL to scan",
    type=str
)
parser.add_argument(
    "-v", "--version",
    action="version",
    version=f"LinkShield v{VERSION}"
)

args = parser.parse_args()

# ─── Banner ───────────────────────────────────────────────────
show_banner()
time.sleep(0.5)

# ─── Get URL ─────────────────────────────────────────────────
if args.url:
    url = args.url
else:
    url = input("🔗 Enter URL to scan: ")

print("\nStarting Scan...\n")
time.sleep(0.5)

# ─── Validate ────────────────────────────────────────────────
if not validators.url(url):
    console.print("[bold red]❌ Invalid URL[/bold red]")
    exit(1)

# ─── Scan ────────────────────────────────────────────────────
extract  = tldextract.extract(url)
domain   = extract.domain + "." + extract.suffix
hostname = urlparse(url).hostname or domain

protocol = "HTTPS ✅" if url.startswith("https://") else "HTTP ⚠️"

ip                    = get_ip(hostname)
status, is_online     = check_status(url)
response_time         = get_response_time(url)
ssl_status, ssl_valid = check_ssl(hostname)
phishing              = check_phishing(url, ssl_valid=ssl_valid, status_online=is_online)
risk                  = calculate_risk(phishing["score"])

# ─── Results Table ───────────────────────────────────────────
table = Table(
    title="🛡️  LinkShield Report",
    box=box.DOUBLE_EDGE,
    style="cyan",
    title_style="bold cyan",
    header_style="bold magenta",
    show_lines=True
)

table.add_column("Property", style="bold white", width=20)
table.add_column("Value", style="green", width=45)

table.add_row("URL", url)
table.add_row("Protocol", protocol)
table.add_row("Domain", hostname)
table.add_row("IP Address", ip)
table.add_row("Website Status", status)
table.add_row("Response Time", f"{response_time}s" if response_time else "Unknown")
table.add_row("SSL Certificate", ssl_status)
table.add_row("Risk Level", risk)
table.add_row("Phishing Score", f"{phishing['score']}/100 — {phishing['level']}")

console.print()
console.print(table)

# ─── Phishing Details Table ──────────────────────────────────
detail_table = Table(
    title="🔍 Phishing Analysis",
    box=box.SIMPLE_HEAVY,
    style="yellow",
    title_style="bold yellow",
    header_style="bold red",
    show_lines=True
)

detail_table.add_column("#", style="dim", width=3)
detail_table.add_column("Finding", style="white", width=60)

for i, warning in enumerate(phishing["warnings"], 1):
    detail_table.add_row(str(i), warning)

console.print()
console.print(detail_table)
console.print()
console.print("[bold green]Scan Completed 🛡️[/bold green]\n")
