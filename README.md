# 🛡️ LinkShield

**LinkShield** is a Python-based URL analysis tool that detects phishing links, tunnel services, typosquatting, homograph attacks, and more — all from your terminal.

> ⚠️ **Disclaimer:** This tool is for educational purposes only. Only scan URLs you own or have permission to test.

---

## ✨ Features

| Check | Description |
|---|---|
| 🔐 Protocol | Detects HTTP vs HTTPS |
| 🌐 IP in URL | Flags raw IP addresses used instead of domains |
| 🕳️ Tunnel Services | Detects ngrok, loclx, serveo, and 15+ others |
| 🎲 Random Subdomain | Shannon entropy analysis on subdomains |
| 🔤 Typosquatting | Levenshtein distance against 30+ known brands |
| 🌀 Homograph Attack | Detects mixed Unicode scripts in domain |
| 🏷️ Suspicious TLD | Flags `.tk`, `.xyz`, `.zip`, `.ml`, and more |
| 🔗 URL Shorteners | Detects bit.ly, tinyurl, and 15+ shorteners |
| 🧩 Brand in Subdomain | Catches `google.com.evil.xyz` tricks |
| 🔑 Suspicious Keywords | Scans for phishing-related words in URL |
| 🔒 SSL Mismatch | Flags sites that are online but have invalid SSL |
| 📏 URL Length | Penalizes abnormally long URLs |

---

## 📦 Installation

```bash
git clone https://github.com/andersonphonom-ui/linkshield.git
cd linkshield

pip install -r requirements.txt --break-system-packages

sudo cp main.py /usr/local/bin/linkshield
sudo cp linkshield_banner.py linkshield_scanner.py /usr/local/bin/

sudo chmod +x /usr/local/bin/linkshield

linkshield --version
```

---

## 🚀 Usage

```bash
linkshield
```

Then enter any URL when prompted:

```
🔗 Enter URL to scan: https://ppiybxtccq.loclx.io
```

---

## 📊 Example Output

```
================================
       LinkShield Report
================================

URL            : https://ppiybxtccq.loclx.io
Protocol       : HTTPS ✅
Domain         : ppiybxtccq.loclx.io
IP Address     : Unavailable
Website Status : Online ✅
Response Time  : 1.764s
SSL Certificate: Invalid ❌
Risk Level     : Critical 🔴

Phishing Score : 100/100 — Dangerous 🔴

Phishing Analysis:
  - Tunnel service detected: loclx.io — hides real server identity
  - Random-looking subdomain: 'ppiybxtccq' — typical in auto-generated phishing URLs
  - Site is online but SSL certificate is invalid — high risk

================================
     Scan Completed 🛡️
================================
```

---

## 📁 Project Structure

```
linkshield/
├── main.py          # Entry point
├── scanner.py       # Phishing detection engine
├── banner.py        # ASCII art banner
├── requirements.txt
├── .gitignore
└── README.md
```

---

## 🧠 How the Scoring Works

Each detected indicator adds points to a risk score (0–100):

| Level | Score | Meaning |
|---|---|---|
| Safe ✅ | 0 | No indicators found |
| Low Risk 🟢 | 1–20 | Minor concerns |
| Suspicious 🟡 | 21–45 | Proceed with caution |
| High Risk 🟠 | 46–70 | Likely malicious |
| Dangerous 🔴 | 71–100 | Do not visit |

---

## 👨‍💻 Author

**Youssef Mediouni**
- YouTube: [PH4nt0m CYber](https://youtube.com/@PH4nt0mCYber)
- GitHub: [@andersonphonom-ui]

---

## 📄 License

MIT License — free to use, modify, and distribute.
