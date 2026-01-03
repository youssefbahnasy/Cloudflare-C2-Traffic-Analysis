# Cloudflare-C2-Traffic-Analysis

Overview
This project documents a real-world network traffic investigation where malicious HTTP and TLS beaconing activity was identified behind Cloudflare infrastructure.

The attacker leveraged Cloudflare to hide the real command-and-control (C2) server, requiring deep traffic inspection, TLS SNI analysis, and OSINT pivoting.

---

## 🎯 Objective
- Detect malicious outbound traffic
- Analyze TLS handshake and HTTP behavior
- Identify attacker infrastructure hidden behind Cloudflare
- Extract actionable Indicators of Compromise (IOCs)

---

## 🧰 Tools Used
- Wireshark
- VirusTotal
- urlscan.io
- InfoSec Exchange

---

## 🔍 Initial Detection

Suspicious outbound HTTP POST requests were observed from an internal workstation:

- Randomized URI paths
- Fixed beacon intervals (~30 seconds)
- Small, consistent payload sizes

Example:
POST /gS1jCqsFm25cY&d50db1c8f3b479e17a996a76a77e4d54/vo6cqHO2 HTTP/1.1

---

## 🔐 TLS Analysis

TLS handshake analysis revealed suspicious Server Name Indication (SNI) values:

- dng-microsoftds.com
- event-time-microsoft.org
- eventdata-microsoft.live

These domains mimic legitimate Microsoft services, indicating typosquatting behavior.

---

## ☁️ Cloudflare Evasion

Multiple destination IPs were observed, all belonging to Cloudflare ASN.

This confirms deliberate use of Cloudflare to:
- Hide origin infrastructure
- Bypass IP-based detection
- Complicate attribution

---

## 🌐 OSINT Enrichment

### VirusTotal
The domain `hillcoweb.com` was flagged as suspicious.

### urlscan.io
Findings included:
- Repeated scans over multiple days
- Presence of `js.php` endpoint
- Minimal content size
- Single backend behavior

---

## 🔗 Attack Flow

TLS Client Hello (SNI)
↓
Initial HTTP GET
↓
Repeated HTTP POST Beaconing

---

## 🚨 Indicators of Compromise (IOCs)

### Domains
hillcoweb.com
dng-microsoftds.com
event-time-microsoft.org
eventdata-microsoft.live

### Network Indicators
- Repeated POST requests
- Randomized URI paths
- Beaconing intervals

---

## ✅ Conclusion

This case study demonstrates how encrypted traffic and CDN services like Cloudflare can be abused by attackers, and why behavioral analysis and TLS metadata inspection are critical for modern incident response.

---

## 📎 Disclaimer
This project is for educational and defensive security research purposes only.
