# 🛡️ ThreatWatch
### Autonomous Cyber Defense & Deception Platform

ThreatWatch is a real-time threat intelligence platform that ingests live data from five industry-standard feeds, deploys an internal honeypot to catch active attackers, auto-generates firewall block rules, and pushes instant Discord alerts — all built on a strict TDD/OOP foundation.

[![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-009688?style=flat-square&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-16-4169E1?style=flat-square&logo=postgresql&logoColor=white)](https://postgresql.org)
[![Pytest](https://img.shields.io/badge/TDD-123%20tests-green?style=flat-square&logo=pytest&logoColor=white)](https://pytest.org)
[![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?style=flat-square&logo=docker&logoColor=white)](https://docker.com)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow?style=flat-square)](LICENSE)

> ⚠️ **Educational project.** Built for the WeThinkCode_ Cybersecurity Elective Application 2026. Do not deploy against systems you do not own. See [DISCLAIMER.md](DISCLAIMER.md).

---

## The Four Pillars

**🌐 Multi-Feed Intelligence Ingestion**
Real-time ingestion from five public threat feeds via a decoupled OOP hierarchy — each feed is a concrete class extending a `BaseIngestor` ABC with `fetch()` and `parse()` methods. Feeds: AbuseIPDB, AlienVault OTX, URLhaus, PhishTank, Blocklist.de.

**🕸️ The Spiderweb — Active Deception Engine**
A lightweight honeypot that impersonates real services (SSH, Telnet) to catch attackers scanning your network. Logs every connection attempt with attacker IP, port, timestamp, and captured credentials.

**🔒 The Iron Curtain — Automated Threat Mitigation**
Translates malicious IPs into ready-to-use firewall block commands for Linux UFW, iptables, and MikroTik RouterOS. One IP in — three firewall commands out.

**📡 The War Room — Real-Time Notifications**
Instant markdown-formatted Discord webhook alerts on high-severity threat matches or honeypot triggers, with severity-coded colour formatting.

---

## Tech Stack

| Layer | Technology |
|---|---|
| Backend | FastAPI (Python 3.11+) |
| Scheduling | APScheduler |
| Database | PostgreSQL 16 + SQLAlchemy ORM |
| Testing | Pytest — TDD throughout |
| Containerisation | Docker + Docker Compose |
| Frontend (in progress) | Vanilla JS + Leaflet.js + Chart.js |

---

## Project Status

> 🚧 Active development — solo build, WeThinkCode_ Cybersecurity Elective submission.

| Component | Status |
|---|---|
| Multi-feed ingestion layer (5 feeds) | ✅ Complete |
| Spiderweb honeypot | ✅ Complete |
| Iron Curtain firewall engine | ✅ Complete |
| War Room Discord notifier | ✅ Complete |
| TDD test suite | ✅ 123 tests passing |
| SQLAlchemy ORM integration | 🔄 In progress |
| Processing layer (enrichment, scoring) | 🔄 In progress |
| FastAPI routes | ⏳ Upcoming |
| Frontend dashboard | ⏳ Upcoming |
| Docker full-stack setup | ⏳ Upcoming |

---

## Quick Start

```bash
git clone https://github.com/Tazio0/threatwatch.git
cd threatwatch
cp .env.example .env
# Add your API keys to .env
docker-compose up
```

---

## Author

**Tazio Petersen** · [github.com/Tazio0](https://github.com/Tazio0)
*WeThinkCode_ Cape Town · Cybersecurity Elective Application · 2026*
