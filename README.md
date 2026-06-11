# ThreatWatch: Autonomous Cyber Defense & Deception Platform

ThreatWatch is an advanced Security Orchestration, Automation, and Response (SOAR) pipeline built to ingest high-fidelity threat intelligence, deploy internal active deception mechanisms, and automatically generate real-time network mitigation rules.

## Core Pillars
* **Multi-Feed Intelligence Ingestion:** Real-time ingestion pipelines from 5 industry-standard threat feeds (AbuseIPDB, AlienVault OTX, URLhaus, PhishTank, and Blocklist.de) mapped via an elegant, decoupled OOP hierarchy.
* **Active Deception Engine ("The Spiderweb"):** Built-in, low-overhead containerized decoy honey-services that capture unauthorized internal network scanning, brute-forcing, and interaction.
* **Automated Threat Mitigation ("The Iron Curtain"):** An orchestration pipeline that translates high-severity threats and honeypot triggers into immediate, copy-pasteable firewall rule matrices (Linux UFW/iptables, MikroTik, and Cisco systems).
* **Real-Time Tactical Notifications:** Instant markdown-formatted push alerting to enterprise communication rooms (Discord webhooks) upon high-velocity threat matching or honeypot activation.

## Technical Architecture Stack
* **Language:** Python 3.11+ (Strict Object-Oriented Blueprinting)
* **Testing Framework:** Pytest (100% Test-Driven Development workflow)
* **Database & ORM:** PostgreSQL + SQLAlchemy (With transactional logging)
* **Containerization:** Docker & Docker Compose
