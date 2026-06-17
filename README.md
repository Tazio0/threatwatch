# ThreatWatch

A cybersecurity-focused threat intelligence dashboard built with **Python**, **FastAPI**, **PostgreSQL**, **Docker**, and **Pytest**.

ThreatWatch collects and processes threat intelligence from public security feeds, helping surface suspicious IPs, malicious URLs, and security context through a structured backend system.

This is an educational portfolio project built to strengthen my skills in backend development, API design, testing, Docker, databases, and cybersecurity-aware software engineering.

---

## Table of Contents

* [Overview](#overview)
* [Project Status](#project-status)
* [Why I Built This](#why-i-built-this)
* [What This Project Demonstrates](#what-this-project-demonstrates)
* [Features](#features)
* [Tech Stack](#tech-stack)
* [Discord Alert Output](#discord-alert-output)
* [Architecture](#architecture)
* [Getting Started](#getting-started)
* [Running Tests](#running-tests)
* [Project Roadmap](#project-roadmap)
* [Security and Responsible Use](#security-and-responsible-use)
* [What I Learned](#what-i-learned)
* [Future Improvements](#future-improvements)

---

## Overview

ThreatWatch is a backend-focused cybersecurity project that works with threat intelligence data from public sources.

The project is designed around a simple idea:

> Collect threat indicators, process them safely, store useful context, and present alerts in a way that is easy to understand.

ThreatWatch currently focuses on backend functionality and alerting. The long-term goal is to grow it into a more complete dashboard for viewing, filtering, and understanding threat intelligence data.

---

## Project Status

ThreatWatch is currently in active development.

### Working

* FastAPI backend structure
* Threat feed ingestion foundation
* PostgreSQL database integration
* Environment-based configuration
* Docker Compose setup
* Pytest test suite
* Discord alert notifications
* Public threat intelligence feed processing

### In Progress

* Dashboard/frontend interface
* Improved threat scoring logic
* More threat intelligence sources
* Better South African threat context
* Deployment workflow
* GitHub Actions continuous integration

---

## Why I Built This

I built ThreatWatch because I wanted a portfolio project that connects backend development with cybersecurity.

Instead of building another basic CRUD app, I wanted to work on something closer to real-world security tooling. ThreatWatch gives me practice with external APIs, threat data, backend architecture, databases, testing, Docker, and responsible security-focused development.

The goal of this project is not to claim that ThreatWatch is a finished enterprise security product. The goal is to show that I can design, build, test, document, and improve a real backend system around a practical cybersecurity use case.

---

## What This Project Demonstrates

ThreatWatch demonstrates my ability to:

* Design and structure a backend application
* Build APIs with FastAPI
* Work with PostgreSQL and SQLAlchemy
* Use Docker Compose for local development
* Write and run automated tests with Pytest
* Handle configuration through environment variables
* Work with external threat intelligence data
* Send formatted Discord alerts through webhook integration
* Document a project clearly for other developers
* Think about security tools responsibly
* Build a project that can grow beyond a simple tutorial or school assignment

---

## Features

### Threat Intelligence Feed Processing

ThreatWatch collects indicators from supported public threat intelligence feeds and processes them into a structured format.

Examples of threat data include:

* Suspicious IP addresses
* Malicious URLs
* Feed source information
* Country context
* Indicator type
* Threat totals from supported feeds

### Discord Alert Notifications

ThreatWatch can send formatted alerts to Discord when threat indicators are collected.

This helps demonstrate real output from the system instead of only showing backend code.

### Backend API Foundation

The project is built around a FastAPI backend, making it easier to expand with:

* API endpoints
* dashboard integration
* filtering
* authentication
* search
* future deployment

### Database Integration

ThreatWatch uses PostgreSQL for storing and managing threat intelligence data.

### Testing

The project includes automated tests using Pytest to validate backend behaviour, configuration, feed processing, and threat intelligence workflows.

### Docker-Based Development

Docker Compose is used to make the project easier to run locally with its required services.

---

## Tech Stack

| Area                    | Technology             |
| ----------------------- | ---------------------- |
| Language                | Python                 |
| Backend Framework       | FastAPI                |
| Database                | PostgreSQL             |
| ORM / Database Layer    | SQLAlchemy             |
| Testing                 | Pytest                 |
| Containerisation        | Docker, Docker Compose |
| Alerts                  | Discord Webhooks       |
| Development Environment | Linux, Git, GitHub     |

---

## Discord Alert Output

ThreatWatch sends formatted threat intelligence alerts to Discord when indicators are collected from supported public feeds.

Each alert includes:

* Feed source
* Threat indicator
* Indicator type
* Country context
* Total threats available from the feed

<img width="431" height="777" alt="ThreatWatch Discord alert output" src="https://github.com/user-attachments/assets/6e354586-6be9-4f8c-8aff-4641e11de54f" />

---

## Architecture

ThreatWatch is designed as a backend-first system with separate responsibilities for ingestion, processing, storage, and alerting.

```text
Public Threat Feeds
        |
        v
Threat Feed Ingestion
        |
        v
Processing and Normalisation
        |
        v
Database Storage
        |
        v
FastAPI Backend
        |
        v
Discord Alerts / Future Dashboard
```

### Core Flow

1. ThreatWatch collects data from supported public threat intelligence feeds.
2. The data is processed and normalised into a consistent structure.
3. Useful threat context is stored in the database.
4. Alerts can be sent to Discord.
5. Future dashboard/API features can use the stored data for filtering, viewing, and analysis.

---

## Getting Started

### Prerequisites

Make sure you have the following installed:

* Python 3.11+
* Git
* Docker
* Docker Compose

### Clone the Repository

```bash
git clone https://github.com/Tazio0/threatwatch.git
cd threatwatch
```

### Set Up Environment Variables

Create your local environment file from the example file:

```bash
cp .env.example .env
```

Then update the `.env` file with the required local settings and API keys for the threat feeds you want to use.

Do not commit real API keys, tokens, webhook URLs, or secrets to GitHub.

### Run with Docker Compose

```bash
docker compose up --build
```

This starts the local development services defined in the Docker Compose configuration.

---

## Running Tests

From the project root, run:

```bash
PYTHONPATH=. python -m pytest
```

The test suite covers backend structure, feed processing, configuration, and threat intelligence workflows.

---

## Project Roadmap

### Completed

* [x] Set up FastAPI backend structure
* [x] Add PostgreSQL database support
* [x] Add Docker Compose development environment
* [x] Add Pytest test suite
* [x] Add Discord alert notifications
* [x] Add public threat feed processing foundation
* [x] Add environment-based configuration

### In Progress

* [ ] Improve threat scoring logic
* [ ] Add more threat intelligence sources
* [ ] Improve South African threat context
* [ ] Add dashboard/frontend interface
* [ ] Add authentication
* [ ] Add deployment instructions
* [ ] Add CI pipeline with GitHub Actions
* [ ] Deploy a demo version

---

## Security and Responsible Use

ThreatWatch is an educational cybersecurity project.

It is intended for learning, portfolio development, and responsible experimentation with public threat intelligence data.

This project should not be used to attack systems, scan targets without permission, expose private data, or automate harmful activity.

Any API keys, webhook URLs, credentials, or private configuration values should be stored locally in environment variables and never committed to the repository.

---

## What I Learned

Through this project, I strengthened my understanding of:

* How to structure a backend project around clear responsibilities
* How to work with external APIs and public security feeds
* How to process and normalise data from different sources
* How to use environment variables for configuration and secrets
* How to connect backend logic to PostgreSQL
* How to write tests for backend behaviour
* How Docker Compose helps with local development
* How to send useful alert output through Discord webhooks
* How to document a technical project for future employers and collaborators
* How to think about cybersecurity tooling responsibly

---

## Future Improvements

The next major improvements planned for ThreatWatch are:

* Add a dashboard interface for viewing threats visually
* Add filtering by country, feed source, indicator type, and severity
* Improve scoring logic for threat indicators
* Add authentication for dashboard/API access
* Add GitHub Actions so tests run automatically on every push
* Add deployment instructions
* Deploy a live demo version
* Add more detailed architecture documentation
* Add screenshots of API docs and test output

---

## Author

Built by **Tazio Petersen**.

Software Development student at **WeThinkCode_**, focused on backend development, cloud, and cybersecurity.

GitHub: [Tazio0](https://github.com/Tazio0)

---

## License

This project is licensed under the MIT License.
