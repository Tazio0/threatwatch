# Nulltrace

Nulltrace is a defensive cybersecurity dashboard project focused on threat intelligence collection, review, and alerting.

The project is currently a polished frontend prototype backed by a Python/FastAPI backend foundation. The frontend demonstrates the intended analyst workflow using mock/demo data. The backend contains models, tests, feed ingestor foundations, processing skeletons, and planned API route structure that can be completed and wired into the frontend later.

This is a portfolio and learning project, not an enterprise security product.

## What Nulltrace Is Trying To Demonstrate

- Threat intelligence ingestion from public security feeds.
- Indicator normalization across different feed formats.
- Severity scoring and deduplication logic.
- South Africa-focused threat context.
- Discord alert delivery concepts.
- Defensive export/mitigation concepts.
- A modern frontend interface for reviewing signals before action.
- Testable backend structure using FastAPI, SQLAlchemy, and Pytest.

## Current Status

### Working Now

- Modern React/Vite frontend branded as Nulltrace.
- Animated globe with real country outlines rendered from map data.
- Mock threat routes, indicators, country insight drawer, and dashboard metrics.
- Frontend-only Discord webhook test form.
- FastAPI app with `/health` endpoint.
- SQLAlchemy models for threats, honeypot logs, and firewall rules.
- Feed ingestor classes for AbuseIPDB, AlienVault OTX, URLhaus, PhishTank, and Blocklist.de.
- Pytest test suite covering models, database structure, ingestors, notifier behavior, mitigation helpers, and planned route contracts.
- Backend skeleton files for routes, repositories, services, and ingestion tasks.

### In Progress / Not Finished Yet

- Backend API route logic is planned but not implemented.
- Frontend still uses mock/demo data through `frontend/src/dataAdapter.js`.
- Discord webhook testing is currently done directly from the browser; a backend proxy is a future improvement.
- Ingestion pipeline orchestration is skeleton-only.
- Severity scoring, enrichment, and deduplication still need real implementation.
- Database migrations are not set up yet.
- Authentication and production deployment are not implemented.

## Tech Stack

| Area | Technology |
| --- | --- |
| Frontend | React, Vite, Three.js, GSAP |
| Backend | Python, FastAPI |
| Database | PostgreSQL, SQLAlchemy |
| Testing | Pytest |
| Local services | Docker Compose |
| Alerts | Discord Webhooks |
| Map data | world-atlas, topojson-client, d3-geo |

## Project Structure

```text
backend/
  app/
    api/                 Planned FastAPI route modules
    core/                Feed ingestors, notifier, mitigation helpers
    processing/          Scoring, enrichment, deduplication skeletons
    repositories/        Planned SQLAlchemy query layer
    services/            Planned business logic layer
    tasks/               Planned ingestion job entry points
    database.py          SQLAlchemy engine/session setup
    main.py              FastAPI application
    models.py            ORM models
    schemas.py           Planned schema pseudocode
  tests/                 Pytest suite
  BACKEND_IMPLEMENTATION_GUIDE.md

frontend/
  src/                   Nulltrace React frontend
  assets/                Nulltrace logo/mark
  package.json           Frontend scripts and dependencies
```


## Running Tests

From the project root:

```bash
PYTHONPATH=. python -m pytest
```

Run a specific test file:

```bash
PYTHONPATH=. python -m pytest backend/tests/test_routes.py -v
```

Note: some route tests describe the intended finished backend behavior. Those tests are expected to fail until you implement and register the planned API routes.

## Responsible Use

Nulltrace is designed as a defensive and educational project.

The project should be used for:

- learning backend engineering through a cybersecurity use case
- practicing threat intelligence data handling
- demonstrating defensive alerting and review workflows
- portfolio demos and QA/testing exercises

The project should not be presented as a finished security product or used to automate blocking decisions without human review.

## Roadmap

Short-term:

- Implement severity scoring.
- Implement enrichment and deduplication.
- Implement repository queries.
- Complete `/api/threats/*`, `/api/map/*`, `/api/sa/*`, and `/api/countries/*` endpoints.
- Add tests for country profile and route endpoints.
- Wire frontend data adapter to real API responses.

Medium-term:

- Add ingestion job runner.
- Add database migrations with Alembic.
- Move Discord webhook testing through FastAPI.
- Add CI for backend tests and frontend build.
- Add deployment instructions.

Long-term:

- Add authentication.
- Add saved analyst notes or review states.
- Add real country-level route data.
- Add clickable country polygons instead of marker-only demo hit areas.
- Add production-safe observability and error handling.
