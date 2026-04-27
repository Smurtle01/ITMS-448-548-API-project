# ITMS-448-548-API-project
Created by: Alden DeHaan, Paul Nyamohanga, Sayleht Varela, Andrew Jiang

Application that utilizes a GUI to pull data through APIs, and then ingests data from multiple sources, normalizes/correlates it, and produces both insight (what’s happening now/why it matters) and foresight (what’s likely next).

1. Core Architecture

┌─────────────────────────────────────────────────────────┐
│           Data Ingestion Layer                           │
│  (APIs, RSS, Scrapers, Webhooks, Message Queues)        │
└────────────────┬────────────────────────────────────────┘
                 ↓
┌─────────────────────────────────────────────────────────┐
│         Data Processing Pipeline                         │
│  (Normalization, Enrichment, Deduplication)             │
└────────────────┬────────────────────────────────────────┘
                 ↓
┌─────────────────────────────────────────────────────────┐
│        Analysis & Intelligence Engine                    │
│  (Pattern Detection, Correlation, ML/AI)                │
└────────────────┬────────────────────────────────────────┘
                 ↓
┌─────────────────────────────────────────────────────────┐
│         Storage Layer (Time-series DB + Search)          │
│  (InfluxDB/TimescaleDB + Elasticsearch/OpenSearch)       │
└────────────────┬────────────────────────────────────────┘
                 ↓
┌─────────────────────────────────────────────────────────┐
│      Dashboard, APIs, Alerting & Visualization           │
└─────────────────────────────────────────────────────────┘


2. Key Data Sources to Integrate
Threat Intelligence Feeds

    NVD (National Vulnerability Database) - CVE data
    CISA Alerts - Advisories
    Shodan/Censys APIs - Exposed devices
    AlienVault OTX - Community threat intel
    GreyNoise - Internet scanner data
    URLhaus, PhishTank - Malicious URLs
    Twitter/X API - Security researcher posts
    GitHub - Leaked credentials, malware repos

3. Technology Stack
Backend

# Python stack (for ML/analytics)
- FastAPI or Django (REST API)
- Celery + Redis (task queue)
- Apache Kafka (event streaming)
- SQLAlchemy (ORM)

Databases

- PostgreSQL (primary relational DB)
- TimescaleDB extension (time-series)
- Elasticsearch/OpenSearch (full-text search)
- Redis (caching, real-time data)
- Neo4j (relationship graph - attacker profiles)

ML/Analytics

- scikit-learn (anomaly detection)
- TensorFlow/PyTorch (deep learning)
- YAKE (keyword extraction)
- Gensim (NLP, similarity)
- Prophet (time-series forecasting)

Frontend

- Vue.js/React (dashboard)
- D3.js/Grafana (visualizations)
- Mapbox (geolocation visualization)

4. Sample Implementation Structure

# project_structure/
├── src/
│   ├── ingestion/
│   │   ├── feeds/
│   │   │   ├── nvd_ingester.py
│   │   │   ├── twitter_feed.py
│   │   │   ├── shodan_scraper.py
│   │   │   └── rss_aggregator.py
│   │   └── kafka_producer.py
│   │
│   ├── processing/
│   │   ├── normalizer.py      # Standardize formats
│   │   ├── deduplicator.py    # Remove duplicates
│   │   ├── enricher.py        # Add context (geo, etc)
│   │   └── validator.py       # Data quality
│   │
│   ├── intelligence/
│   │   ├── threat_correlation.py  # Link threats
│   │   ├── pattern_detection.py    # Anomalies
│   │   ├── clustering.py           # Group similar threats
│   │   ├── forecasting.py          # Predict trends
│   │   └── risk_scorer.py          # Score severity
│   │
│   ├── storage/
│   │   ├── postgres_repo.py
│   │   ├── elasticsearch_repo.py
│   │   └── graph_db.py
│   │
│   ├── api/
│   │   ├── threat_routes.py
│   │   ├── search_routes.py
│   │   ├── alert_routes.py
│   │   └── analytics_routes.py
│   │
│   └── tasks/
│       ├── scheduled_jobs.py    # Celery tasks
│       └── alert_engine.py
│
├── notebooks/          # Analysis & experiments
├── tests/
├── docker-compose.yml
└── requirements.txt

5. Core Features to Build
Phase 1 (MVP)

    Data ingestion from 3-5 key sources
    Centralized search/query interface
    Basic dashboard
    Email alerts on new threats

Phase 2

    Correlation engine (link related threats)
    Enrichment (OSINT lookups - whois, ASN)
    Basic ML (clustering similar threats)
    REST API

Phase 3

    Predictive analytics (forecasting attack trends)
    Graph analysis (attacker relationships)
    Advanced visualizations (attack timelines)
    Integration with SIEM/SOC tools
