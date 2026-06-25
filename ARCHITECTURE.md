        # Sentrix SOC — Architecture Documentation

## Overview

Sentrix SOC is a service-oriented Security Operations Center platform. All detection, correlation, and response logic is implemented as modular services that receive processed events from `compute.py`.

---

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────┐
│                      SENTRIX SOC PLATFORM                           │
│                                                                     │
│  ┌──────────┐    ┌──────────┐    ┌──────────────────────────────┐  │
│  │  Wazuh   │    │ Suricata │    │   Session Manager (Docker)   │  │
│  │  (HIDS)  │    │  (IDS)   │    │   FastAPI + Redis + Keycloak │  │
│  └────┬─────┘    └────┬─────┘    └──────────────────────────────┘  │
│       │               │                                             │
│       └───────┬────────┘                                           │
│               │                                                     │
│        ┌──────▼──────┐                                             │
│        │ collector.py │  ← Elasticsearch queries (Wazuh + Suricata)│
│        └──────┬───────┘                                            │
│               │  raw events {source, data}                         │
│        ┌──────▼──────┐                                             │
│        │  writer.py   │  ← Stores to local JSON logs (preserved)   │
│        └──────┬───────┘                                            │
│               │                                                     │
│   ┌───────────▼──────────────────────────────────────────────────┐ │
│   │                    compute.py (ORCHESTRATOR)                  │ │
│   │                Central Event Orchestration Point              │ │
│   └───────────┬──────────────────┬───────────────────────────────┘ │
│               │                  │                    │             │
│    ┌──────────▼──────┐  ┌────────▼──────┐  ┌────────▼──────────┐  │
│    │  ThreatEngine   │  │  DashboardSvc │  │  ExecutorService  │  │
│    │ .process(event) │  │ .publish(ev)  │  │  .evaluate(ev)    │  │
│    └──────────┬──────┘  └────────┬──────┘  └────────┬──────────┘  │
│               │                  │                   │             │
│    ┌──────────▼──────────┐ ┌─────▼──────────┐ ┌─────▼──────────┐  │
│    │  threat_engine/     │ │  dashboard/    │ │ executor_svc/  │  │
│    │  ├ risk_engine      │ │  ├ service.py  │ │ ├ response_eng │  │
│    │  ├ mitre_engine     │ │  ├ server.py   │ │ ├ dispatcher   │  │
│    │  ├ anomaly_engine   │ │  └ index.html  │ │ ├ actions.py   │  │
│    │  ├ campaign_detect  │ └────────────────┘ │ └ playbooks/   │  │
│    │  ├ ai_analysis      │                    └────────────────┘  │
│    │  ├ response_recomm  │                                         │
│    │  └ report_engine    │                                         │
│    └─────────────────────┘                                         │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Service Interaction Diagram

```
compute.py
    │
    ├─── ThreatEngine.process(raw_event)
    │         │
    │         ├─ mitre_engine.map_event()       → MITRE ATT&CK context
    │         ├─ risk_engine.score()            → Risk score 0-100
    │         ├─ anomaly_engine.analyze()       → Behavioral anomaly detection
    │         ├─ campaign_detector.correlate()  → Campaign/alert correlation
    │         ├─ ai_analysis.analyze()          → AI narrative + guidance
    │         └─ response_recommender.recommend() → Playbook recommendations
    │
    ├─── DashboardService.publish(enriched_event)
    │         │
    │         ├─ In-memory ring buffer (2000 events)
    │         └─ SSE push to browser (real-time)
    │
    └─── ExecutorService.evaluate(enriched_event)
              │
              ├─ response_engine.evaluate()    → Threshold check
              └─ dispatcher.dispatch()         → Execute playbook actions
```

---

## Event Flow Diagram

```
Raw Event (Wazuh/Suricata)
  {source: "wazuh", data: {...}}
          │
          ▼
  [MITRE Mapping]
  {technique_id, tactic_id, kill_chain_stage, kill_chain_position}
          │
          ▼
  [Risk Scoring]
  {score: 0-100, severity_raw, category, factors}
          │
          ▼
  [Anomaly Detection]
  {anomaly_detected, anomalies[], max_anomaly_score, primary_anomaly}
          │
          ▼
  [Campaign Correlation] ←── Alert Memory (7-day window, 10k events)
  {campaign_id, is_multi_stage, stage_progression, event_count}
          │
          ▼
  [AI Analysis]
  {summary, technique_context, kill_chain_context, recommendations}
          │
          ▼
  [Response Recommendation]
  {playbooks[], auto_playbooks[], primary_playbook, actions[]}
          │
          ▼
  Enriched Event → DashboardService.publish()   [Real-time SSE]
                → ExecutorService.evaluate()    [Auto SOAR]
```

---

## Folder Structure

```
Sentrix_SOC/
├── agent/
│   ├── executor.py
│   ├── main.py
│   └── watcher.py
├── cleint/                          ← Agent (endpoint)
│   ├── config.py
│   ├── logger.py
│   ├── main.py                      ← Entry point
│   ├── pipeline/
│   │   ├── collector.py             ← Existing (unchanged)
│   │   ├── compute.py               ← ENHANCED — central orchestrator
│   │   ├── writer.py                ← Existing (unchanged)
│   │   ├── streamer.py              ← Existing (unchanged)
│   │   ├── dashboard/
│   │   │   ├── feeds.py             ← Existing (preserved)
│   │   │   ├── server.py            ← ENHANCED — SSE + full API
│   │   │   ├── service.py           ← NEW — DashboardService
│   │   │   └── index.html           ← NEW — SOC Command Center UI
│   │   ├── threat_engine/           ← NEW SERVICE
│   │   │   ├── __init__.py          ← ThreatEngine class
│   │   │   ├── risk_engine.py       ← Dynamic risk scoring (0-100)
│   │   │   ├── mitre_engine.py      ← MITRE ATT&CK mapping
│   │   │   ├── anomaly_engine.py    ← Behavioral anomaly detection
│   │   │   ├── campaign_detector.py ← Campaign correlation + memory
│   │   │   ├── ai_analysis.py       ← AI-grade analysis narratives
│   │   │   ├── response_recommender.py ← Playbook recommendations
│   │   │   └── report_engine.py     ← Aggregated reporting
│   │   └── executor_service/        ← NEW SOAR SERVICE
│   │       ├── __init__.py          ← ExecutorService class
│   │       ├── actions.py           ← Action library (20 actions)
│   │       ├── dispatcher.py        ← Playbook execution + history
│   │       ├── response_engine.py   ← Auto-trigger logic
│   │       └── playbooks/
│   │           └── __init__.py
│   └── [other existing files...]
├── connectors/
│   ├── elastic.py
│   ├── grpc_server.py
│   └── thehive.py
├── docker/
│   └── session-manager/
│       ├── app.py                   ← Server (preserved)
│       └── [other existing files...]
└── libs/
    └── rules_engine.py
```

---

## Service Contracts

### ThreatEngine

```python
# compute.py → ThreatEngine
from pipeline.threat_engine import ThreatEngine
engine  = ThreatEngine()
enriched = engine.process(raw_event)
# Returns: enriched dict with risk, mitre, anomaly, campaign, ai_analysis, response
```

### DashboardService

```python
# compute.py → DashboardService
from pipeline.dashboard.service import DashboardService
dashboard = DashboardService()
dashboard.publish(enriched_event)
# Pushes to in-memory ring buffer + SSE subscribers
```

### ExecutorService

```python
# compute.py → ExecutorService
from pipeline.executor_service import ExecutorService
executor = ExecutorService()
records  = executor.evaluate(enriched_event)
# Auto-triggers playbooks if score >= threshold
```

---

## Dashboard API

| Endpoint                  | Method | Description                              |
|---------------------------|--------|------------------------------------------|
| `/`                       | GET    | SOC Command Center UI (HTML)             |
| `/api/stream`             | GET    | SSE live event stream                    |
| `/api/events`             | GET    | Recent enriched events (REST fallback)   |
| `/api/timeline`           | GET    | Alert timeline                           |
| `/api/severity-distribution` | GET | Event counts by severity               |
| `/api/top-ips`            | GET    | Top source IP addresses                  |
| `/api/top-assets`         | GET    | Top targeted assets                      |
| `/api/mitre-heatmap`      | GET    | Technique hit counts for MITRE matrix    |
| `/api/mitre-tactics`      | GET    | All MITRE tactics                        |
| `/api/campaigns`          | GET    | Active attack campaigns                  |
| `/api/campaign/{id}`      | GET    | Campaign detail                          |
| `/api/executive-summary`  | GET    | Executive security posture summary       |
| `/api/iocs`               | GET    | Extracted Indicators of Compromise       |
| `/api/responses`          | GET    | SOAR response execution history          |
| `/api/memory-stats`       | GET    | Alert memory / correlation statistics    |
| `/api/agent`              | GET    | Agent health information                 |
| `/api/health`             | GET    | Service health check                     |

---

## Threat Engine Capabilities

### Risk Scoring (0-100)
- Base severity from Wazuh/Suricata level
- Category weight (exploit=1.0, scan=0.55, etc.)
- Kill chain position multiplier
- Source IP frequency bonus (sliding 5-min window)
- Reputation bonus for previously-flagged IPs

### MITRE ATT&CK Coverage
- 25 techniques mapped
- 15 tactics covered
- Signature-based + fallback mapping
- Kill chain position tracking (0-10)

### Anomaly Detection (Unknown Threats)
- Auth failure burst detection (brute force)
- Event rate burst (scanners, worms)
- Off-hours authentication
- Rare process execution (LoTL detection)
- Rare destination port detection
- User behavioral shift (statistical Z-score)

### Campaign Correlation (Alert Memory Layer)
- 7-day correlation window
- 10,000-event in-memory ring buffer
- IP-based and user-based campaign grouping
- Multi-stage attack story construction
- Kill chain progression tracking

### SOAR Playbooks (9 playbooks)
| ID     | Name                  | Auto | Threshold |
|--------|-----------------------|------|-----------|
| PB-001 | Block Malicious IP    | Yes  | 60        |
| PB-002 | Host Isolation        | Yes  | 75        |
| PB-003 | Account Lockdown      | Yes  | 55        |
| PB-004 | Process Termination   | Yes  | 65        |
| PB-005 | Threat Hunt Initiation| No   | 50        |
| PB-006 | DDoS Mitigation       | Yes  | 60        |
| PB-007 | Brute Force Response  | Yes  | 40        |
| PB-008 | Anomaly Investigation | No   | 35        |
| PB-009 | Campaign Containment  | Yes  | 70        |

---

## Integration Plan

The new services integrate with the existing Sentrix_SOC architecture without replacing anything:

1. **`compute.py`** — Enhanced in-place. Existing `log()` and `print()` preserved. Services lazy-initialized on first event (no startup cost if no events arrive).

2. **`dashboard/server.py`** — Enhanced in-place. All existing `/api/feeds` and `/api/feed/{name}` endpoints preserved. New endpoints added.

3. **`dashboard/index.html`** — Replaced with full SOC Command Center. All existing agent info APIs still compatible.

4. **No changes to**: `collector.py`, `writer.py`, `streamer.py`, `main.py`, `logger.py`, `config.py`, session-manager, connectors.

---

## Deployment Instructions

### Development (Agent)

```bash
cd Sentrix_SOC/cleint
pip install fastapi uvicorn requests psutil
python main.py
# Dashboard: http://localhost:7000
```

### Production (Docker)

```bash
# Build and start session manager
cd Sentrix_SOC/docker
docker-compose up -d

# On each endpoint, run the agent:
cd Sentrix_SOC/cleint
python main.py
```

### Required Dependencies

```
fastapi
uvicorn
requests
psutil
```

### Configuration

`Sentrix_SOC/cleint/config.py` reads from environment variables:

```bash
export SENTRIX_SERVER_URL=http://<server-ip>:8000   # default: http://127.0.0.1:8000
```

Edit `TIMING` in `config.py` to adjust heartbeat / poll intervals.

### Dashboard Port

Default: **7000**. The server auto-increments to the next free port if 7000 is taken.
Check agent log output for the actual bound port:
```
[DASHBOARD] SOC Command Center running on port 7000
```

---

## Network Map

```
Browser
  │
  ├─ port 8000 (session-manager / Docker)
  │      ├─ GET  /              → dashboard.html   (agent management UI)
  │      ├─ GET  /login         → login.html
  │      ├─ POST /auth/login    → JWT token (Keycloak or local fallback)
  │      ├─ GET  /api/sessions  → all agent sessions (no auth required)
  │      ├─ GET  /api/stream    → SSE (event: session-update every 5s)
  │      ├─ POST /admin/command → push command to agent queue
  │      ├─ GET  /admin/tamper/alerts → tamper alert queue
  │      └─ GET  /api/*         → proxy → port 7000 (threat-engine data)
  │
  └─ port 7000 (agent FastAPI / cleint)
         ├─ GET  /              → index.html       (SOC threat dashboard)
         ├─ GET  /api/stream    → SSE (data: enriched events in real-time)
         ├─ GET  /api/events    → recent enriched events (REST polling)
         ├─ GET  /api/campaigns → campaign detector output
         ├─ GET  /api/mitre-*   → MITRE ATT&CK heatmap + tactics
         ├─ GET  /api/executive-summary → security posture report
         ├─ GET  /api/iocs      → extracted Indicators of Compromise
         └─ GET  /api/responses → SOAR playbook execution history

port 9200 (Elasticsearch) ← Filebeat ← Suricata + Wazuh logs
port 55000 (Wazuh API)    ← wazuh.py  (JWT auth, auto-refresh)
port 6379  (Redis)        ← session-manager session store
port 8080  (Keycloak)     ← session-manager user auth
```

---

## Critical Design Decisions

### 1. Session Verification — Canonical Hash Only
The server hashes `{client_id, **machine_info}` — the original registration fields only.
The agent (`storage.py`) **must** hash the same canonical subset, excluding runtime-added
keys (`wazuh`, `services`). Hashing the full local session dict causes a guaranteed
mismatch on every restart, creating false tamper alerts.

### 2. Port Separation — Two Distinct Dashboards
Port 8000 serves `dashboard.html` (agent management) and port 7000 serves `index.html`
(SOC threat feed). These are two different HTML files serving two different purposes.
The agent dashboard server must **not** serve `dashboard.html` because `dashboard.html`
relies on `/auth/login` and `/auth/me` routes that only exist on the session-manager.

### 3. Proxy — urllib vs FastAPI Request Class
The session-manager proxy (`/api/{path}`) uses `urllib.request.urlopen`. The stdlib
`Request` class must be aliased as `_UrllibRequest` at import time because FastAPI's
`Request` is imported into the same namespace and would otherwise shadow it, silently
breaking all proxy calls with a TypeError.

### 4. SERVER_URL — Environment Variable
`config.py` reads `SENTRIX_SERVER_URL` from the environment (default `http://127.0.0.1:8000`).
Never hardcode an IP address here — doing so breaks every agent on any other machine.
