<div align="center">

# 🛡️ Sentrix SOC
### AI-Native Security Operations Center (SOC)

Real-time cyber threat detection, enrichment, correlation, automated response, and enterprise security analytics powered by **Wazuh**, **Suricata**, **Elasticsearch**, and a custom **Threat Intelligence Engine**.

![Python](https://img.shields.io/badge/Python-3.11+-blue?style=for-the-badge&logo=python)
![FastAPI](https://img.shields.io/badge/FastAPI-Backend-009688?style=for-the-badge&logo=fastapi)
![Docker](https://img.shields.io/badge/Docker-Containerized-2496ED?style=for-the-badge&logo=docker)
![Elasticsearch](https://img.shields.io/badge/Elasticsearch-Search-FEC514?style=for-the-badge&logo=elasticsearch)
![Wazuh](https://img.shields.io/badge/Wazuh-SIEM-0052CC?style=for-the-badge)
![Suricata](https://img.shields.io/badge/Suricata-IDS-E65100?style=for-the-badge)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT&CK-red?style=for-the-badge)

</div>

---

# 📖 Overview

**Sentrix SOC** is an AI-powered Security Operations Center designed to detect, correlate, analyze, and respond to cyber threats in real time.

Unlike traditional dashboards, Sentrix processes live telemetry from **Wazuh**, **Suricata**, and **Elasticsearch**, enriches every security event through a modular Threat Engine, maps attacks to the **MITRE ATT&CK Framework**, calculates dynamic risk scores, detects multi-stage attack campaigns, generates analyst recommendations, and visualizes everything through a live enterprise SOC dashboard.

The platform follows a **Service-Oriented Architecture (SOA)** where every component operates independently while remaining fully integrated through a centralized event pipeline.

---

# 🚀 Key Features

## 🔍 Real-Time Security Monitoring

- Live Wazuh Security Event Monitoring
- Suricata IDS Integration
- Elasticsearch Log Collection
- Continuous Event Streaming
- Real-Time Alert Processing

---

## 🧠 Threat Intelligence Engine

- MITRE ATT&CK Mapping
- Dynamic Risk Scoring
- Behavioral Anomaly Detection
- Campaign Correlation Engine
- IOC Extraction
- AI Threat Analysis
- Response Recommendation Engine

---

## ⚡ SOAR Automation

- Automated Incident Response
- Playbook Execution
- IP Blocking
- Host Isolation (Simulation Layer)
- Analyst Recommendations
- Execution Tracking

---

## 📊 Enterprise SOC Dashboard

- Live Threat Feed
- Executive Summary
- MITRE ATT&CK Heatmap
- Campaign Timeline
- Analyst Investigation Panel
- Severity Analytics
- Source IP Analytics
- Asset Analytics
- Response Tracker
- Live Health Monitoring

---

## 🔒 Detection Sources

- Wazuh SIEM
- Suricata IDS
- Elasticsearch
- Custom Threat Rules
- JSON Event Sources

---

# 🏗️ System Architecture

```text
                    ┌────────────────────┐
                    │   Wazuh SIEM       │
                    └─────────┬──────────┘
                              │
                    ┌─────────▼──────────┐
                    │  Suricata IDS      │
                    └─────────┬──────────┘
                              │
                    ┌─────────▼──────────┐
                    │ Elasticsearch      │
                    └─────────┬──────────┘
                              │
                      Event Collection Layer
                              │
               ┌──────────────▼──────────────┐
               │ Collector / Streamer        │
               └──────────────┬──────────────┘
                              │
                       Normalized Events
                              │
               ┌──────────────▼──────────────┐
               │      Threat Engine          │
               ├─────────────────────────────┤
               │ MITRE Mapping               │
               │ Risk Scoring                │
               │ Anomaly Detection           │
               │ Campaign Detection          │
               │ AI Analysis                 │
               │ IOC Extraction              │
               │ Recommendations             │
               └──────────────┬──────────────┘
                              │
             ┌────────────────┴────────────────┐
             │                                 │
      Dashboard Service                SOAR Executor
             │                                 │
             └──────────────┬──────────────────┘
                            │
                  Live SOC Dashboard
```

---

# ⚙️ Threat Processing Pipeline

Every incoming security event passes through the following pipeline:

```
Raw Event

↓

Collector

↓

Event Stream

↓

Normalization

↓

Threat Engine

↓

MITRE Mapping

↓

Risk Scoring

↓

Anomaly Detection

↓

Campaign Correlation

↓

AI Threat Analysis

↓

Response Recommendation

↓

Dashboard Service

↓

Live Dashboard
```

---

# 🧠 Threat Engine

The Threat Engine is the intelligence core of Sentrix SOC.

| Engine | Purpose |
|----------|----------|
| MITRE Engine | Maps attacks to MITRE ATT&CK techniques |
| Risk Engine | Calculates dynamic threat scores |
| Anomaly Engine | Detects behavioral anomalies |
| Campaign Engine | Correlates multi-stage attacks |
| IOC Engine | Extracts Indicators of Compromise |
| AI Analysis | Generates analyst-friendly summaries |
| Recommendation Engine | Suggests automated responses |

---

# 📂 Repository Structure

```
Sentrix_SOC/

├── agent/
│
├── client/
│   ├── pipeline/
│   │   ├── collector.py
│   │   ├── streamer.py
│   │   ├── compute.py
│   │   ├── watcher.py
│   │   └── threat_engine/
│   │
│   ├── installer.py
│   ├── service.py
│   └── registration.py
│
├── dashboard/
│
├── connectors/
│
├── docker/
│
├── docs/
│
├── libs/
│
├── rules/
│
├── tests/
│
└── README.md
```

---

# ⚙️ Technology Stack

## Backend

- Python
- FastAPI
- Redis
- Docker

## Security Stack

- Wazuh
- Suricata
- Elasticsearch
- MITRE ATT&CK

## Frontend

- HTML5
- CSS3
- JavaScript
- Server Sent Events (SSE)

---

# 🚀 Quick Start

## Clone Repository

```bash
git clone https://github.com/yourusername/Sentrix_SOC.git

cd Sentrix_SOC
```

---

## Start Infrastructure

```bash
cd docker

docker compose up -d
```

---

## Install Dependencies

```bash
cd client

pip install -r requirements.txt
```

---

## Start Agent

```bash
python main.py
```

---

## Open Dashboard

```
http://localhost:7000
```

---

# 🔄 Event Flow

```
Wazuh

↓

Suricata

↓

Elasticsearch

↓

Collector

↓

Streamer

↓

Threat Engine

↓

Dashboard API

↓

SSE

↓

SOC Dashboard
```

---

# 🎯 Current Capabilities

✅ Real-Time Threat Detection

✅ MITRE ATT&CK Mapping

✅ Dynamic Risk Scoring

✅ Campaign Detection

✅ Behavioral Analytics

✅ Live Event Streaming

✅ IOC Extraction

✅ AI Threat Summarization

✅ SOAR Playbooks

✅ Response Tracking

✅ Executive Dashboard

---

# 🛣️ Roadmap

- Multi-Tenant SOC
- Threat Intelligence Feed Integration
- Sigma Rule Support
- YARA Rule Engine
- OSQuery Integration
- EDR Integration
- Cloud Deployment
- Kubernetes Support
- Machine Learning Detection Models

---

# 👥 Contributors

Built with ❤️ by the **Sentrix Team 1**

---

# 📜 License

This project is intended for research, education, hackathons, and security innovation.

---

<div align="center">

## ⭐ If you found this project interesting, consider giving it a Star!

**Sentrix SOC — Detect. Correlate. Respond.**

</div>
