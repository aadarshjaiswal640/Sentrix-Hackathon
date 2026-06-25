# pipeline/dashboard/server.py
"""
SOC Command Center Dashboard Server (port 7000)
Enhanced FastAPI server with SSE streaming, full threat-engine API, and SOC UI.

This server runs inside the agent process and serves:
  - index.html  (SOC threat dashboard — events, campaigns, MITRE, executive summary)
  - /api/stream (SSE — enriched events from the threat engine)
  - /api/*      (REST polling fallback for all threat-engine data)

The session-manager (port 8000) proxies unrecognised /api/* routes here so the
dashboard.html served at port 8000 can also access threat-engine data.
"""
import json
import queue
import threading
import asyncio
import socket
from datetime import datetime, timezone
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
import uvicorn

app = FastAPI(title="Sentrix SOC Command Center")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

_session = {}


def set_session(session: dict):
    global _session
    _session = session


# ─── UI ───────────────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
def index():
    """
    Serve index.html — the SOC Command Center threat dashboard.
    This is the full threat-engine UI (events, campaigns, MITRE, executive
    summary) and is the correct page for port 7000.
    dashboard.html (session-manager UI) must NOT be served here because it
    relies on /auth/login and /auth/me which only exist on port 8000.
    """
    legacy_dashboard = Path(__file__).parent / "index.html"
    if legacy_dashboard.exists():
        return legacy_dashboard.read_text(encoding="utf-8")

    return "<h1>Sentrix SOC — index.html not found</h1>"


# ─── SSE Live Event Stream ────────────────────────────────────────────────────

@app.get("/api/stream")
async def event_stream(request: Request):
    """
    Server-Sent Events stream — pushes new enriched events to the browser
    in real-time as they arrive from compute.py via DashboardService.
    """
    from pipeline.dashboard.service import subscribe, unsubscribe

    q: queue.Queue = queue.Queue(maxsize=100)
    subscribe(q)

    async def generator():
        try:
            while True:
                if await request.is_disconnected():
                    break
                try:
                    event = await asyncio.get_event_loop().run_in_executor(
                        None, lambda: q.get(timeout=15)
                    )
                    payload = json.dumps(_serialize_event(event))
                    yield f"data: {payload}\n\n"
                except queue.Empty:
                    yield ": heartbeat\n\n"
        finally:
            unsubscribe(q)

    return StreamingResponse(
        generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control":               "no-cache",
            "X-Accel-Buffering":           "no",
            "Access-Control-Allow-Origin": "*",
        }
    )


def _serialize_event(ev: dict) -> dict:
    """Flatten enriched event to a dashboard-friendly dict."""
    risk     = ev.get("risk", {})
    mitre    = ev.get("mitre", {})
    anomaly  = ev.get("anomaly", {})
    campaign = ev.get("campaign", {})
    ai_ctx   = ev.get("ai_analysis", {})
    response = ev.get("response", {})
    memory   = ev.get("threat_memory", {}) or {}
    identity = ev.get("identity", {}) or {}
    incident = ev.get("incident", {}) or {}

    from pipeline.dashboard.service import score_to_severity
    score = risk.get("score", 0)
    sev   = score_to_severity(score)

    return {
        "timestamp":         ev.get("processed_at", datetime.now(timezone.utc).isoformat()),
        "source":            ev.get("source", "unknown").upper(),
        "score":             score,
        "severity":          sev,
        "src_ip":            risk.get("src_ip", ""),
        "dest_ip":           risk.get("dest_ip", ""),
        "technique_id":      mitre.get("technique_id", ""),
        "technique_name":    mitre.get("technique_name", ""),
        "tactic_id":         mitre.get("tactic_id", ""),
        "tactic_name":       mitre.get("tactic_name", ""),
        "kill_chain":        mitre.get("kill_chain_stage", ""),
        "kill_chain_pos":    mitre.get("kill_chain_position", 0),
        "campaign_id":       campaign.get("campaign_id", ""),
        "is_multi_stage":    campaign.get("is_multi_stage", False),
        "stage_progression": campaign.get("stage_progression", ""),
        "campaign_severity": campaign.get("campaign_severity", ""),
        "anomaly_detected":  anomaly.get("anomaly_detected", False),
        "primary_anomaly":   anomaly.get("primary_anomaly", ""),
        "max_anomaly_score": anomaly.get("max_anomaly_score", 0),
        "summary":           ai_ctx.get("summary", "")[:300],
        "analyst_notes":     ai_ctx.get("analyst_notes", ""),
        "confidence":        ai_ctx.get("confidence", ""),
        "playbooks":         [p.get("id", "") for p in response.get("auto_playbooks", [])],
        # Brownie: Threat Memory
        "mem_total_events":  memory.get("total_events", 0),
        "mem_previous_obs":  memory.get("previous_obs", 0),
        "mem_is_returning":  memory.get("is_returning", False),
        "mem_techniques":    memory.get("techniques", []),
        "mem_kc_evo":        memory.get("kill_chain_evo", []),
        # Brownie: Identity
        "identity_status":   identity.get("status", "WAITING_FOR_IAM_FEED"),
        "identity_user":     identity.get("user"),
        "identity_score":    identity.get("user_risk_score", 0),
        "identity_priv_esc": identity.get("privilege_escalation", False),
        "identity_offhours": identity.get("off_hours", False),
        # Brownie: Incident
        "incident_id":       incident.get("incident_id", ""),
        "incident_count":    incident.get("raw_alert_count", 1),
        "incident_conf":     incident.get("confidence", "LOW"),
        "incident_priority": incident.get("priority_score", 0),
        "incident_escalated":incident.get("escalated", False),
    }


# ─── Agent Info ───────────────────────────────────────────────────────────────

@app.get("/api/agent")
def agent_info():
    client_id = _session.get("client_id", "")
    # Derive agent status from session completeness rather than hardcoding "online"
    if client_id:
        status = "online"
    elif _session:
        status = "pending"   # session exists but client_id not yet populated
    else:
        status = "offline"
    return {
        "client_id": client_id,
        "hostname":  _session.get("hostname", ""),
        "ip":        _session.get("ip", ""),
        "os":        _session.get("os", ""),
        "status":    status,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


# ─── Live Threat Feed (REST polling fallback) ─────────────────────────────────

@app.get("/api/events")
def get_events(limit: int = 50):
    from pipeline.dashboard.service import get_recent_events
    events = get_recent_events(limit)
    return {
        "count":     len(events),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "events":    [_serialize_event(e) for e in events],
    }


@app.get("/api/timeline")
def get_timeline(limit: int = 50):
    from pipeline.dashboard.service import get_alert_timeline
    return {
        "timeline":  get_alert_timeline(limit),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


# ─── Threat Engine Stats ──────────────────────────────────────────────────────

@app.get("/api/severity-distribution")
def severity_distribution():
    from pipeline.threat_engine import report_engine
    return report_engine.severity_distribution()


@app.get("/api/top-ips")
def top_ips(limit: int = 10):
    from pipeline.threat_engine import report_engine
    return {"top_ips": report_engine.top_source_ips(limit)}


@app.get("/api/top-assets")
def top_assets(limit: int = 10):
    from pipeline.threat_engine import report_engine
    return {"top_assets": report_engine.top_targeted_assets(limit)}


@app.get("/api/mitre-heatmap")
def mitre_heatmap():
    from pipeline.threat_engine import report_engine
    return {"heatmap": report_engine.mitre_heatmap()}


@app.get("/api/mitre-tactics")
def mitre_tactics():
    from pipeline.threat_engine import mitre_engine
    return {"tactics": mitre_engine.get_all_tactics()}


# ─── Campaign View ────────────────────────────────────────────────────────────

@app.get("/api/campaigns")
def get_campaigns():
    from pipeline.threat_engine import campaign_detector
    return {
        "campaigns": campaign_detector.get_all_campaigns(),
        "stats":     campaign_detector.get_memory_stats(),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.get("/api/campaign/{campaign_id}")
def get_campaign(campaign_id: str):
    from pipeline.threat_engine import campaign_detector
    camp = campaign_detector.get_campaign(campaign_id)
    if not camp:
        return {"error": "Campaign not found"}
    summary = dict(camp)
    summary.pop("events", None)
    return summary


# ─── Executive Summary ────────────────────────────────────────────────────────

@app.get("/api/executive-summary")
def executive_summary():
    from pipeline.threat_engine import report_engine
    return report_engine.executive_summary()


@app.get("/api/iocs")
def get_iocs():
    from pipeline.threat_engine import report_engine
    return report_engine.extract_iocs()


# ─── Response / SOAR Tracking ─────────────────────────────────────────────────

@app.get("/api/responses")
def get_responses(limit: int = 50):
    from pipeline.executor_service.dispatcher import get_execution_history, get_response_stats
    return {
        "responses": get_execution_history(limit),
        "stats":     get_response_stats(),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


# ─── Memory & Alert Correlation Stats ────────────────────────────────────────

@app.get("/api/memory-stats")
def memory_stats():
    from pipeline.threat_engine import campaign_detector
    return campaign_detector.get_memory_stats()


# ─── Brownie: Threat Memory Engine ────────────────────────────────────────────

@app.get("/api/threat-memory")
def get_threat_memory(limit: int = 50):
    """
    All tracked source IPs with per-IP history:
    first_seen, last_seen, total_events, techniques_used,
    severity_history, risk_trend, anomaly_history, previous_observations.
    """
    from pipeline.threat_engine import threat_memory
    return {
        "memories":  threat_memory.get_all_ip_memories(limit),
        "stats":     threat_memory.get_memory_stats(),
        "returning": threat_memory.get_returning_attackers(20),
        "top_techniques": threat_memory.get_top_techniques(),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.get("/api/threat-memory/{ip}")
def get_ip_memory(ip: str):
    """History for a specific source IP."""
    from pipeline.threat_engine import threat_memory
    mem = threat_memory.get_ip_memory(ip)
    if not mem:
        return {"error": f"IP '{ip}' not seen", "ip": ip}
    return mem


# ─── Brownie: Identity Risk Framework ────────────────────────────────────────

@app.get("/api/identity")
def get_identity():
    """
    Identity Risk Framework status.
    Shows WAITING_FOR_IAM_FEED when no user telemetry has been received.
    Activates automatically when real Wazuh events include user.name.
    """
    from pipeline.threat_engine import identity_engine
    return {
        "framework":  identity_engine.get_framework_status(),
        "user_risks": identity_engine.get_all_user_risks(50),
        "timestamp":  datetime.now(timezone.utc).isoformat(),
    }


# ─── Brownie: Incident Engine ─────────────────────────────────────────────────

@app.get("/api/incidents")
def get_incidents(limit: int = 100):
    """
    Grouped incidents with alert compression.
    Shows: raw_alert_count → 1 incident, confidence, priority_score.
    """
    from pipeline.threat_engine import incident_engine
    return {
        "incidents": incident_engine.get_all_incidents(limit),
        "stats":     incident_engine.get_compression_stats(),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


# ─── Brownie: Behavioral Baseline ────────────────────────────────────────────

@app.get("/api/behavioral-baseline")
def behavioral_baseline():
    """
    Behavioral anomaly summary — the Unknown Attack Card.
    Shows: known MITRE techniques vs behavior-only (no-signature) detections.
    Data derives entirely from anomaly_engine runtime detectors.
    """
    from pipeline.threat_engine import report_engine, anomaly_engine
    from pipeline.dashboard.service import get_recent_events

    recent = get_recent_events(200)

    known_attacks   = []   # events with MITRE rule match
    unknown_behavior = []  # events with anomaly but no/fallback MITRE match

    for ev in recent:
        mitre   = ev.get("mitre", {})
        anomaly = ev.get("anomaly", {})
        risk    = ev.get("risk", {})

        technique_id   = mitre.get("technique_id", "")
        match_method   = mitre.get("match_method", "fallback")
        anom_detected  = anomaly.get("anomaly_detected", False)
        primary_anom   = anomaly.get("primary_anomaly", "")
        anom_score     = anomaly.get("max_anomaly_score", 0)
        score          = risk.get("score", 0)

        if match_method == "rule" and technique_id:
            known_attacks.append({
                "technique_id":   technique_id,
                "technique_name": mitre.get("technique_name", ""),
                "score":          score,
                "timestamp":      ev.get("processed_at", ""),
            })
        elif anom_detected and match_method == "fallback":
            unknown_behavior.append({
                "anomaly_type":  primary_anom,
                "anomaly_score": anom_score,
                "confidence_pct": min(99, anom_score),
                "src_ip":        risk.get("src_ip", ""),
                "timestamp":     ev.get("processed_at", ""),
            })

    return {
        "known_attacks":     known_attacks[:20],
        "unknown_behavior":  unknown_behavior[:20],
        "detector_compat":   [
            {"name": name, "suricata": compat[0], "wazuh": compat[1]}
            for name, compat in anomaly_engine.DETECTOR_COMPAT.items()
        ],
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


# ─── Legacy feed compatibility ────────────────────────────────────────────────

@app.get("/api/feeds")
def list_feeds():
    from pipeline.dashboard.feeds import FEEDS
    return {"feeds": list(FEEDS.keys())}


@app.get("/api/feed/{name}")
def get_feed(name: str):
    from pipeline.dashboard.feeds import FEEDS
    if name not in FEEDS:
        return {"error": f"Feed '{name}' not found"}
    service_url = _session.get("services", {}).get(name, {}).get("url", "")
    data = FEEDS[name](_session)
    return {
        "feed":       name,
        "configured": bool(service_url),
        "count":      len(data),
        "timestamp":  datetime.now(timezone.utc).isoformat(),
        "events":     data,
    }


# ─── Health ───────────────────────────────────────────────────────────────────

@app.get("/api/health")
def health():
    return {
        "status":    "ok",
        "service":   "Sentrix SOC Command Center",
        "timestamp": datetime.now(timezone.utc).isoformat()
    }


@app.get("/api/health-detail")
def health_detail():
    """
    Per-subsystem liveness check for the Agent Health panel.
    Returns counts from live in-memory stores so the UI can show real status.
    """
    from pipeline.dashboard.service import get_recent_events
    from pipeline.threat_engine import report_engine, campaign_detector
    from pipeline.executor_service.dispatcher import get_response_stats

    try:
        buf_len = len(report_engine._get_events_snapshot())
    except Exception:
        buf_len = 0

    try:
        mem_stats = campaign_detector.get_memory_stats()
    except Exception:
        mem_stats = {}

    try:
        resp_stats = get_response_stats()
        executor_ok = True
    except Exception:
        resp_stats = {}
        executor_ok = False

    # Threat engine is ACTIVE only when events have been processed,
    # WAITING on cold start (imports succeed but pipeline not yet running),
    # ERROR if the store is inaccessible.
    if buf_len > 0:
        threat_engine_status = "ACTIVE"
    elif buf_len == 0:
        threat_engine_status = "WAITING"
    else:
        threat_engine_status = "ERROR"

    # SOAR executor: ACTIVE when it has successfully run (responses exist),
    # WAITING when imported but no events have been dispatched yet.
    if not executor_ok:
        soar_status = "ERROR"
    elif resp_stats.get("total_responses", 0) > 0:
        soar_status = "ACTIVE"
    else:
        soar_status = "WAITING"

    # Wazuh / Suricata sensor status:
    #   CONNECTED   — services are configured AND events have arrived recently (< 5 min)
    #   DEGRADED    — services are configured BUT no events for > 5 min (sensor may be stale)
    #   DISCONNECTED — no sensor services configured in session at all
    alerts_in_memory = mem_stats.get("total_alerts_in_memory", 0)
    services_configured = bool(_session.get("services"))

    if not services_configured:
        sensor_status = "DISCONNECTED"
    else:
        # Services are configured — check whether events are flowing
        sensor_status = "DEGRADED"   # default: configured but no recent data
        if alerts_in_memory > 0:
            try:
                recent = get_recent_events(1)
                if recent:
                    last_ts = recent[0].get("processed_at", "")
                    if last_ts:
                        age_s = (
                            datetime.now(timezone.utc) -
                            datetime.fromisoformat(last_ts.replace("Z", "+00:00"))
                        ).total_seconds()
                        sensor_status = "CONNECTED" if age_s < 300 else "DEGRADED"
                    else:
                        sensor_status = "CONNECTED"
            except Exception:
                sensor_status = "DEGRADED"

    return {
        "timestamp":            datetime.now(timezone.utc).isoformat(),
        "threat_engine":        threat_engine_status,
        "soar_executor":        soar_status,
        "alert_memory":         f"● {alerts_in_memory} alerts",
        "wazuh_suricata":       sensor_status,
        "report_engine_events": buf_len,
        "active_campaigns":     mem_stats.get("active_campaigns", 0),
        "total_responses":      resp_stats.get("total_responses", 0),
    }


@app.get("/api/mitre-mapping-stats")
def mitre_mapping_stats():
    """Return MITRE mapping quality statistics (rule hits, fallbacks, technique counts)."""
    from pipeline.threat_engine.mitre_engine import get_mapping_stats
    return get_mapping_stats()


@app.get("/api/reputation-stats")
def reputation_stats():
    """Return bad-IP reputation store metrics (active, expired, TTL info)."""
    from pipeline.threat_engine.risk_engine import get_reputation_stats
    return get_reputation_stats()


@app.get("/api/anomaly-compat")
def anomaly_compat():
    """Return detector compatibility matrix (which detectors run for each source)."""
    from pipeline.threat_engine.anomaly_engine import DETECTOR_COMPAT
    return {
        "detectors": [
            {"name": name, "suricata": compat[0], "wazuh": compat[1]}
            for name, compat in DETECTOR_COMPAT.items()
        ]
    }


# ─── Launch ───────────────────────────────────────────────────────────────────

def find_available_port(start_port: int = 7000, max_attempts: int = 10) -> int:
    port = start_port
    for _ in range(max_attempts):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            try:
                # Probe on 0.0.0.0 so we detect conflicts on all interfaces,
                # not just loopback — uvicorn binds to 0.0.0.0 below.
                sock.bind(("0.0.0.0", port))
                return port
            except OSError:
                port += 1
    return start_port


def launch(session: dict, port: int = 7000):
    set_session(session)
    actual_port = find_available_port(port)

    def _run():
        uvicorn.run(app, host="0.0.0.0", port=actual_port, log_level="error")

    threading.Thread(target=_run, daemon=True).start()
    print(f"[DASHBOARD] SOC Command Center running on port {actual_port}")
