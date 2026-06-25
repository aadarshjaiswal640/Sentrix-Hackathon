# pipeline/compute.py
"""
Central Event Orchestration Point
All events from collector flow through here to the service layer.
Service contracts:
    ThreatEngine.process(event)  → enriched event
    Dashboard.publish(enriched)  → live dashboard update
    Executor.evaluate(enriched)  → automated SOAR response
"""
from logger import log

# ─── Service layer (lazy-initialized singletons) ─────────────────────────────
_threat_engine  = None
_dashboard      = None
_executor       = None


def _get_services():
    global _threat_engine, _dashboard, _executor
    if _threat_engine is None:
        from pipeline.threat_engine   import ThreatEngine
        from pipeline.dashboard.service import DashboardService
        from pipeline.executor_service import ExecutorService
        _threat_engine = ThreatEngine()
        _dashboard     = DashboardService()
        _executor      = ExecutorService()
    return _threat_engine, _dashboard, _executor


def process(event: dict):
    """
    Receives raw event from collector/streamer.
    Orchestrates the full service pipeline:
        1. ThreatEngine  — enrich, score, map, correlate, analyze
        2. Dashboard     — publish enriched event to live dashboard
        3. Executor      — evaluate + auto-trigger SOAR playbooks
    """
    source = event.get("source", "unknown")
    data   = event.get("data", {})

    # Original log behavior preserved
    log(f"[{source.upper()}] {data}")
    print(f"[COMPUTE] [{source.upper()}] {data}")

    try:
        threat_engine, dashboard, executor = _get_services()

        # 1. Threat Engine — full enrichment
        enriched = threat_engine.process(event)

        score    = enriched.get("risk", {}).get("score", 0)
        mitre    = enriched.get("mitre", {})
        campaign = enriched.get("campaign", {})
        anomaly  = enriched.get("anomaly", {})

        print(
            f"[THREAT ENGINE] score={score:3d} | "
            f"{mitre.get('technique_id','?')} {mitre.get('technique_name','?')} | "
            f"campaign={campaign.get('campaign_id','?')} "
            f"({'multi-stage' if campaign.get('is_multi_stage') else 'single'}) | "
            f"anomaly={'YES' if anomaly.get('anomaly_detected') else 'no'}"
        )

        # 2. Dashboard Service — publish to live feed
        dashboard.publish(enriched)

        # 3. Executor Service — automated SOAR response
        exec_records = executor.evaluate(enriched)
        if exec_records:
            for rec in exec_records:
                print(
                    f"[EXECUTOR] Playbook {rec['playbook_id']} triggered — "
                    f"{rec['action_count']} actions executed"
                )

    except Exception as e:
        log(f"[COMPUTE] Service layer error: {e}", "ERROR")
        print(f"[COMPUTE] Service layer error: {e}")
