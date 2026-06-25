# threat_engine/__init__.py
"""
ThreatEngine — Central threat processing service.
Orchestrates: risk scoring, MITRE mapping, anomaly detection,
campaign correlation, AI analysis, response recommendation,
threat memory, identity risk, incident management, and reporting.
"""
from datetime import datetime, timezone

from pipeline.threat_engine import (
    risk_engine,
    mitre_engine,
    anomaly_engine,
    campaign_detector,
    ai_analysis,
    response_recommender,
    report_engine,
    threat_memory,
    identity_engine,
    incident_engine,
)


class ThreatEngine:
    """
    Service contract:
        enriched = ThreatEngine().process(raw_event)
    """

    def process(self, event: dict) -> dict:
        """
        Full enrichment pipeline for a single raw event.
        Returns a deeply enriched event dict ready for dashboard and executor.

        Pipeline order:
          1.  MITRE ATT&CK mapping
          2.  Dynamic risk scoring
          3.  Behavioral anomaly detection
          4.  Campaign correlation (Alert Memory Layer)
          5.  AI analysis & narrative
          6.  Response recommendations
          7.  Threat Memory Engine  (cross-session IP history)
          8.  Identity Risk Framework (user telemetry if present)
          9.  Incident Engine  (alert compression & confidence)
          10. Report engine ingestion
        """
        # 1. MITRE ATT&CK mapping
        mitre_ctx = mitre_engine.map_event(event)

        # 2. Dynamic risk scoring
        risk_ctx = risk_engine.score(event, mitre_context=mitre_ctx)

        # 3. Behavioral anomaly detection
        anomaly_ctx = anomaly_engine.analyze(event)

        # 4. Campaign correlation (Alert Memory Layer)
        enriched_partial = {
            **event,
            "risk":    risk_ctx,
            "mitre":   mitre_ctx,
            "anomaly": anomaly_ctx,
        }
        campaign_ctx = campaign_detector.correlate(enriched_partial)

        # 5. AI analysis & narrative
        enriched_with_campaign = {
            **enriched_partial,
            "campaign": campaign_ctx,
        }
        ai_ctx = ai_analysis.analyze(enriched_with_campaign)

        # 6. Response recommendations
        response_ctx = response_recommender.recommend(enriched_with_campaign)

        # Build intermediate enriched event
        enriched_mid = {
            **event,
            "processed_at": datetime.now(timezone.utc).isoformat(),
            "risk":         risk_ctx,
            "mitre":        mitre_ctx,
            "anomaly":      anomaly_ctx,
            "campaign":     campaign_ctx,
            "ai_analysis":  ai_ctx,
            "response":     response_ctx,
        }

        # 7. Threat Memory Engine — cross-session per-IP history
        memory_ctx = threat_memory.ingest(enriched_mid)
        enriched_mid["threat_memory"] = memory_ctx

        # 8. Identity Risk Framework — real user telemetry (Wazuh only)
        identity_ctx = identity_engine.analyze(event)
        enriched_mid["identity"] = identity_ctx

        # 9. Incident Engine — alert compression & confidence scoring
        incident_ctx = incident_engine.ingest(enriched_mid)
        enriched_mid["incident"] = incident_ctx

        # Final enriched event
        enriched = {
            **enriched_mid,
        }

        # 10. Feed report engine for aggregated reporting
        report_engine.ingest(enriched)

        return enriched
