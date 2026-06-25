# threat_engine/incident_engine.py
"""
Intelligent Alert Management — Incident Engine
===============================================
Groups raw alerts into compressed incidents.

Problem: 50 identical port-scan alerts are not 50 incidents — they are 1.
This engine groups them, compresses the count, and computes:
  - Confidence: Low / Medium / High
  - Priority Score: Risk + Anomaly + Campaign Depth + Historical Reputation

Grouping key: (src_ip, technique_id)
  Events from the same source using the same technique are merged into one incident.
  After a configurable gap, the incident is closed and a new one begins.

If technique_id is unavailable but anomaly is detected, group by (src_ip, anomaly_type).

Returns per event:
  {
    "incident_id":     str,
    "is_new":          bool,
    "raw_alert_count": int,
    "confidence":      "LOW" | "MEDIUM" | "HIGH",
    "priority_score":  int (0-200+),
    "campaign_depth":  int,
    "escalated":       bool,
  }

Data sources (100% real pipeline output):
  - risk_engine     → score, src_ip
  - mitre_engine    → technique_id, technique_name
  - anomaly_engine  → max_anomaly_score, primary_anomaly
  - campaign_detector → event_count, techniques (campaign depth proxy)
  - threat_memory   → previous_observations (historical reputation)
"""
import time
import uuid
from collections import defaultdict
from threading import Lock
from typing import Optional

_lock = Lock()

# ─── Incident store ───────────────────────────────────────────────────────────
# key (src_ip, group_key) → incident dict
_incidents: dict = {}

# History of all closed + active incidents
_incident_history: list = []

INCIDENT_GAP    = 600    # 10 min gap with no events closes an incident group
MAX_HISTORY     = 500


def _incident_key(src_ip: str, technique_id: str, primary_anomaly: Optional[str]) -> str:
    if technique_id:
        return f"{src_ip}||{technique_id}"
    if primary_anomaly:
        return f"{src_ip}||anomaly:{primary_anomaly}"
    return f"{src_ip}||generic"


def _compute_confidence(raw_count: int, campaign_depth: int,
                         anomaly_score: int, technique_sev: int) -> str:
    """
    Confidence = Low / Medium / High based on 4 real pipeline signals.
      raw_count:      number of grouped alerts
      campaign_depth: how many events are in the linked campaign (maturity)
      anomaly_score:  max anomaly score from anomaly_engine (0-100)
      technique_sev:  MITRE technique severity proxy (based on kill chain position)
    """
    score = 0
    # Event count factor (0-30)
    if raw_count >= 20:
        score += 30
    elif raw_count >= 5:
        score += 15
    else:
        score += raw_count * 2

    # Campaign maturity factor (0-30)
    if campaign_depth >= 10:
        score += 30
    elif campaign_depth >= 3:
        score += 15
    else:
        score += campaign_depth * 3

    # Anomaly overlap factor (0-25)
    if anomaly_score >= 70:
        score += 25
    elif anomaly_score >= 40:
        score += 12
    elif anomaly_score > 0:
        score += 5

    # Technique severity factor (0-15)
    score += min(15, technique_sev)

    if score >= 55:
        return "HIGH"
    elif score >= 25:
        return "MEDIUM"
    return "LOW"


def _compute_priority(risk_score: int, anomaly_score: int,
                       campaign_depth: int, previous_obs: int) -> int:
    """
    Priority Score = Risk + Anomaly_bonus + Campaign_depth*5 + Historical_reputation
    Range: 0 – 200+
    """
    anomaly_bonus = int(anomaly_score * 0.5)
    campaign_bonus = min(50, campaign_depth * 5)
    reputation_bonus = min(40, previous_obs * 10)
    return risk_score + anomaly_bonus + campaign_bonus + reputation_bonus


def ingest(enriched: dict) -> dict:
    """
    Group the enriched event into an incident.
    Returns incident context for this event.

    Called by ThreatEngine.process() as the final enrichment step.
    """
    risk     = enriched.get("risk", {})
    mitre    = enriched.get("mitre", {})
    anomaly  = enriched.get("anomaly", {})
    campaign = enriched.get("campaign", {})
    memory   = enriched.get("threat_memory", {})

    src_ip         = risk.get("src_ip", "")
    risk_score     = risk.get("score", 0)
    technique_id   = mitre.get("technique_id", "")
    technique_name = mitre.get("technique_name", "")
    kc_pos         = mitre.get("kill_chain_position", 0)
    anom_score     = anomaly.get("max_anomaly_score", 0)
    primary_anom   = anomaly.get("primary_anomaly")
    campaign_depth = campaign.get("event_count", 1)
    prev_obs       = memory.get("previous_obs", 0) if isinstance(memory, dict) else 0

    if not src_ip:
        return _empty_ctx()

    now = time.time()
    key = _incident_key(src_ip, technique_id, primary_anom)

    with _lock:
        inc = _incidents.get(key)

        if inc is None or (now - inc["last_seen"] > INCIDENT_GAP):
            # New incident
            iid = str(uuid.uuid4())[:8].upper()
            inc = {
                "incident_id":     iid,
                "key":             key,
                "src_ip":          src_ip,
                "technique_id":    technique_id,
                "technique_name":  technique_name,
                "primary_anomaly": primary_anom,
                "first_seen":      now,
                "last_seen":       now,
                "raw_alert_count": 1,
                "max_risk_score":  risk_score,
                "max_anom_score":  anom_score,
                "campaign_depth":  campaign_depth,
                "previous_obs":    prev_obs,
                "escalated":       False,
                "techniques":      [technique_id] if technique_id else [],
            }
            _incidents[key] = inc
            is_new = True
        else:
            inc["raw_alert_count"] += 1
            inc["last_seen"]        = now
            inc["max_risk_score"]   = max(inc["max_risk_score"], risk_score)
            inc["max_anom_score"]   = max(inc["max_anom_score"], anom_score)
            inc["campaign_depth"]   = max(inc["campaign_depth"], campaign_depth)
            inc["previous_obs"]     = max(inc["previous_obs"], prev_obs)
            if technique_id and technique_id not in inc["techniques"]:
                inc["techniques"].append(technique_id)
            is_new = False

        # Campaign-aware escalation: multiple techniques = escalate
        if len(inc["techniques"]) >= 2 and not inc["escalated"]:
            inc["escalated"] = True

        confidence = _compute_confidence(
            inc["raw_alert_count"],
            inc["campaign_depth"],
            inc["max_anom_score"],
            kc_pos * 2,     # kill chain position 0-10 → 0-20 severity proxy
        )
        priority = _compute_priority(
            inc["max_risk_score"],
            inc["max_anom_score"],
            inc["campaign_depth"],
            inc["previous_obs"],
        )
        inc["confidence"]     = confidence
        inc["priority_score"] = priority

        return {
            "incident_id":     inc["incident_id"],
            "is_new":          is_new,
            "raw_alert_count": inc["raw_alert_count"],
            "confidence":      confidence,
            "priority_score":  priority,
            "campaign_depth":  inc["campaign_depth"],
            "escalated":       inc["escalated"],
            "technique_id":    technique_id,
            "technique_name":  technique_name,
        }


def _empty_ctx() -> dict:
    return {
        "incident_id":     "",
        "is_new":          True,
        "raw_alert_count": 1,
        "confidence":      "LOW",
        "priority_score":  0,
        "campaign_depth":  1,
        "escalated":       False,
        "technique_id":    "",
        "technique_name":  "",
    }


# ─── API accessors ─────────────────────────────────────────────────────────────

def get_all_incidents(limit: int = 100) -> list:
    """Return active incidents sorted by priority_score desc."""
    with _lock:
        now = time.time()
        out = []
        for inc in _incidents.values():
            # Only include incidents active in the last hour
            if now - inc["last_seen"] > 3600:
                continue
            out.append({
                "incident_id":     inc["incident_id"],
                "src_ip":          inc["src_ip"],
                "technique_id":    inc["technique_id"],
                "technique_name":  inc["technique_name"],
                "primary_anomaly": inc["primary_anomaly"],
                "first_seen":      inc["first_seen"],
                "last_seen":       inc["last_seen"],
                "raw_alert_count": inc["raw_alert_count"],
                "confidence":      inc.get("confidence", "LOW"),
                "priority_score":  inc.get("priority_score", 0),
                "campaign_depth":  inc["campaign_depth"],
                "escalated":       inc["escalated"],
                "techniques":      inc["techniques"],
            })
    out.sort(key=lambda x: x["priority_score"], reverse=True)
    return out[:limit]


def get_compression_stats() -> dict:
    """Return stats showing how many raw alerts were compressed into incidents."""
    with _lock:
        total_incidents  = len(_incidents)
        total_raw_alerts = sum(i["raw_alert_count"] for i in _incidents.values())
        escalated        = sum(1 for i in _incidents.values() if i["escalated"])
        high_conf        = sum(1 for i in _incidents.values() if i.get("confidence") == "HIGH")
        return {
            "total_incidents":    total_incidents,
            "total_raw_alerts":   total_raw_alerts,
            "compression_ratio":  (
                round(total_raw_alerts / total_incidents, 1)
                if total_incidents > 0 else 0
            ),
            "escalated_incidents": escalated,
            "high_confidence":    high_conf,
        }
