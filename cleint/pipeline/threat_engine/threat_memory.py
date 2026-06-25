# threat_engine/threat_memory.py
"""
Threat Memory Engine
====================
Maintains persistent, cross-event memory per source IP, destination asset,
and MITRE technique. Every enriched event is ingested and the memory is
updated in real-time.

Tracks per source IP:
  - first_seen / last_seen (unix timestamps)
  - total_events / total_campaigns
  - techniques_used (ordered, deduplicated)
  - severity_history [(timestamp, severity_label)]
  - risk_trend [(timestamp, score)]
  - anomaly_history [(timestamp, anomaly_type)]
  - previous_observations (how many prior distinct activity sessions)
  - campaign_ids (set of campaign IDs this IP contributed to)
  - kill_chain_progression (ordered unique kill-chain stages seen)

Returns:
  {
    "ip_memory":      dict | None,
    "is_returning":   bool,
    "previous_obs":   int,
    "risk_trend":     list[dict],
    "techniques":     list[str],
    "kill_chain_evo": list[str],
    "first_seen":     float | None,
    "last_seen":      float | None,
  }

Data source: 100% derived from real enriched events — risk_engine, mitre_engine,
             anomaly_engine, campaign_detector outputs.
"""
import time
from collections import defaultdict
from threading import Lock
from typing import Optional

_lock = Lock()

# ─── Per source-IP memory store ──────────────────────────────────────────────
# ip → memory dict
_ip_memory: dict = {}

# ─── Per destination-IP (asset) targeting memory ─────────────────────────────
_asset_memory: dict = {}

# ─── Per technique observation count ─────────────────────────────────────────
_technique_counts: dict = defaultdict(int)

# ─── Session gap: gap between last_seen and new event that counts as a "return" ──
SESSION_GAP = 1800    # 30 minutes — a new burst after 30 min = returning attacker

MAX_HISTORY = 100     # keep last N severity/risk/anomaly history entries per IP


def _severity_label(score: int) -> str:
    if score >= 80:   return "CRITICAL"
    elif score >= 60: return "HIGH"
    elif score >= 40: return "MEDIUM"
    elif score >= 20: return "LOW"
    return "INFO"


def ingest(enriched: dict) -> dict:
    """
    Ingest an enriched event and update threat memory.
    Returns the memory context for this event's source IP.

    Called by ThreatEngine.process() after all other engines have run.

    Data extracted from real engine outputs:
      - risk_engine  → src_ip, score
      - mitre_engine → technique_id, kill_chain_stage
      - anomaly_engine → anomaly_detected, primary_anomaly
      - campaign_detector → campaign_id, event_count
    """
    risk     = enriched.get("risk", {})
    mitre    = enriched.get("mitre", {})
    anomaly  = enriched.get("anomaly", {})
    campaign = enriched.get("campaign", {})

    src_ip      = risk.get("src_ip")
    score       = risk.get("score", 0)
    technique   = mitre.get("technique_id", "")
    kc_stage    = mitre.get("kill_chain_stage", "")
    anom_type   = anomaly.get("primary_anomaly") if anomaly.get("anomaly_detected") else None
    campaign_id = campaign.get("campaign_id")
    sev_label   = _severity_label(score)
    now         = time.time()

    if not src_ip:
        return _empty_ctx()

    with _lock:
        # ── Update per-technique global counter ───────────────────────────
        if technique:
            _technique_counts[technique] += 1

        # ── Get or create IP memory ───────────────────────────────────────
        mem = _ip_memory.get(src_ip)
        if mem is None:
            mem = {
                "ip":                   src_ip,
                "first_seen":           now,
                "last_seen":            now,
                "total_events":         0,
                "total_campaigns":      0,
                "campaign_ids":         set(),
                "techniques_used":      [],
                "severity_history":     [],
                "risk_trend":           [],
                "anomaly_history":      [],
                "kill_chain_stages":    [],
                "previous_observations":0,
                "last_session_end":     None,
            }
            _ip_memory[src_ip] = mem

        # ── Detect returning attacker ─────────────────────────────────────
        is_returning = False
        if mem["total_events"] > 0:
            gap = now - mem["last_seen"]
            if gap > SESSION_GAP:
                mem["previous_observations"] += 1
                mem["last_session_end"] = mem["last_seen"]
                is_returning = True

        # ── Update fields ─────────────────────────────────────────────────
        mem["total_events"] += 1
        mem["last_seen"]     = now

        if technique and technique not in mem["techniques_used"]:
            mem["techniques_used"].append(technique)

        if kc_stage and (not mem["kill_chain_stages"] or
                         mem["kill_chain_stages"][-1] != kc_stage):
            mem["kill_chain_stages"].append(kc_stage)

        if campaign_id and campaign_id not in mem["campaign_ids"]:
            mem["campaign_ids"].add(campaign_id)
            mem["total_campaigns"] = len(mem["campaign_ids"])

        # Severity history (capped)
        mem["severity_history"].append((now, sev_label))
        if len(mem["severity_history"]) > MAX_HISTORY:
            mem["severity_history"] = mem["severity_history"][-MAX_HISTORY:]

        # Risk trend (capped)
        mem["risk_trend"].append((now, score))
        if len(mem["risk_trend"]) > MAX_HISTORY:
            mem["risk_trend"] = mem["risk_trend"][-MAX_HISTORY:]

        # Anomaly history (capped)
        if anom_type:
            mem["anomaly_history"].append((now, anom_type))
            if len(mem["anomaly_history"]) > MAX_HISTORY:
                mem["anomaly_history"] = mem["anomaly_history"][-MAX_HISTORY:]

        # ── Build return context ──────────────────────────────────────────
        risk_trend_out = [
            {"timestamp": ts, "score": s}
            for ts, s in mem["risk_trend"][-20:]
        ]
        return {
            "ip_memory":      _serialize(mem),
            "is_returning":   is_returning,
            "previous_obs":   mem["previous_observations"],
            "risk_trend":     risk_trend_out,
            "techniques":     list(mem["techniques_used"]),
            "kill_chain_evo": list(mem["kill_chain_stages"]),
            "first_seen":     mem["first_seen"],
            "last_seen":      mem["last_seen"],
            "total_events":   mem["total_events"],
        }


def _empty_ctx() -> dict:
    return {
        "ip_memory":    None,
        "is_returning": False,
        "previous_obs": 0,
        "risk_trend":   [],
        "techniques":   [],
        "kill_chain_evo": [],
        "first_seen":   None,
        "last_seen":    None,
        "total_events": 0,
    }


def _serialize(mem: dict) -> dict:
    """Convert internal memory dict to JSON-safe dict."""
    return {
        "ip":                    mem["ip"],
        "first_seen":            mem["first_seen"],
        "last_seen":             mem["last_seen"],
        "total_events":          mem["total_events"],
        "total_campaigns":       mem["total_campaigns"],
        "techniques_used":       list(mem["techniques_used"]),
        "kill_chain_stages":     list(mem["kill_chain_stages"]),
        "previous_observations": mem["previous_observations"],
        "severity_history":      [
            {"timestamp": ts, "severity": sev}
            for ts, sev in mem["severity_history"][-20:]
        ],
        "risk_trend": [
            {"timestamp": ts, "score": s}
            for ts, s in mem["risk_trend"][-20:]
        ],
        "anomaly_history": [
            {"timestamp": ts, "anomaly_type": a}
            for ts, a in mem["anomaly_history"][-20:]
        ],
    }


# ─── API accessors ────────────────────────────────────────────────────────────

def get_all_ip_memories(limit: int = 50) -> list:
    """Return all IP memory records sorted by total_events desc."""
    with _lock:
        records = [_serialize(m) for m in _ip_memory.values()]
    records.sort(key=lambda r: r["total_events"], reverse=True)
    return records[:limit]


def get_ip_memory(ip: str) -> Optional[dict]:
    """Return memory for a specific IP, or None if unseen."""
    with _lock:
        mem = _ip_memory.get(ip)
        if not mem:
            return None
        return _serialize(mem)


def get_returning_attackers(limit: int = 20) -> list:
    """Return IPs with previous_observations > 0, sorted by threat level."""
    with _lock:
        records = [
            _serialize(m) for m in _ip_memory.values()
            if m["previous_observations"] > 0
        ]
    records.sort(key=lambda r: (r["previous_observations"], r["total_events"]), reverse=True)
    return records[:limit]


def get_top_techniques() -> list:
    """Return technique observation counts across all IPs."""
    with _lock:
        items = list(_technique_counts.items())
    items.sort(key=lambda x: x[1], reverse=True)
    return [{"technique_id": t, "count": c} for t, c in items[:20]]


def get_memory_stats() -> dict:
    with _lock:
        total_events    = sum(m["total_events"] for m in _ip_memory.values())
        returning_count = sum(1 for m in _ip_memory.values() if m["previous_observations"] > 0)
        return {
            "tracked_ips":       len(_ip_memory),
            "total_events_seen": total_events,
            "returning_attackers": returning_count,
            "unique_techniques": len(_technique_counts),
        }
