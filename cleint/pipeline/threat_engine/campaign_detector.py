# threat_engine/campaign_detector.py
"""
Attack Campaign / Correlation Engine
Groups individual alerts into multi-stage attack campaigns (attack stories).
Implements the Alert Memory Layer — correlates events across time (days/weeks).
"""
import uuid
import time
from collections import defaultdict, deque
from threading import Lock
from typing import Optional

_lock = Lock()

# ─── In-memory campaign store ────────────────────────────────────────────────
# Campaigns live here — keyed by campaign_id
_campaigns: dict = {}

# Reverse index: ip → campaign_ids, user → campaign_ids
_ip_to_campaigns:   dict = defaultdict(set)
_user_to_campaigns: dict = defaultdict(set)

# Alert memory — ALL processed alerts kept for correlation (TTL: 7 days)
_alert_memory: deque = deque(maxlen=10000)   # (timestamp, enriched_event)

CAMPAIGN_TTL        = 7 * 24 * 3600    # 7 days — cross-day correlation
CORRELATION_WINDOW  = 300              # 5 min to group related events
CAMPAIGN_THRESHOLD  = 2                # minimum events to form a campaign

# ─── Kill-chain stage ordering ───────────────────────────────────────────────
STAGE_ORDER = [
    "Reconnaissance", "Initial Access", "Exploitation",
    "Persistence", "Privilege Escalation", "Defense Evasion",
    "Credential Access", "Lateral Movement", "C2", "Exfiltration", "Impact"
]


def _get_src_ip(enriched: dict) -> Optional[str]:
    return enriched.get("risk", {}).get("src_ip")


def _get_user(enriched: dict) -> Optional[str]:
    data = enriched.get("data", {})
    if isinstance(data, dict):
        u = data.get("user", {})
        if isinstance(u, dict):
            return u.get("name")
    return None


def _get_stage(enriched: dict) -> str:
    return enriched.get("mitre", {}).get("kill_chain_stage", "Reconnaissance")


def _campaign_stage_progression(stages: list) -> str:
    """Summarize progression: 'Reconnaissance → Exploitation → Lateral Movement'"""
    seen = []
    for s in stages:
        if not seen or seen[-1] != s:
            seen.append(s)
    return " → ".join(seen)


def _create_campaign(first_event: dict, src_ip: Optional[str], user: Optional[str]) -> dict:
    cid = str(uuid.uuid4())[:8].upper()
    stage = _get_stage(first_event)
    campaign = {
        "campaign_id":    cid,
        "src_ip":         src_ip,
        "user":           user,
        "first_seen":     time.time(),
        "last_seen":      time.time(),
        "event_count":    1,
        "stages":         [stage],
        "stage_progression": stage,
        "events":         [first_event],
        "risk_score":     first_event.get("risk", {}).get("score", 0),
        "severity":       "LOW",
        "status":         "active",
        "techniques":     [first_event.get("mitre", {}).get("technique_id", "")],
        "is_multi_stage": False,
    }
    return campaign


def _update_campaign(campaign: dict, enriched: dict) -> dict:
    stage = _get_stage(enriched)
    risk  = enriched.get("risk", {}).get("score", 0)

    campaign["last_seen"]    = time.time()
    campaign["event_count"] += 1
    campaign["stages"].append(stage)
    campaign["stage_progression"] = _campaign_stage_progression(campaign["stages"])

    # Upgrade risk score to max seen in campaign
    campaign["risk_score"] = max(campaign["risk_score"], risk)

    tech = enriched.get("mitre", {}).get("technique_id", "")
    if tech and tech not in campaign["techniques"]:
        campaign["techniques"].append(tech)

    campaign["events"].append(enriched)
    # Keep event list bounded
    if len(campaign["events"]) > 50:
        campaign["events"] = campaign["events"][-50:]

    unique_stages = list(dict.fromkeys(campaign["stages"]))
    campaign["is_multi_stage"] = len(unique_stages) > 1

    score = campaign["risk_score"]
    if score >= 80:   campaign["severity"] = "CRITICAL"
    elif score >= 60: campaign["severity"] = "HIGH"
    elif score >= 40: campaign["severity"] = "MEDIUM"
    else:             campaign["severity"] = "LOW"

    return campaign


def _purge_expired():
    """Remove campaigns older than TTL."""
    now = time.time()
    expired = [cid for cid, c in _campaigns.items() if now - c["last_seen"] > CAMPAIGN_TTL]
    for cid in expired:
        del _campaigns[cid]


def correlate(enriched: dict) -> dict:
    """
    Correlate the enriched event against existing campaigns.
    Returns campaign context: {"campaign_id": str, "is_new": bool, "campaign": dict}
    """
    src_ip = _get_src_ip(enriched)
    user   = _get_user(enriched)
    now    = time.time()

    # Store in alert memory for long-term correlation
    with _lock:
        _alert_memory.append((now, enriched))
        _purge_expired()

    # ── Look for an active campaign matching this IP or user ──────────────
    matched_campaign_id = None
    with _lock:
        candidates = set()
        if src_ip:
            candidates |= _ip_to_campaigns.get(src_ip, set())
        if user:
            candidates |= _user_to_campaigns.get(user, set())

        for cid in list(candidates):
            camp = _campaigns.get(cid)
            if not camp:
                continue
            if camp["status"] != "active":
                continue
            # Within correlation window (5 min) — events outside window start a new campaign
            if now - camp["last_seen"] <= CORRELATION_WINDOW:
                matched_campaign_id = cid
                break

        if matched_campaign_id:
            campaign = _update_campaign(_campaigns[matched_campaign_id], enriched)
            _campaigns[matched_campaign_id] = campaign
            is_new = False
        else:
            # Create new campaign
            campaign = _create_campaign(enriched, src_ip, user)
            cid = campaign["campaign_id"]
            _campaigns[cid] = campaign
            if src_ip:
                _ip_to_campaigns[src_ip].add(cid)
            if user:
                _user_to_campaigns[user].add(cid)
            is_new = True

    cid = campaign["campaign_id"]
    return {
        "campaign_id":        cid,
        "is_new_campaign":    is_new,
        "is_multi_stage":     campaign["is_multi_stage"],
        "stage_progression":  campaign["stage_progression"],
        "event_count":        campaign["event_count"],
        "campaign_severity":  campaign["severity"],
        "techniques":         campaign["techniques"],
    }


def get_all_campaigns() -> list:
    """Return campaigns with >= CAMPAIGN_THRESHOLD events, sorted by last_seen desc."""
    with _lock:
        camps = list(_campaigns.values())
    camps.sort(key=lambda c: c["last_seen"], reverse=True)
    # Filter out single-event noise — only real correlated campaigns
    out = []
    for c in camps:
        if c["event_count"] < CAMPAIGN_THRESHOLD:
            continue
        out.append({
            "campaign_id":       c["campaign_id"],
            "src_ip":            c["src_ip"],
            "user":              c["user"],
            "first_seen":        c["first_seen"],
            "last_seen":         c["last_seen"],
            "event_count":       c["event_count"],
            "stage_progression": c["stage_progression"],
            "risk_score":        c["risk_score"],
            "severity":          c["severity"],
            "is_multi_stage":    c["is_multi_stage"],
            "techniques":        c["techniques"],
            "status":            c["status"],
        })
    return out


def get_campaign(campaign_id: str) -> Optional[dict]:
    with _lock:
        return _campaigns.get(campaign_id)


def get_memory_stats() -> dict:
    with _lock:
        return {
            "total_alerts_in_memory": len(_alert_memory),
            "active_campaigns":       len(_campaigns),
            "tracked_ips":            len(_ip_to_campaigns),
            "tracked_users":          len(_user_to_campaigns),
        }
