# dashboard/service.py
"""
Dashboard Service — In-memory event store for real-time SOC dashboard.
Service contract: DashboardService().publish(enriched_event)
"""
from collections import deque
from threading import Lock
from datetime import datetime, timezone


def score_to_severity(score: int) -> str:
    """Single source of truth for score → severity label mapping."""
    if score >= 80:   return "CRITICAL"
    elif score >= 60: return "HIGH"
    elif score >= 40: return "MEDIUM"
    elif score >= 20: return "LOW"
    else:             return "INFO"

_lock = Lock()
_event_store: deque = deque(maxlen=2000)   # ring buffer of enriched events
_subscribers: list  = []                   # SSE subscriber queues


class DashboardService:
    def publish(self, enriched: dict):
        """
        Service contract: Dashboard.publish(enriched_event)
        Stores event and notifies all active SSE subscribers.
        """
        with _lock:
            _event_store.append(enriched)
            dead = []
            for q in _subscribers:
                try:
                    q.put_nowait(enriched)
                except Exception:
                    dead.append(q)
            for q in dead:
                _subscribers.remove(q)


# ─── Store accessors (used by dashboard server routes) ──────────────────────

def get_recent_events(limit: int = 100) -> list:
    with _lock:
        events = list(_event_store)
    events.sort(key=lambda e: e.get("processed_at", ""), reverse=True)
    return events[:limit]


def get_alert_timeline(limit: int = 50) -> list:
    """Return events formatted for timeline display."""
    events = get_recent_events(limit)
    timeline = []
    for ev in events:
        risk   = ev.get("risk", {})
        mitre  = ev.get("mitre", {})
        score  = risk.get("score", 0)
        sev    = score_to_severity(score)

        timeline.append({
            "timestamp":      ev.get("processed_at", ""),
            "source":         ev.get("source", "unknown").upper(),
            "severity":       sev,
            "score":          score,
            "technique_id":   mitre.get("technique_id", ""),
            "technique_name": mitre.get("technique_name", ""),
            "tactic":         mitre.get("tactic_name", ""),
            "kill_chain":     mitre.get("kill_chain_stage", ""),
            "src_ip":         risk.get("src_ip", ""),
            "dest_ip":        risk.get("dest_ip", ""),
            "campaign_id":    ev.get("campaign", {}).get("campaign_id", ""),
            "is_multi_stage": ev.get("campaign", {}).get("is_multi_stage", False),
            "anomaly":        ev.get("anomaly", {}).get("anomaly_detected", False),
            "summary":        ev.get("ai_analysis", {}).get("summary", "")[:200],
        })
    return timeline


def subscribe(queue):
    """Register a queue for SSE event streaming."""
    with _lock:
        _subscribers.append(queue)


def unsubscribe(queue):
    with _lock:
        try:
            _subscribers.remove(queue)
        except ValueError:
            pass
