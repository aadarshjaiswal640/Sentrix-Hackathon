# executor_service/dispatcher.py
"""
SOAR Dispatcher
Routes enriched events to appropriate playbooks and dispatches action execution.
Maintains a response execution history for dashboard tracking.
"""
import time
import uuid
from collections import deque
from threading import Lock
from datetime import datetime, timezone
from typing import Optional

from pipeline.executor_service.actions import execute_action

_lock = Lock()
_execution_history: deque = deque(maxlen=500)   # ring buffer of execution records


def _build_action_context(enriched: dict) -> dict:
    """Build context dict for action functions from enriched event."""
    risk     = enriched.get("risk", {})
    mitre    = enriched.get("mitre", {})
    campaign = enriched.get("campaign", {})
    ai_ctx   = enriched.get("ai_analysis", {})

    src_ip   = risk.get("src_ip", "")
    dest_ip  = risk.get("dest_ip", "")
    score    = risk.get("score", 0)

    data = enriched.get("data", {})
    hostname = ""
    username = ""
    process_name = ""
    if isinstance(data, dict):
        hostname = (data.get("hostname") or
                   (data.get("agent", {}).get("name") if isinstance(data.get("agent"), dict) else ""))
        user_obj = data.get("user", {})
        if isinstance(user_obj, dict):
            username = user_obj.get("name", "")
        proc_obj = data.get("process", {})
        if isinstance(proc_obj, dict):
            process_name = proc_obj.get("name", "")

    severity_label = "CRITICAL" if score >= 80 else "HIGH" if score >= 60 else "MEDIUM" if score >= 40 else "LOW"

    return {
        "ip":           src_ip,
        "src_ip":       src_ip,
        "dest_ip":      dest_ip,
        "hostname":     hostname,
        "username":     username,
        "process_name": process_name,
        "severity":     severity_label,
        "campaign_id":  campaign.get("campaign_id", ""),
        "title":        ai_ctx.get("summary", "Automated incident")[:120],
        "details":      ai_ctx.get("technique_context", ""),
        "message":      ai_ctx.get("summary", "")[:200],
        "summary":      ai_ctx.get("summary", "")[:200],
        "reason":       f"{mitre.get('technique_id', '')} — {mitre.get('technique_name', '')}",
        "priority":     severity_label,
    }


def dispatch(enriched: dict, playbook: dict) -> dict:
    """
    Execute all actions in the given playbook for the enriched event.
    Returns an execution record.
    """
    exec_id      = str(uuid.uuid4())[:8].upper()
    pb_id        = playbook.get("id", "PB-???")
    pb_name      = playbook.get("name", "Unknown Playbook")
    action_names = playbook.get("actions", [])
    context      = _build_action_context(enriched)

    results = []
    for action_name in action_names:
        result = execute_action(action_name, context)
        results.append(result)

    success_count = sum(1 for r in results if r.get("status") == "executed")
    record = {
        "exec_id":       exec_id,
        "playbook_id":   pb_id,
        "playbook_name": pb_name,
        "executed_at":   datetime.now(timezone.utc).isoformat(),
        "auto":          playbook.get("auto_execute", False),
        "action_count":  len(action_names),
        "success_count": success_count,
        "actions":       results,
        "context_summary": {
            "src_ip":    context.get("src_ip"),
            "hostname":  context.get("hostname"),
            "severity":  context.get("severity"),
            "campaign":  context.get("campaign_id"),
        },
    }

    with _lock:
        _execution_history.append(record)

    return record


def get_execution_history(limit: int = 50) -> list:
    """Return recent response execution records for dashboard."""
    with _lock:
        history = list(_execution_history)
    history.sort(key=lambda r: r["executed_at"], reverse=True)
    return history[:limit]


def get_response_stats() -> dict:
    """Aggregated response statistics."""
    with _lock:
        history = list(_execution_history)

    from collections import Counter
    pb_counts   = Counter(r["playbook_id"] for r in history)
    auto_count  = sum(1 for r in history if r.get("auto"))
    total       = len(history)
    success     = sum(r["success_count"] for r in history)
    total_acts  = sum(r["action_count"] for r in history)

    return {
        "total_responses":   total,
        "automated":         auto_count,
        "manual":            total - auto_count,
        "total_actions":     total_acts,
        "successful_actions": success,
        "playbook_usage":    dict(pb_counts.most_common(10)),
    }
