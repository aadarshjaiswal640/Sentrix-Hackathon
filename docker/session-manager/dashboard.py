# dashboard.py
"""
Session-manager dashboard helpers.
The full dashboard API is served by app.py.
This module provides supplementary dashboard utility functions.
"""
from session import get_all_sessions, push_command
from datetime import datetime


def get_dashboard_summary() -> dict:
    """Return a high-level dashboard summary of all connected agents."""
    all_sessions = get_all_sessions()
    online = [s for s in all_sessions if s.get("status") == "online"]
    offline = [s for s in all_sessions if s.get("status") != "online"]
    total_alerts = sum(len(s.get("alerts", [])) for s in all_sessions)
    pending_commands = sum(
        sum(1 for c in s.get("commands", []) if c.get("status") == "pending")
        for s in all_sessions
    )

    return {
        "total_agents":      len(all_sessions),
        "online_agents":     len(online),
        "offline_agents":    len(offline),
        "total_alerts":      total_alerts,
        "pending_commands":  pending_commands,
        "generated_at":      datetime.utcnow().isoformat(),
    }


def push_broadcast_command(command: str, args: str = "") -> list:
    """Push a command to ALL connected online agents. Returns list of cmd_ids."""
    all_sessions = get_all_sessions()
    results = []
    for s in all_sessions:
        if s.get("status") == "online":
            cmd_id = push_command(s["client_id"], command, args)
            if cmd_id:
                results.append({"client_id": s["client_id"], "cmd_id": cmd_id})
    return results
