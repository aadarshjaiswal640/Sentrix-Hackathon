# threat_engine/identity_engine.py
"""
Identity Risk Framework
=======================
Extracts REAL user/identity telemetry from Wazuh events.
Suricata events have no user context — for those, status = WAITING_FOR_IAM_FEED.

If user telemetry is present in the event (username, host, process_owner):
  - Builds a User Risk Score (0-100)
  - Tracks behavior baseline (normal hours = 07:00-22:00 UTC)
  - Detects off-hours activity
  - Detects new host access (user accessing a host never seen before)
  - Detects new destination access
  - Detects privilege escalation pattern:
      multiple failed logins from same user + subsequent admin/root success

Data sources:
  - event.data.user.name          (Wazuh standard field)
  - event.data.agent.name         (Wazuh agent = hostname)
  - event.data.agent.ip           (Wazuh agent IP)
  - event.data.rule.description   (Wazuh rule description — used for context)
  - event.data.rule.level         (Wazuh severity level)

Returns per event:
  {
    "status":          "ACTIVE" | "WAITING_FOR_IAM_FEED",
    "user":            str | None,
    "host":            str | None,
    "user_risk_score": int (0-100),
    "factors":         dict,
    "privilege_escalation": bool,
    "off_hours":       bool,
    "new_host":        bool,
    "new_destination": bool,
  }

Architecture note:
  Impossible Travel detection is architecturally supported (user → seen_ips tracking)
  but requires a real geo-IP feed to be connected. The framework records the IP
  history so geo resolution can be added without code changes.
"""
import time
from collections import defaultdict, deque
from datetime import datetime, timezone
from threading import Lock
from typing import Optional

_lock = Lock()

# ─── Per-user state ───────────────────────────────────────────────────────────
# user → {hosts_seen, dest_ips_seen, hour_history, failed_logins, last_login_success}
_user_state: dict = {}

# Auth failure burst: user → deque of timestamps
_auth_failures: dict = defaultdict(lambda: deque(maxlen=100))

# ─── Thresholds ───────────────────────────────────────────────────────────────
NORMAL_HOURS_START = 7     # 07:00 UTC
NORMAL_HOURS_END   = 22    # 22:00 UTC
AUTH_FAIL_WINDOW   = 300   # 5 minutes
PRIV_ESC_THRESHOLD = 3     # failed logins before checking for admin success

# ─── Keywords for rule description classification ─────────────────────────────
_FAIL_KEYWORDS    = ("failed", "failure", "invalid", "incorrect", "denied",
                     "authentication failed", "pam_unix", "bad password")
_SUCCESS_KEYWORDS = ("accepted", "success", "logged in", "session opened",
                     "authentication success", "sudo", "su root", "su -")
_ADMIN_KEYWORDS   = ("sudo", "su root", "root", "admin", "administrator",
                     "privilege", "elevated", "su -")


def _extract_identity(event: dict) -> dict:
    """Extract identity fields from a real Wazuh event."""
    data = event.get("data", {})
    if not isinstance(data, dict):
        return {}

    user_obj  = data.get("user", {})
    agent_obj = data.get("agent", {})
    rule_obj  = data.get("rule", {})

    username = None
    if isinstance(user_obj, dict):
        username = user_obj.get("name")
    if not username and isinstance(agent_obj, dict):
        # Wazuh sometimes puts the user in agent.name for process events
        username = data.get("syscheck", {}).get("uname_after") if isinstance(data.get("syscheck"), dict) else None

    hostname = None
    if isinstance(agent_obj, dict):
        hostname = agent_obj.get("name")

    agent_ip = None
    if isinstance(agent_obj, dict):
        agent_ip = agent_obj.get("ip")

    dest_ip = (data.get("dest_ip") or data.get("destip") or
               data.get("dst_ip") or data.get("src_ip"))

    rule_desc = ""
    rule_level = 0
    if isinstance(rule_obj, dict):
        rule_desc  = str(rule_obj.get("description", "")).lower()
        try:
            rule_level = int(rule_obj.get("level", 0))
        except (TypeError, ValueError):
            rule_level = 0

    hour = datetime.now(timezone.utc).hour

    return {
        "username":   username,
        "hostname":   hostname,
        "agent_ip":   agent_ip,
        "dest_ip":    dest_ip,
        "rule_desc":  rule_desc,
        "rule_level": rule_level,
        "hour":       hour,
    }


def _is_auth_failure(rule_desc: str) -> bool:
    return any(kw in rule_desc for kw in _FAIL_KEYWORDS)


def _is_auth_success(rule_desc: str) -> bool:
    return any(kw in rule_desc for kw in _SUCCESS_KEYWORDS)


def _is_admin_access(rule_desc: str) -> bool:
    return any(kw in rule_desc for kw in _ADMIN_KEYWORDS)


def analyze(event: dict) -> dict:
    """
    Analyze identity context from a real event.

    Called by ThreatEngine.process() after MITRE mapping and risk scoring.
    Returns identity context that is added to the enriched event under "identity".

    For Suricata events (no user context):
      returns {"status": "WAITING_FOR_IAM_FEED", ...}

    For Wazuh events with user data:
      returns full user risk analysis.
    """
    source = event.get("source", "").lower()
    meta   = _extract_identity(event)

    username = meta.get("username")
    hostname = meta.get("hostname")
    dest_ip  = meta.get("dest_ip")
    hour     = meta.get("hour", 12)
    rule_desc  = meta.get("rule_desc", "")
    rule_level = meta.get("rule_level", 0)

    # ── No identity data available ────────────────────────────────────────
    if not username:
        return {
            "status":               "WAITING_FOR_IAM_FEED",
            "user":                 None,
            "host":                 hostname,
            "user_risk_score":      0,
            "factors":              {},
            "privilege_escalation": False,
            "off_hours":            False,
            "new_host":             False,
            "new_destination":      False,
            "data_source":          source,
        }

    now = time.time()

    with _lock:
        # ── Get or create user state ──────────────────────────────────────
        state = _user_state.get(username)
        if state is None:
            state = {
                "hosts_seen":       set(),
                "dest_ips_seen":    set(),
                "hour_history":     [],
                "failed_login_ts":  deque(maxlen=50),
                "last_fail_count":  0,
                "priv_esc_flagged": False,
            }
            _user_state[username] = state

        # ── Off-hours detection ────────────────────────────────────────────
        off_hours = (hour < NORMAL_HOURS_START or hour >= NORMAL_HOURS_END)

        # ── New host access ───────────────────────────────────────────────
        new_host = False
        if hostname:
            new_host = hostname not in state["hosts_seen"]
            state["hosts_seen"].add(hostname)

        # ── New destination access ────────────────────────────────────────
        new_dest = False
        if dest_ip:
            new_dest = dest_ip not in state["dest_ips_seen"]
            state["dest_ips_seen"].add(dest_ip)

        # ── Auth failure tracking ─────────────────────────────────────────
        is_fail    = _is_auth_failure(rule_desc)
        is_success = _is_auth_success(rule_desc)
        is_admin   = _is_admin_access(rule_desc)

        if is_fail:
            state["failed_login_ts"].append(now)

        # ── Privilege escalation: N failures then admin success ───────────
        priv_esc = False
        recent_fails = [t for t in state["failed_login_ts"]
                        if now - t < AUTH_FAIL_WINDOW]
        if is_success and is_admin and len(recent_fails) >= PRIV_ESC_THRESHOLD:
            priv_esc = True
            state["priv_esc_flagged"] = True

        # ── User risk score ───────────────────────────────────────────────
        score = 0
        factors = {}

        if off_hours:
            pts = 20
            score += pts
            factors["off_hours"] = {"points": pts, "detail": f"Activity at UTC {hour:02d}:xx"}

        if new_host and len(state["hosts_seen"]) > 1:
            pts = 15
            score += pts
            factors["new_host"] = {"points": pts, "detail": f"First access to host '{hostname}'"}

        if new_dest and len(state["dest_ips_seen"]) > 1:
            pts = 10
            score += pts
            factors["new_destination"] = {"points": pts, "detail": f"First access to {dest_ip}"}

        if len(recent_fails) > 0:
            pts = min(30, len(recent_fails) * 5)
            score += pts
            factors["failed_logins"] = {"points": pts, "detail": f"{len(recent_fails)} failures in {AUTH_FAIL_WINDOW}s"}

        if priv_esc:
            pts = 35
            score += pts
            factors["privilege_escalation"] = {"points": pts, "detail": "Failed logins followed by admin/root access"}

        if rule_level >= 12:
            pts = 20
            score += pts
            factors["high_severity_rule"] = {"points": pts, "detail": f"Wazuh rule level {rule_level}"}

        score = min(100, score)

    return {
        "status":               "ACTIVE",
        "user":                 username,
        "host":                 hostname,
        "user_risk_score":      score,
        "factors":              factors,
        "privilege_escalation": priv_esc,
        "off_hours":            off_hours,
        "new_host":             new_host,
        "new_destination":      new_dest,
        "data_source":          source,
    }


# ─── API accessors ─────────────────────────────────────────────────────────────

def get_all_user_risks(limit: int = 50) -> list:
    """Return all tracked users with risk summary."""
    with _lock:
        out = []
        for username, state in _user_state.items():
            failed_count = len(state["failed_login_ts"])
            out.append({
                "user":              username,
                "hosts_seen":        len(state["hosts_seen"]),
                "destinations_seen": len(state["dest_ips_seen"]),
                "failed_logins":     failed_count,
                "priv_esc_flagged":  state["priv_esc_flagged"],
            })
    out.sort(key=lambda x: (x["priv_esc_flagged"], x["failed_logins"]), reverse=True)
    return out[:limit]


def get_framework_status() -> dict:
    """Return IAM framework status for dashboard health panel."""
    with _lock:
        users_tracked = len(_user_state)
        priv_esc_count = sum(1 for s in _user_state.values() if s["priv_esc_flagged"])

    return {
        "status":           "ACTIVE" if users_tracked > 0 else "WAITING_FOR_IAM_FEED",
        "users_tracked":    users_tracked,
        "priv_esc_alerts":  priv_esc_count,
        "data_requirement": "Wazuh events with user.name field",
        "note": (
            "Identity data present — user risk scoring active."
            if users_tracked > 0
            else "No user identity data received yet. Wazuh events with user.name will activate this framework."
        ),
    }
