# executor_service/actions.py
"""
SOAR Action Library
Simulated response actions. Each action logs what it would do in production
and returns a structured result. Replace simulation stubs with real API calls
for production deployment (firewall API, AD API, EDR API, etc.).
"""
import uuid
import time
from datetime import datetime, timezone
from typing import Optional

from logger import log


def _action_result(action: str, status: str, entity: str, details: str, simulated: bool = True) -> dict:
    return {
        "action_id":   str(uuid.uuid4())[:8],
        "action":      action,
        "status":      status,
        "entity":      entity,
        "details":     details,
        "simulated":   simulated,
        "executed_at": datetime.now(timezone.utc).isoformat(),
    }


# ─── Network Actions ─────────────────────────────────────────────────────────

def block_ip(ip: Optional[str], reason: str = "", **kwargs) -> dict:
    if not ip:
        return _action_result("block_ip", "skipped", "", "No IP provided")
    log(f"[EXECUTOR] BLOCK IP: {ip} | Reason: {reason}", "WARNING")
    # Production: call firewall / WAF API here
    return _action_result(
        "block_ip", "executed", ip,
        f"IP {ip} added to blocklist. Reason: {reason}"
    )


def rate_limit_ip(ip: Optional[str], rate: str = "10/min", **kwargs) -> dict:
    if not ip:
        return _action_result("rate_limit_ip", "skipped", "", "No IP provided")
    log(f"[EXECUTOR] RATE LIMIT: {ip} → {rate}", "WARNING")
    return _action_result(
        "rate_limit_ip", "executed", ip,
        f"Rate limit {rate} applied to {ip}"
    )


def engage_scrubbing(**kwargs) -> dict:
    log("[EXECUTOR] DDoS scrubbing service engaged", "WARNING")
    return _action_result(
        "engage_scrubbing", "executed", "upstream",
        "Upstream scrubbing center activated for DDoS mitigation"
    )


# ─── Host Actions ─────────────────────────────────────────────────────────────

def isolate_host(hostname: Optional[str], ip: Optional[str] = None, **kwargs) -> dict:
    entity = hostname or ip or "unknown"
    log(f"[EXECUTOR] HOST ISOLATION: {entity}", "WARNING")
    return _action_result(
        "isolate_host", "executed", entity,
        f"Host {entity} isolated from network. Only SOC management traffic permitted."
    )


def capture_memory(hostname: Optional[str], **kwargs) -> dict:
    entity = hostname or "unknown"
    log(f"[EXECUTOR] MEMORY CAPTURE: {entity}", "INFO")
    return _action_result(
        "capture_memory", "executed", entity,
        f"Memory acquisition initiated on {entity}. Artifact stored in forensics vault."
    )


def kill_process(process_name: Optional[str], hostname: Optional[str] = None, pid: Optional[int] = None, **kwargs) -> dict:
    entity = f"{process_name or 'unknown'} on {hostname or 'unknown'}"
    log(f"[EXECUTOR] KILL PROCESS: {entity}", "WARNING")
    return _action_result(
        "kill_process", "executed", entity,
        f"Process '{process_name}' (PID: {pid}) terminated on {hostname}"
    )


def quarantine_file(file_path: Optional[str], hostname: Optional[str] = None, **kwargs) -> dict:
    entity = file_path or "unknown"
    log(f"[EXECUTOR] QUARANTINE FILE: {entity} on {hostname}", "WARNING")
    return _action_result(
        "quarantine_file", "executed", entity,
        f"File '{file_path}' quarantined on {hostname}. Hash recorded."
    )


def collect_process_tree(hostname: Optional[str], **kwargs) -> dict:
    entity = hostname or "unknown"
    log(f"[EXECUTOR] PROCESS TREE COLLECTION: {entity}", "INFO")
    return _action_result(
        "collect_process_tree", "executed", entity,
        f"Full process tree snapshot collected from {entity}"
    )


def collect_network_connections(hostname: Optional[str], **kwargs) -> dict:
    entity = hostname or "unknown"
    log(f"[EXECUTOR] NETWORK CONNECTION COLLECTION: {entity}", "INFO")
    return _action_result(
        "collect_network_connections", "executed", entity,
        f"Active network connections snapshot collected from {entity}"
    )


# ─── Identity Actions ─────────────────────────────────────────────────────────

def disable_account(username: Optional[str], **kwargs) -> dict:
    entity = username or "unknown"
    log(f"[EXECUTOR] DISABLE ACCOUNT: {entity}", "WARNING")
    return _action_result(
        "disable_account", "executed", entity,
        f"Account '{entity}' disabled in directory. MFA tokens revoked."
    )


def force_password_reset(username: Optional[str], **kwargs) -> dict:
    entity = username or "unknown"
    log(f"[EXECUTOR] FORCE PASSWORD RESET: {entity}", "INFO")
    return _action_result(
        "force_password_reset", "executed", entity,
        f"Password reset enforced for '{entity}'. User will be prompted on next login."
    )


def increase_auth_logging(username: Optional[str] = None, ip: Optional[str] = None, **kwargs) -> dict:
    entity = username or ip or "global"
    log(f"[EXECUTOR] INCREASE AUTH LOGGING: {entity}", "INFO")
    return _action_result(
        "increase_auth_logging", "executed", entity,
        f"Enhanced authentication logging enabled for {entity}"
    )


# ─── Case / Incident Management ──────────────────────────────────────────────

def create_incident(title: str = "", severity: str = "MEDIUM", details: str = "", **kwargs) -> dict:
    incident_id = f"INC-{int(time.time()) % 100000:05d}"
    log(f"[EXECUTOR] CREATE INCIDENT: {incident_id} — {title}", "INFO")
    return _action_result(
        "create_incident", "executed", incident_id,
        f"Incident {incident_id} created. Severity: {severity}. Title: {title}"
    )


def create_case(title: str = "", priority: str = "HIGH", **kwargs) -> dict:
    case_id = f"CASE-{int(time.time()) % 100000:05d}"
    log(f"[EXECUTOR] CREATE CASE: {case_id} — {title}", "INFO")
    return _action_result(
        "create_case", "executed", case_id,
        f"Case {case_id} created in case management system. Priority: {priority}"
    )


# ─── Notification Actions ─────────────────────────────────────────────────────

def notify_analyst(message: str = "", severity: str = "", **kwargs) -> dict:
    log(f"[EXECUTOR] NOTIFY ANALYST: [{severity}] {message}", "INFO")
    return _action_result(
        "notify_analyst", "executed", "soc-team",
        f"SOC analyst notified: {message}"
    )


def notify_soc(message: str = "", **kwargs) -> dict:
    log(f"[EXECUTOR] NOTIFY SOC: {message}", "INFO")
    return _action_result(
        "notify_soc", "executed", "soc-team",
        f"SOC team notification sent: {message}"
    )


def notify_noc(message: str = "", **kwargs) -> dict:
    log(f"[EXECUTOR] NOTIFY NOC: {message}", "INFO")
    return _action_result(
        "notify_noc", "executed", "noc-team",
        f"NOC team notification sent: {message}"
    )


def notify_hr(username: str = "", **kwargs) -> dict:
    log(f"[EXECUTOR] NOTIFY HR: account action on {username}", "INFO")
    return _action_result(
        "notify_hr", "executed", username,
        f"HR team notified of account action for user '{username}'"
    )


def notify_ciso(summary: str = "", **kwargs) -> dict:
    log(f"[EXECUTOR] NOTIFY CISO: {summary}", "WARNING")
    return _action_result(
        "notify_ciso", "executed", "ciso",
        f"CISO notified: {summary}"
    )


# ─── Threat Hunt ──────────────────────────────────────────────────────────────

def extract_iocs(**kwargs) -> dict:
    log("[EXECUTOR] IOC EXTRACTION initiated", "INFO")
    return _action_result(
        "extract_iocs", "executed", "threat-intel",
        "IOC extraction job initiated. Results pushed to threat intel platform."
    )


def hunt_lateral_movement(campaign_id: str = "", **kwargs) -> dict:
    log(f"[EXECUTOR] LATERAL MOVEMENT HUNT: campaign {campaign_id}", "INFO")
    return _action_result(
        "hunt_lateral_movement", "executed", campaign_id,
        f"Lateral movement hunt initiated for campaign {campaign_id}"
    )


# ─── Action dispatcher ────────────────────────────────────────────────────────
ACTION_REGISTRY = {
    "block_ip":                  block_ip,
    "rate_limit_ip":             rate_limit_ip,
    "engage_scrubbing":          engage_scrubbing,
    "isolate_host":              isolate_host,
    "capture_memory":            capture_memory,
    "kill_process":              kill_process,
    "quarantine_file":           quarantine_file,
    "collect_process_tree":      collect_process_tree,
    "collect_network_connections": collect_network_connections,
    "disable_account":           disable_account,
    "force_password_reset":      force_password_reset,
    "increase_auth_logging":     increase_auth_logging,
    "create_incident":           create_incident,
    "create_case":               create_case,
    "notify_analyst":            notify_analyst,
    "notify_soc":                notify_soc,
    "notify_noc":                notify_noc,
    "notify_hr":                 notify_hr,
    "notify_ciso":               notify_ciso,
    "extract_iocs":              extract_iocs,
    "hunt_lateral_movement":     hunt_lateral_movement,
}


def execute_action(action_name: str, context: dict) -> dict:
    fn = ACTION_REGISTRY.get(action_name)
    if not fn:
        return _action_result(action_name, "error", "", f"Unknown action: {action_name}")
    try:
        return fn(**context)
    except Exception as e:
        return _action_result(action_name, "error", "", str(e))
