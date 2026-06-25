# threat_engine/response_recommender.py
"""
Response Recommendation Engine
Maps threat profiles to appropriate automated and manual response actions.
"""
from typing import Optional


# ─── Playbook catalog ────────────────────────────────────────────────────────
# Each playbook: {id, name, actions, severity_threshold, auto_execute}
PLAYBOOKS = {
    "PB-001": {
        "id":                "PB-001",
        "name":              "Block Malicious IP",
        "description":       "Automatically block the source IP at the network perimeter.",
        "actions":           ["block_ip", "create_incident", "notify_analyst"],
        "severity_threshold": 60,
        "auto_execute":      True,
        "mitre_tactics":     ["TA0043", "TA0001", "TA0006"],
    },
    "PB-002": {
        "id":                "PB-002",
        "name":              "Host Isolation",
        "description":       "Isolate the compromised host from the network to contain the incident.",
        "actions":           ["isolate_host", "capture_memory", "create_case", "notify_soc"],
        "severity_threshold": 75,
        "auto_execute":      True,
        "mitre_tactics":     ["TA0004", "TA0008", "TA0010"],
    },
    "PB-003": {
        "id":                "PB-003",
        "name":              "Account Lockdown",
        "description":       "Disable compromised user account and force password reset.",
        "actions":           ["disable_account", "force_password_reset", "notify_hr", "create_incident"],
        "severity_threshold": 55,
        "auto_execute":      True,
        "mitre_tactics":     ["TA0006", "TA0001"],
    },
    "PB-004": {
        "id":                "PB-004",
        "name":              "Process Termination",
        "description":       "Kill the malicious process and quarantine related files.",
        "actions":           ["kill_process", "quarantine_file", "create_incident"],
        "severity_threshold": 65,
        "auto_execute":      True,
        "mitre_tactics":     ["TA0002", "TA0005"],
    },
    "PB-005": {
        "id":                "PB-005",
        "name":              "Threat Hunt Initiation",
        "description":       "Trigger broader threat hunt across the environment based on IOCs.",
        "actions":           ["extract_iocs", "hunt_lateral_movement", "create_case", "notify_analyst"],
        "severity_threshold": 50,
        "auto_execute":      False,
        "mitre_tactics":     ["TA0008", "TA0011"],
    },
    "PB-006": {
        "id":                "PB-006",
        "name":              "DDoS Mitigation",
        "description":       "Engage rate-limiting and upstream scrubbing for DoS events.",
        "actions":           ["rate_limit_ip", "engage_scrubbing", "notify_noc"],
        "severity_threshold": 60,
        "auto_execute":      True,
        "mitre_tactics":     ["TA0040"],
    },
    "PB-007": {
        "id":                "PB-007",
        "name":              "Brute Force Response",
        "description":       "Block attacking IP and increase auth monitoring for targeted accounts.",
        "actions":           ["block_ip", "increase_auth_logging", "create_incident"],
        "severity_threshold": 40,
        "auto_execute":      True,
        "mitre_tactics":     ["TA0006"],
    },
    "PB-008": {
        "id":                "PB-008",
        "name":              "Anomaly Investigation",
        "description":       "Collect additional context for behavioral anomaly analysis.",
        "actions":           ["collect_process_tree", "collect_network_connections", "create_incident"],
        "severity_threshold": 35,
        "auto_execute":      False,
        "mitre_tactics":     [],
    },
    "PB-009": {
        "id":                "PB-009",
        "name":              "Campaign Containment",
        "description":       "Full containment response for detected multi-stage attack campaign.",
        "actions":           ["isolate_host", "block_ip", "disable_account", "create_case", "notify_ciso"],
        "severity_threshold": 70,
        "auto_execute":      True,
        "mitre_tactics":     [],  # Applied for campaigns regardless of tactic
    },
}


def _get_severity_label(score: int) -> str:
    if score >= 80: return "CRITICAL"
    if score >= 60: return "HIGH"
    if score >= 40: return "MEDIUM"
    if score >= 20: return "LOW"
    return "INFO"


def recommend(enriched: dict) -> dict:
    """
    Given a fully enriched event, recommend appropriate response playbooks.
    Returns:
    {
        "playbooks": list[dict],
        "auto_playbooks": list[dict],
        "manual_playbooks": list[dict],
        "primary_playbook": dict | None,
        "recommended_actions": list[str],
    }
    """
    risk     = enriched.get("risk", {})
    mitre    = enriched.get("mitre", {})
    anomaly  = enriched.get("anomaly", {})
    campaign = enriched.get("campaign", {})

    score       = risk.get("score", 0)
    tactic_id   = mitre.get("tactic_id", "")
    is_campaign = campaign.get("is_multi_stage", False)
    is_anomaly  = anomaly.get("anomaly_detected", False)

    matched: list = []

    # Campaign → always PB-009 if severe enough
    if is_campaign and score >= 60:
        matched.append(PLAYBOOKS["PB-009"])

    # Tactic-based matching
    for pb in PLAYBOOKS.values():
        if pb["id"] == "PB-009":
            continue  # already handled
        if score < pb["severity_threshold"]:
            continue
        if tactic_id in pb["mitre_tactics"] or not pb["mitre_tactics"]:
            matched.append(pb)

    # Anomaly-only path
    if is_anomaly and not matched and score >= 30:
        matched.append(PLAYBOOKS["PB-008"])

    # De-duplicate
    seen = set()
    unique = []
    for pb in matched:
        if pb["id"] not in seen:
            seen.add(pb["id"])
            unique.append(pb)

    auto_pbs   = [pb for pb in unique if pb["auto_execute"]]
    manual_pbs = [pb for pb in unique if not pb["auto_execute"]]

    # Primary = highest-threshold auto playbook
    primary = max(auto_pbs, key=lambda p: p["severity_threshold"]) if auto_pbs else (
              max(manual_pbs, key=lambda p: p["severity_threshold"]) if manual_pbs else None)

    all_actions = []
    for pb in unique:
        for action in pb["actions"]:
            if action not in all_actions:
                all_actions.append(action)

    return {
        "playbooks":           unique,
        "auto_playbooks":      auto_pbs,
        "manual_playbooks":    manual_pbs,
        "primary_playbook":    primary,
        "recommended_actions": all_actions,
        "severity_label":      _get_severity_label(score),
    }
