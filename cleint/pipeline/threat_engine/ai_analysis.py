# threat_engine/ai_analysis.py
"""
AI Analysis Engine
Context-aware threat analysis using behavioral heuristics, pattern recognition,
and intelligent narrative generation. Provides analyst-grade event summaries.
"""
from datetime import datetime, timezone
from typing import Optional


# ─── Narrative templates per attack type ────────────────────────────────────
_NARRATIVES = {
    "auth_burst": (
        "Rapid authentication failures detected from {entity}. "
        "This pattern is consistent with automated credential stuffing or brute-force tooling. "
        "Recommend immediate IP block and account lockout review."
    ),
    "off_hours_auth": (
        "Authentication event detected outside business hours for {entity}. "
        "This may indicate compromised credentials or an insider threat scenario. "
        "Validate with the asset owner before escalating."
    ),
    "rare_process": (
        "An uncommonly-seen process '{entity}' executed on this host. "
        "Rare process execution is a strong indicator of living-off-the-land (LoTL) tactics "
        "or malware deployment. Correlate with parent process and network activity."
    ),
    "rare_port": (
        "Connection to an unusual destination port detected: {entity}. "
        "This may represent C2 channel establishment, data staging, or lateral movement. "
        "Inspect packet contents and correlate with DNS queries."
    ),
    "behavior_shift": (
        "Significant behavioral deviation observed for {entity}. "
        "The user's access pattern has statistically shifted beyond normal variance. "
        "This warrants identity verification and session review."
    ),
    "event_rate_burst": (
        "Abnormal event rate spike from {entity}. "
        "Possible automated attack tool, scanner, or worm propagation. "
        "Consider network-level rate limiting and source isolation."
    ),
}

_TECHNIQUE_CONTEXT = {
    "T1110": "Credential brute-force attack. Attacker systematically tries password combinations to gain unauthorized access.",
    "T1595": "Active reconnaissance. Attacker is mapping network topology to identify targets and vulnerabilities.",
    "T1046": "Network service scanning. Attacker enumerating open ports and services on target systems.",
    "T1190": "Public-facing application exploitation. Attacker leveraging known CVE or zero-day against internet-exposed service.",
    "T1548": "Privilege escalation attempt. Attacker trying to gain higher system privileges to expand access.",
    "T1055": "Process injection detected. Adversary injecting code into legitimate processes to evade detection.",
    "T1021": "Remote service access. Attacker moving laterally using remote administration protocols.",
    "T1021.004": "SSH lateral movement detected. Attacker pivoting through SSH using valid or stolen credentials.",
    "T1003": "Credential harvesting underway. Memory or disk-based credential dump in progress.",
    "T1071": "C2 communication detected. Compromised host beaconing to external infrastructure.",
    "T1041": "Data exfiltration in progress. Attacker transferring data via established C2 channel.",
    "T1498": "Denial of service attack. Attacker flooding target to disrupt availability.",
    "T1562": "Defense tampering. Attacker disabling logging, AV, or security controls to operate undetected.",
    "T1547": "Persistence mechanism installed. Attacker establishing boot-time execution to survive reboots.",
}

_SEVERITY_CONTEXT = {
    "CRITICAL": "IMMEDIATE ACTION REQUIRED. This event represents an active, high-confidence threat with significant business impact potential.",
    "HIGH":     "URGENT REVIEW NEEDED. Strong indicators of malicious activity. Escalate to tier-2 analyst within 15 minutes.",
    "MEDIUM":   "INVESTIGATE PROMPTLY. Suspicious activity requiring analyst review within 1 hour.",
    "LOW":      "MONITOR. Low-severity indicator. Log and review during next analyst shift.",
    "INFO":     "INFORMATIONAL. No immediate action required. Retain for historical correlation.",
}

_KILL_CHAIN_CONTEXT = {
    "Reconnaissance":    "Early-stage attack. Attacker gathering intelligence. Window of opportunity to disrupt campaign before damage occurs.",
    "Initial Access":    "Attacker attempting to establish foothold. Detection at this stage prevents full compromise.",
    "Exploitation":      "Active exploitation underway. Attacker has found a vulnerability and is leveraging it.",
    "Persistence":       "Attacker establishing persistence. Indicates intent for long-term presence.",
    "Privilege Escalation": "Attacker escalating privileges. High risk of lateral movement and data access.",
    "Defense Evasion":   "Attacker actively hiding. Security controls may be impaired.",
    "Credential Access": "Credential theft underway. Account compromise likely imminent.",
    "Lateral Movement":  "Attacker pivoting. Multiple systems may be compromised.",
    "C2":                "Active C2 channel. Attacker has persistent remote control capability.",
    "Exfiltration":      "Data leaving the network. Potential data breach in progress.",
    "Impact":            "Destructive action occurring. Ransomware, deletion, or service disruption underway.",
}


def _get_severity_label(score: int) -> str:
    if score >= 80: return "CRITICAL"
    if score >= 60: return "HIGH"
    if score >= 40: return "MEDIUM"
    if score >= 20: return "LOW"
    return "INFO"


def _get_source_name(event: dict) -> str:
    src = event.get("source", "unknown").upper()
    return {"WAZUH": "Wazuh HIDS", "SURICATA": "Suricata IDS"}.get(src, src)


def analyze(enriched: dict) -> dict:
    """
    Generate AI-grade threat analysis context for an enriched event.
    Returns:
    {
        "summary": str,
        "technique_context": str,
        "kill_chain_context": str,
        "severity_guidance": str,
        "recommended_queries": list[str],
        "confidence": str,
        "analyst_notes": str,
    }
    """
    risk     = enriched.get("risk", {})
    mitre    = enriched.get("mitre", {})
    anomaly  = enriched.get("anomaly", {})
    campaign = enriched.get("campaign", {})

    risk_score     = risk.get("score", 0)
    severity       = _get_severity_label(risk_score)
    technique_id   = mitre.get("technique_id", "")
    technique_name = mitre.get("technique_name", "Unknown")
    tactic_name    = mitre.get("tactic_name", "Unknown")
    kill_chain     = mitre.get("kill_chain_stage", "")
    src_ip         = risk.get("src_ip", "unknown")
    source_name    = _get_source_name(enriched)

    # Use the event's own timestamp if present; fall back to current time
    raw_ts = enriched.get("processed_at") or (
        enriched.get("data", {}).get("@timestamp") if isinstance(enriched.get("data"), dict) else None
    )
    try:
        from datetime import timezone as _tz
        event_dt = datetime.fromisoformat(raw_ts.replace("Z", "+00:00")) if raw_ts else datetime.now(timezone.utc)
    except Exception:
        event_dt = datetime.now(timezone.utc)
    now_str = event_dt.strftime("%Y-%m-%d %H:%M UTC")

    # ── Build summary ───────────────────────────────────────────────────────
    anomaly_detected = anomaly.get("anomaly_detected", False)
    primary_anomaly  = anomaly.get("primary_anomaly")
    is_multi_stage   = campaign.get("is_multi_stage", False)
    stage_prog       = campaign.get("stage_progression", kill_chain)

    summary_parts = [
        f"[{now_str}] {source_name} detected {severity} severity event.",
        f"Technique: {technique_id} — {technique_name} ({tactic_name}).",
    ]
    if src_ip and src_ip != "unknown":
        summary_parts.append(f"Source: {src_ip}.")
    if is_multi_stage:
        summary_parts.append(f"Part of multi-stage campaign: {stage_prog}.")
    if anomaly_detected:
        primary_desc = anomaly.get("anomalies", [{}])[0].get("description", "")
        summary_parts.append(f"Behavioral anomaly: {primary_desc}.")

    summary = " ".join(summary_parts)

    # ── Technique context ───────────────────────────────────────────────────
    tech_ctx = _TECHNIQUE_CONTEXT.get(technique_id,
               f"Attack technique {technique_id} detected. Review MITRE ATT&CK documentation for detailed context.")

    # ── Anomaly narrative ───────────────────────────────────────────────────
    analyst_notes = ""
    if primary_anomaly and primary_anomaly in _NARRATIVES:
        entity = ""
        if anomaly.get("anomalies"):
            entity = anomaly["anomalies"][0].get("entity", "")
        analyst_notes = _NARRATIVES[primary_anomaly].format(entity=entity)

    # ── Recommended queries ─────────────────────────────────────────────────
    queries = []
    if src_ip and src_ip != "unknown":
        queries.append(f'src_ip:"{src_ip}"')
        queries.append(f'SELECT * FROM events WHERE src_ip = \'{src_ip}\' ORDER BY timestamp DESC LIMIT 100')
    queries.append(f'mitre.technique_id:"{technique_id}"')
    if is_multi_stage:
        cid = campaign.get("campaign_id", "")
        if cid:
            queries.append(f'campaign_id:"{cid}"')

    # ── Confidence ─────────────────────────────────────────────────────────
    confidence_score = risk_score
    if anomaly_detected:
        confidence_score = min(100, confidence_score + 10)
    if is_multi_stage:
        confidence_score = min(100, confidence_score + 15)

    if confidence_score >= 80:   confidence = "HIGH"
    elif confidence_score >= 50: confidence = "MEDIUM"
    else:                        confidence = "LOW"

    return {
        "summary":           summary,
        "technique_context": tech_ctx,
        "kill_chain_context": _KILL_CHAIN_CONTEXT.get(kill_chain, ""),
        "severity_guidance": _SEVERITY_CONTEXT.get(severity, ""),
        "recommended_queries": queries,
        "confidence":        confidence,
        "analyst_notes":     analyst_notes,
    }
