# threat_engine/mitre_engine.py
"""
MITRE ATT&CK Mapping Engine
Maps detected events to tactics, techniques, and kill-chain stages.

FIX DQ-3: Replaced first-match-wins (break) with best-specificity scoring.
           All rules evaluated; highest-scoring match wins.
           Added mappings for T1133, T1078, T1543, T1027, T1589, T1110.001.
"""
from collections import Counter
from threading import Lock
from typing import Optional

# ─── MITRE ATT&CK Knowledge Base ───────────────────────────────────────────
MITRE_TACTICS = {
    "TA0001": "Initial Access",
    "TA0002": "Execution",
    "TA0003": "Persistence",
    "TA0004": "Privilege Escalation",
    "TA0005": "Defense Evasion",
    "TA0006": "Credential Access",
    "TA0007": "Discovery",
    "TA0008": "Lateral Movement",
    "TA0009": "Collection",
    "TA0010": "Exfiltration",
    "TA0011": "Command and Control",
    "TA0040": "Impact",
    "TA0042": "Resource Development",
    "TA0043": "Reconnaissance",
}

MITRE_TECHNIQUES = {
    "T1190":    {"name": "Exploit Public-Facing Application", "tactic": "TA0001", "kill_chain": "Exploitation"},
    "T1133":    {"name": "External Remote Services",          "tactic": "TA0001", "kill_chain": "Initial Access"},
    "T1078":    {"name": "Valid Accounts",                    "tactic": "TA0001", "kill_chain": "Initial Access"},
    "T1059":    {"name": "Command and Scripting Interpreter", "tactic": "TA0002", "kill_chain": "Execution"},
    "T1059.001":{"name": "PowerShell",                        "tactic": "TA0002", "kill_chain": "Execution"},
    "T1059.004":{"name": "Unix Shell",                        "tactic": "TA0002", "kill_chain": "Execution"},
    "T1543":    {"name": "Create or Modify System Process",   "tactic": "TA0003", "kill_chain": "Persistence"},
    "T1547":    {"name": "Boot or Logon Autostart Execution", "tactic": "TA0003", "kill_chain": "Persistence"},
    "T1548":    {"name": "Abuse Elevation Control Mechanism", "tactic": "TA0004", "kill_chain": "Privilege Escalation"},
    "T1055":    {"name": "Process Injection",                 "tactic": "TA0004", "kill_chain": "Privilege Escalation"},
    "T1027":    {"name": "Obfuscated Files or Information",   "tactic": "TA0005", "kill_chain": "Defense Evasion"},
    "T1562":    {"name": "Impair Defenses",                   "tactic": "TA0005", "kill_chain": "Defense Evasion"},
    "T1003":    {"name": "OS Credential Dumping",             "tactic": "TA0006", "kill_chain": "Credential Access"},
    "T1110":    {"name": "Brute Force",                       "tactic": "TA0006", "kill_chain": "Credential Access"},
    "T1110.001":{"name": "Password Guessing",                 "tactic": "TA0006", "kill_chain": "Credential Access"},
    "T1110.003":{"name": "Password Spraying",                 "tactic": "TA0006", "kill_chain": "Credential Access"},
    "T1046":    {"name": "Network Service Discovery",         "tactic": "TA0007", "kill_chain": "Reconnaissance"},
    "T1082":    {"name": "System Information Discovery",      "tactic": "TA0007", "kill_chain": "Reconnaissance"},
    "T1021":    {"name": "Remote Services",                   "tactic": "TA0008", "kill_chain": "Lateral Movement"},
    "T1021.001":{"name": "Remote Desktop Protocol",           "tactic": "TA0008", "kill_chain": "Lateral Movement"},
    "T1021.004":{"name": "SSH",                               "tactic": "TA0008", "kill_chain": "Lateral Movement"},
    "T1071":    {"name": "Application Layer Protocol",        "tactic": "TA0011", "kill_chain": "C2"},
    "T1041":    {"name": "Exfiltration Over C2 Channel",      "tactic": "TA0010", "kill_chain": "Exfiltration"},
    "T1498":    {"name": "Network Denial of Service",         "tactic": "TA0040", "kill_chain": "Impact"},
    "T1595":    {"name": "Active Scanning",                   "tactic": "TA0043", "kill_chain": "Reconnaissance"},
    "T1589":    {"name": "Gather Victim Identity Information","tactic": "TA0043", "kill_chain": "Reconnaissance"},
}

KILL_CHAIN_ORDER = [
    "Reconnaissance", "Initial Access", "Exploitation",
    "Persistence", "Privilege Escalation", "Defense Evasion",
    "Credential Access", "Lateral Movement", "C2", "Exfiltration", "Impact"
]

# ─── Signature → Technique mappings ────────────────────────────────────────
# Each entry: (keywords_list, technique_id)
# Specificity score = sum of lengths of matched keywords (longer keyword = more specific match).
# All rules are evaluated; the rule with the highest total matched-keyword-length wins.
# Sub-technique entries (T1110.001, T1021.004 etc.) use more specific keywords so
# they naturally outscore their parent technique entries for the same event text.

_SIGNATURE_MAP = [
    # ── Credential Access ──────────────────────────────────────────────────
    (["password spray", "multiple user", "multiple accounts"],  "T1110.003"),   # most specific spraying
    (["password guess", "credential test", "credential check"], "T1110.001"),   # password guessing
    (["ssh brute", "ssh invalid", "ssh failed"],                "T1021.004"),   # SSH brute (specific)
    (["rdp brute", "rdp fail", "rdp invalid"],                  "T1021.001"),   # RDP brute (specific)
    (["brute", "failed login", "authentication failure",
      "invalid user", "pam_unix", "pam"],                       "T1110"),       # generic brute force
    # ── Credential Dumping ─────────────────────────────────────────────────
    (["mimikatz", "lsass", "hashdump", "shadow copy",
      "credential dump", "ntds"],                               "T1003"),
    # ── Scanning / Recon ──────────────────────────────────────────────────
    (["network scan", "arp scan", "host discovery",
      "service scan", "service enumeration"],                   "T1046"),       # network service discovery
    (["scan", "nmap", "port scan", "stealth scan",
      "xmas scan", "fin scan"],                                 "T1595"),       # active scanning (generic)
    # ── Reconnaissance — identity gathering ───────────────────────────────
    (["whois", "linkedin", "gather victim",
      "employee harvest", "email harvest"],                     "T1589"),
    # ── Exploitation ──────────────────────────────────────────────────────
    (["exploit", "shellcode", "buffer overflow",
      "sql injection", "sqli", "rce", "log4j",
      "cve-", "remote code"],                                   "T1190"),
    # ── Privilege Escalation ──────────────────────────────────────────────
    (["process injection", "ptrace", "ld_preload",
      "dll injection", "reflective"],                           "T1055"),
    (["sudo", "su root", "privilege escalation",
      "setuid", "suid", "elevation", "uac bypass"],             "T1548"),
    # ── Lateral Movement ──────────────────────────────────────────────────
    (["ssh lateral", "ssh pivot", "ssh tunnel"],                "T1021.004"),   # SSH lateral (specific)
    (["rdp lateral", "rdp session"],                            "T1021.001"),   # RDP lateral (specific)
    (["lateral", "psexec", "wmi exec", "pass-the-hash",
      "pth", "smb exec", "dcom"],                               "T1021"),       # generic lateral
    (["ssh", "remote shell"],                                   "T1021.004"),   # SSH (fallback, short keywords)
    # ── Defense Evasion ───────────────────────────────────────────────────
    (["encoded payload", "base64 decode", "base64 encoded",
      "packed payload"],                                        "T1027"),       # obfuscation (specific)
    (["disable audit", "clear log", "log tamper",
      "obfuscat", "disable firewall", "disable av"],            "T1562"),       # impair defenses
    # ── Persistence ───────────────────────────────────────────────────────
    (["systemd service", "service install", "daemon install",
      "new service", "sc create"],                              "T1543"),       # system process persistence
    (["crontab", "rc.local", "autostart",
      "startup script", "boot persist"],                        "T1547"),       # boot/logon autostart
    # ── Execution ─────────────────────────────────────────────────────────
    (["powershell", "ps1", "invoke-expression",
      "iex ", "encoded command"],                               "T1059.001"),
    (["bash script", "shell script", "python exec",
      "python -c", "perl exec"],                                "T1059.004"),
    # ── C2 ────────────────────────────────────────────────────────────────
    (["beacon", "c2 channel", "command and control",
      "reverse shell", "bind shell", "c2 traffic",
      "cobalt strike"],                                         "T1071"),
    # ── Exfiltration ──────────────────────────────────────────────────────
    (["exfil", "data exfil", "data transfer out",
      "ftp out", "upload sensitive"],                           "T1041"),
    # ── Impact / DDoS ─────────────────────────────────────────────────────
    (["ddos", "dos attack", "syn flood",
      "denial of service", "flood attack"],                     "T1498"),
    # ── Initial Access — external remote / valid accounts ─────────────────
    (["vpn access", "external remote", "remote access tool",
      "rat connection", "anydesk", "teamviewer"],               "T1133"),
    (["valid account", "credential reuse", "stolen credential",
      "account takeover", "default credential"],                "T1078"),
]

# ─── Mapping statistics tracker ─────────────────────────────────────────────
_stats_lock = Lock()
_mapping_stats: dict = {
    "total_mapped":       0,
    "fallback_suricata":  0,
    "fallback_wazuh":     0,
    "unmapped_total":     0,
    "technique_counts":   Counter(),
    "rule_hit_counts":    Counter(),   # which rule index fired most
}


def _extract_text(event: dict) -> str:
    """Flatten event to a single searchable text blob (lower-cased)."""
    data = event.get("data", {})
    if isinstance(data, dict):
        parts = []
        for v in data.values():
            if isinstance(v, (str, int)):
                parts.append(str(v).lower())
            elif isinstance(v, dict):
                for vv in v.values():
                    parts.append(str(vv).lower())
        return " ".join(parts)
    return str(data).lower()


def _score_rule(keywords: list, text: str) -> int:
    """
    Compute specificity score for a rule against event text.
    Score = sum of character-lengths of each keyword that appears in text.
    Longer, more specific keyword phrases produce higher scores.
    Returns 0 if no keyword matches.
    """
    score = 0
    for kw in keywords:
        if kw in text:
            score += len(kw)
    return score


def map_event(event: dict) -> dict:
    """
    Map an event to a MITRE ATT&CK technique using best-specificity scoring.

    All rules in _SIGNATURE_MAP are evaluated. The rule whose matched keywords
    have the highest total character-length wins (longer = more specific).
    Falls back to T1046 (Suricata) or T1082 (Wazuh) only when no rule matches.

    Returns:
        {
            "technique_id":       str,
            "technique_name":     str,
            "tactic_id":          str,
            "tactic_name":        str,
            "kill_chain_stage":   str,
            "kill_chain_position":int,
            "match_score":        int,   # 0 = fallback
            "match_method":       str,   # "rule" | "fallback"
        }
    """
    text = _extract_text(event)

    source = event.get("source", "")
    if isinstance(event.get("data"), dict):
        alert_cat = str(event["data"].get("alert", {}).get("category", "")).lower()
        rule_desc = str(event["data"].get("rule", {}).get("description", "")).lower()
        text += " " + alert_cat + " " + rule_desc

    # ── Evaluate all rules; pick highest specificity ──────────────────────
    best_tid:   Optional[str] = None
    best_score: int = 0
    best_rule_idx: int = -1

    for idx, (keywords, tid) in enumerate(_SIGNATURE_MAP):
        s = _score_rule(keywords, text)
        if s > best_score:
            best_score = s
            best_tid = tid
            best_rule_idx = idx

    # ── Fallback by source ────────────────────────────────────────────────
    method = "rule"
    if not best_tid:
        method = "fallback"
        if source == "suricata":
            best_tid = "T1046"
        else:
            best_tid = "T1082"

    tech = MITRE_TECHNIQUES.get(best_tid, MITRE_TECHNIQUES["T1082"])
    tactic_id   = tech["tactic"]
    tactic_name = MITRE_TACTICS.get(tactic_id, "Unknown")
    kc_stage    = tech["kill_chain"]

    try:
        kc_pos = KILL_CHAIN_ORDER.index(kc_stage)
    except ValueError:
        kc_pos = 0

    # ── Update stats ──────────────────────────────────────────────────────
    with _stats_lock:
        if method == "fallback":
            _mapping_stats["unmapped_total"] += 1
            if source == "suricata":
                _mapping_stats["fallback_suricata"] += 1
            else:
                _mapping_stats["fallback_wazuh"] += 1
        else:
            _mapping_stats["total_mapped"] += 1
            if best_rule_idx >= 0:
                _mapping_stats["rule_hit_counts"][best_rule_idx] += 1
        _mapping_stats["technique_counts"][best_tid] += 1

    return {
        "technique_id":        best_tid,
        "technique_name":      tech["name"],
        "tactic_id":           tactic_id,
        "tactic_name":         tactic_name,
        "kill_chain_stage":    kc_stage,
        "kill_chain_position": kc_pos,
        "match_score":         best_score,
        "match_method":        method,
    }


def get_mapping_stats() -> dict:
    """Return accumulated MITRE mapping statistics for diagnostics."""
    with _stats_lock:
        total = (_mapping_stats["total_mapped"] +
                 _mapping_stats["unmapped_total"])
        fallback_pct = (
            round(_mapping_stats["unmapped_total"] / total * 100, 1) if total else 0.0
        )
        top_techniques = _mapping_stats["technique_counts"].most_common(10)
        return {
            "total_events_mapped":   total,
            "rule_matched":          _mapping_stats["total_mapped"],
            "fallback_suricata":     _mapping_stats["fallback_suricata"],
            "fallback_wazuh":        _mapping_stats["fallback_wazuh"],
            "unmapped_total":        _mapping_stats["unmapped_total"],
            "fallback_percentage":   fallback_pct,
            "top_techniques":        [{"technique_id": t, "count": c} for t, c in top_techniques],
            "rule_hit_distribution": dict(_mapping_stats["rule_hit_counts"].most_common(10)),
        }


def reset_mapping_stats():
    """Reset stats (for testing)."""
    with _stats_lock:
        _mapping_stats["total_mapped"] = 0
        _mapping_stats["fallback_suricata"] = 0
        _mapping_stats["fallback_wazuh"] = 0
        _mapping_stats["unmapped_total"] = 0
        _mapping_stats["technique_counts"].clear()
        _mapping_stats["rule_hit_counts"].clear()


def get_all_tactics() -> list:
    return [{"id": k, "name": v} for k, v in MITRE_TACTICS.items()]


def get_all_techniques() -> list:
    return [
        {"id": k, "name": v["name"], "tactic": v["tactic"], "kill_chain": v["kill_chain"]}
        for k, v in MITRE_TECHNIQUES.items()
    ]
