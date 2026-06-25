# threat_engine/risk_engine.py
"""
Dynamic Risk Scoring Engine
Produces a 0-100 risk score per event based on multiple weighted factors.

FIX DQ-4.1: Added Suricata Snort-style category strings to CATEGORY_WEIGHTS.
FIX DQ-7.3: _known_bad_ips now uses TTL-based expiration (default 24 h).
"""
import math
import time
from collections import defaultdict, deque
from datetime import datetime, timezone
from threading import Lock
from typing import Optional

# ─── Severity mappings ──────────────────────────────────────────────────────
SEVERITY_SCORES = {
    1: 10, 2: 20, 3: 35, 4: 55, 5: 75,
    "low": 20, "medium": 45, "high": 70, "critical": 90,
    "informational": 5, "info": 5,
}

# ─── Category weights ────────────────────────────────────────────────────────
# Includes both internal semantic labels AND real Suricata/Snort category strings.
# Lookup: substring match (case-insensitive) — longest key matching the category wins.
# FIX: Suricata alert.category values (Snort-style) now have explicit weights
#      so they no longer silently fall back to 1.0.

CATEGORY_WEIGHTS = {
    # ── Internal / semantic labels ──────────────────────────────────────
    "brute force":                          0.85,
    "exploit":                              1.0,
    "privilege escalation":                 0.95,
    "lateral movement":                     0.9,
    "credential access":                    0.85,
    "command and control":                  0.9,
    "exfiltration":                         0.95,
    "impact":                               1.0,
    "defense evasion":                      0.8,
    "reconnaissance":                       0.6,
    "scan":                                 0.55,
    "anomaly":                              0.7,
    "policy violation":                     0.4,
    "network":                              0.5,

    # ── Suricata / Snort category strings ───────────────────────────────
    # Exact category strings Suricata places in alert.category
    "attempted administrator privilege gain": 1.0,
    "successful administrator privilege gain": 1.0,
    "attempted user privilege gain":          0.95,
    "successful user privilege gain":         0.95,
    "web application attack":                 1.0,
    "attempted information leak":             0.6,
    "successful information leak":            0.75,
    "large scale information leak":           0.85,
    "information leak":                       0.65,
    "network trojan was detected":            0.9,
    "a network trojan was detected":          0.9,
    "network trojan":                         0.9,
    "trojan activity":                        0.9,
    "denial of service":                      0.85,
    "denial-of-service":                      0.85,
    "denial of service attack":               0.85,
    "attempted denial of service":            0.75,
    "malware command and control":            0.95,
    "command and control activity":           0.9,
    "malware":                                0.9,
    "executable code was detected":           0.85,
    "shellcode detected":                     1.0,
    "potential corporate privacy violation":  0.45,
    "corporate privacy violation":            0.45,
    "potentially bad traffic":                0.5,
    "bad traffic":                            0.5,
    "misc activity":                          0.4,
    "misc attack":                            0.7,
    "detection of a network scan":            0.55,
    "network scan":                           0.55,
    "not suspicious":                         0.3,
    "protocol command decode":                0.4,
    "unknown traffic":                        0.35,
    "string detect":                          0.35,
    "suspicious":                             0.6,
    "credential phishing":                    0.9,
    "phishing":                               0.85,
}

KILL_CHAIN_MULTIPLIERS = {
    0: 0.5,   # Reconnaissance
    1: 0.6,   # Initial Access
    2: 0.8,   # Exploitation
    3: 0.7,   # Persistence
    4: 0.85,  # Privilege Escalation
    5: 0.75,  # Defense Evasion
    6: 0.8,   # Credential Access
    7: 0.9,   # Lateral Movement
    8: 0.85,  # C2
    9: 0.95,  # Exfiltration
    10: 1.0,  # Impact
}

# ─── In-memory frequency tracker ────────────────────────────────────────────
_lock = Lock()
_source_ip_history: dict = defaultdict(lambda: deque(maxlen=200))
_asset_history:     dict = defaultdict(lambda: deque(maxlen=200))

# ─── TTL-based bad IP reputation ────────────────────────────────────────────
# Stores: ip → expiry_timestamp (unix seconds)
# FIX DQ-7.3: Was a plain set() with no expiration. Now entries expire after TTL.
BAD_IP_TTL = 24 * 3600   # 24 hours

_known_bad_ips: dict = {}    # ip → expiry_unix_ts
_cleanup_stats: dict = {
    "cleanup_runs":    0,
    "total_expired":   0,
    "active_count":    0,
}


def _cleanup_expired_bad_ips():
    """Remove expired bad-IP entries. Called on every score() invocation."""
    now = time.time()
    expired_keys = [ip for ip, exp in _known_bad_ips.items() if now >= exp]
    for ip in expired_keys:
        del _known_bad_ips[ip]
    _cleanup_stats["cleanup_runs"] += 1
    _cleanup_stats["total_expired"] += len(expired_keys)
    _cleanup_stats["active_count"] = len(_known_bad_ips)


def get_reputation_stats() -> dict:
    """Return debug metrics for the bad-IP reputation store."""
    with _lock:
        _cleanup_expired_bad_ips()
        now = time.time()
        active = [{"ip": ip, "expires_in_s": round(exp - now)}
                  for ip, exp in sorted(_known_bad_ips.items(),
                                        key=lambda x: x[1])]
        return {
            "active_bad_ips":   len(active),
            "cleanup_runs":     _cleanup_stats["cleanup_runs"],
            "total_expired":    _cleanup_stats["total_expired"],
            "active_entries":   active[:50],
        }


def _get_severity(event: dict) -> int:
    """Extract numeric severity 1-5 from Suricata or Wazuh event."""
    data = event.get("data", {})
    if not isinstance(data, dict):
        return 2

    _SURICATA_REMAP = {1: 5, 2: 3, 3: 2, 4: 1}
    alert = data.get("alert", {})
    if isinstance(alert, dict) and "severity" in alert:
        raw = int(alert["severity"])
        return _SURICATA_REMAP.get(raw, 2)

    rule = data.get("rule", {})
    if isinstance(rule, dict):
        lvl = rule.get("level", 3)
        return max(1, min(5, int(lvl) // 3 + 1))

    return 2


def _get_category(event: dict) -> str:
    data = event.get("data", {})
    if not isinstance(data, dict):
        return ""
    alert = data.get("alert", {})
    if isinstance(alert, dict):
        cat = str(alert.get("category", "")).lower().strip()
        if cat:
            return cat
    rule = data.get("rule", {})
    if isinstance(rule, dict):
        return str(rule.get("description", "")).lower().strip()
    return ""


def _get_category_weight(category: str) -> float:
    """
    Look up category weight using longest-key-first substring matching.

    Longest key matched first so that specific Suricata categories (e.g.
    "attempted administrator privilege gain") take precedence over shorter
    generic keys (e.g. "privilege escalation").

    Returns 0.65 as a neutral default (not 1.0) when no key matches.
    """
    if not category:
        return 0.65

    # Sort keys by length descending so most-specific wins
    for cat_key in sorted(CATEGORY_WEIGHTS, key=len, reverse=True):
        if cat_key in category:
            return CATEGORY_WEIGHTS[cat_key]

    return 0.65   # neutral default — previously was 1.0 (inflated)


def _get_source_ip(event: dict) -> Optional[str]:
    data = event.get("data", {})
    if not isinstance(data, dict):
        return None
    agent = data.get("agent")
    return (
        data.get("src_ip") or
        data.get("srcip") or
        (agent.get("ip") if isinstance(agent, dict) else None)
    )


def _get_dest_ip(event: dict) -> Optional[str]:
    data = event.get("data", {})
    if not isinstance(data, dict):
        return None
    return data.get("dest_ip") or data.get("destip") or data.get("dst_ip")


def _frequency_score(ip: Optional[str], asset: Optional[str]) -> float:
    """Return 0–30 bonus based on recent event frequency for this IP/asset."""
    now = datetime.now(timezone.utc).timestamp()
    window = 300

    ip_count = 0
    asset_count = 0

    with _lock:
        if ip:
            ts_list = _source_ip_history[ip]
            ip_count = sum(1 for t in ts_list if now - t < window)
            ts_list.append(now)

        if asset:
            ts_list = _asset_history[asset]
            asset_count = sum(1 for t in ts_list if now - t < window)
            ts_list.append(now)

    freq = max(ip_count, asset_count)
    return min(30, math.log1p(freq) * 8)


def _reputation_bonus(ip: Optional[str]) -> float:
    """Return +15 if IP is a known bad actor with a non-expired TTL entry."""
    if not ip:
        return 0.0
    now = time.time()
    with _lock:
        expiry = _known_bad_ips.get(ip)
        if expiry and now < expiry:
            return 15.0
    return 0.0


def score(event: dict, mitre_context: Optional[dict] = None) -> dict:
    """
    Compute a risk score for the event.

    Returns:
        {
            "score":        int (0-100),
            "severity_raw": int (1-5),
            "category":     str,
            "src_ip":       str | None,
            "dest_ip":      str | None,
            "factors":      dict,
        }
    """
    with _lock:
        _cleanup_expired_bad_ips()

    sev      = _get_severity(event)
    base     = SEVERITY_SCORES.get(sev, 20)
    category = _get_category(event)
    cat_weight = _get_category_weight(category)

    kc_mult = 1.0
    if mitre_context:
        kc_pos  = mitre_context.get("kill_chain_position", 0)
        kc_mult = KILL_CHAIN_MULTIPLIERS.get(kc_pos, 1.0)

    src_ip = _get_source_ip(event)
    dest_ip = _get_dest_ip(event)
    asset   = dest_ip or (
        event.get("data", {}).get("hostname")
        if isinstance(event.get("data"), dict) else None
    )

    freq_bonus = _frequency_score(src_ip, asset)
    rep_bonus  = _reputation_bonus(src_ip)

    raw_score = (base * cat_weight * kc_mult) + freq_bonus + rep_bonus
    final     = int(min(100, max(0, raw_score)))

    # Register bad IP with TTL
    with _lock:
        if final >= 70 and src_ip:
            _known_bad_ips[src_ip] = time.time() + BAD_IP_TTL

    return {
        "score":        final,
        "severity_raw": sev,
        "category":     category,
        "src_ip":       src_ip,
        "dest_ip":      dest_ip,
        "factors": {
            "base_severity":    base,
            "category_weight":  round(cat_weight, 2),
            "kill_chain_mult":  round(kc_mult, 2),
            "frequency_bonus":  round(freq_bonus, 2),
            "reputation_bonus": rep_bonus,
        }
    }


def severity_label(score_val: int) -> str:
    if score_val >= 80: return "CRITICAL"
    if score_val >= 60: return "HIGH"
    if score_val >= 40: return "MEDIUM"
    if score_val >= 20: return "LOW"
    return "INFO"
