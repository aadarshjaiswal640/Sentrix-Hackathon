# threat_engine/report_engine.py
"""
Report Engine
Generates structured reports from enriched events and campaigns.
Supports executive summary, analyst detail, and IOC extraction.
"""
from datetime import datetime, timezone
from collections import Counter, defaultdict
from threading import Lock
from typing import Optional

_lock = Lock()
_event_buffer: list = []   # rolling buffer of enriched events for report generation
MAX_BUFFER = 5000


def ingest(enriched: dict):
    """Store enriched event for report generation."""
    with _lock:
        _event_buffer.append(enriched)
        if len(_event_buffer) > MAX_BUFFER:
            _event_buffer.pop(0)


def _get_events_snapshot() -> list:
    with _lock:
        return list(_event_buffer)


def executive_summary() -> dict:
    """
    High-level summary for executive / management view.
    """
    events = _get_events_snapshot()
    now = datetime.now(timezone.utc).isoformat()

    total = len(events)
    if total == 0:
        return {
            "generated_at":    now,
            "total_events":    0,
            "critical_count":  0,
            "high_count":      0,
            "medium_count":    0,
            "low_count":       0,
            "top_techniques":  [],
            "top_src_ips":     [],
            "campaign_count":  0,
            "anomaly_count":   0,
            "summary_text":    "No events processed yet.",
        }

    severity_counts = Counter()
    technique_counts = Counter()
    src_ip_counts = Counter()
    campaign_ids = set()
    anomaly_count = 0

    for ev in events:
        risk = ev.get("risk", {})
        score = risk.get("score", 0)
        if score >= 80:   severity_counts["critical"] += 1
        elif score >= 60: severity_counts["high"] += 1
        elif score >= 40: severity_counts["medium"] += 1
        else:             severity_counts["low"] += 1

        tech = ev.get("mitre", {}).get("technique_id", "")
        if tech:
            technique_counts[tech] += 1

        src = risk.get("src_ip", "")
        if src:
            src_ip_counts[src] += 1

        cid = ev.get("campaign", {}).get("campaign_id", "")
        if cid:
            campaign_ids.add(cid)

        if ev.get("anomaly", {}).get("anomaly_detected"):
            anomaly_count += 1

    top_techniques = [{"technique_id": t, "count": c} for t, c in technique_counts.most_common(5)]
    top_src_ips    = [{"ip": ip, "count": c}            for ip, c in src_ip_counts.most_common(10)]

    crit  = severity_counts["critical"]
    high  = severity_counts["high"]
    med   = severity_counts["medium"]
    low   = severity_counts["low"]

    if crit > 0:
        posture = "CRITICAL — Immediate incident response required."
    elif high > 5:
        posture = "HIGH — Multiple high-severity threats active. Escalate to SOC management."
    elif high > 0 or med > 10:
        posture = "ELEVATED — Active threats detected. Analyst review required."
    elif med > 0:
        posture = "GUARDED — Moderate activity. Continue monitoring."
    else:
        posture = "NORMAL — No significant threats detected."

    return {
        "generated_at":   now,
        "total_events":   total,
        "critical_count": crit,
        "high_count":     high,
        "medium_count":   med,
        "low_count":      low,
        "top_techniques": top_techniques,
        "top_src_ips":    top_src_ips,
        "campaign_count": len(campaign_ids),
        "anomaly_count":  anomaly_count,
        "posture":        posture,
        "summary_text":   (
            f"Security posture: {posture} "
            f"Total events: {total}. "
            f"Critical: {crit}, High: {high}, Medium: {med}, Low: {low}. "
            f"Active campaigns: {len(campaign_ids)}. "
            f"Behavioral anomalies: {anomaly_count}."
        ),
    }


def extract_iocs(limit: int = 100) -> dict:
    """Extract Indicators of Compromise from recent events."""
    events = _get_events_snapshot()
    ips:       set = set()
    domains:   set = set()
    hashes:    set = set()
    processes: set = set()

    for ev in events[-limit:]:
        risk = ev.get("risk", {})
        src  = risk.get("src_ip", "")
        dst  = risk.get("dest_ip", "")
        if src: ips.add(src)
        if dst: ips.add(dst)

        data = ev.get("data", {})
        if isinstance(data, dict):
            # DNS
            dns = data.get("dns", {})
            if isinstance(dns, dict):
                q = dns.get("rrname", "")
                if q: domains.add(q)

            # File hashes (Wazuh syscheck)
            syschk = data.get("syscheck", {})
            if isinstance(syschk, dict):
                h = syschk.get("sha256_after") or syschk.get("md5_after", "")
                if h: hashes.add(h)

            # Process names
            proc = data.get("process", {})
            if isinstance(proc, dict):
                pname = proc.get("name", "")
                if pname: processes.add(pname)

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "ip_iocs":      sorted(ips)[:50],
        "domain_iocs":  sorted(domains)[:50],
        "hash_iocs":    sorted(hashes)[:50],
        "process_iocs": sorted(processes)[:50],
        "total_iocs":   len(ips) + len(domains) + len(hashes) + len(processes),
    }


def severity_distribution() -> dict:
    """Return event counts grouped by severity for chart rendering."""
    events = _get_events_snapshot()
    dist = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    by_source = defaultdict(lambda: {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0})

    for ev in events:
        score  = ev.get("risk", {}).get("score", 0)
        source = ev.get("source", "unknown").upper()
        if score >= 80:   sev = "CRITICAL"
        elif score >= 60: sev = "HIGH"
        elif score >= 40: sev = "MEDIUM"
        elif score >= 20: sev = "LOW"
        else:             sev = "INFO"
        dist[sev] += 1
        by_source[source][sev] += 1

    return {
        "total":      sum(dist.values()),
        "overall":    dist,
        "by_source":  dict(by_source),
    }


def top_source_ips(limit: int = 10) -> list:
    events = _get_events_snapshot()
    counts = Counter()
    for ev in events:
        ip = ev.get("risk", {}).get("src_ip", "")
        if ip:
            counts[ip] += 1
    return [{"ip": ip, "count": c, "rank": i + 1}
            for i, (ip, c) in enumerate(counts.most_common(limit))]


def top_targeted_assets(limit: int = 10) -> list:
    events = _get_events_snapshot()
    counts = Counter()
    for ev in events:
        asset = ev.get("risk", {}).get("dest_ip", "")
        if asset:
            counts[asset] += 1
    return [{"asset": a, "count": c, "rank": i + 1}
            for i, (a, c) in enumerate(counts.most_common(limit))]


def mitre_heatmap() -> list:
    """Return technique hit counts for MITRE matrix heatmap."""
    events = _get_events_snapshot()
    counts = Counter()
    for ev in events:
        tech = ev.get("mitre", {}).get("technique_id", "")
        tactic = ev.get("mitre", {}).get("tactic_name", "")
        if tech:
            counts[(tech, tactic)] += 1
    return [
        {"technique_id": t, "tactic": tac, "count": c}
        for (t, tac), c in counts.most_common(30)
    ]
