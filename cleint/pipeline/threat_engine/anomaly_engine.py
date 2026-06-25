# threat_engine/anomaly_engine.py
"""
Behavioral Anomaly Detection Engine

FIX DQ-6: Audited every detector for Suricata compatibility.
           Detectors that require user/process fields are guarded — they are
           skipped automatically for Suricata events and remain active for Wazuh.
           Five new network-layer detectors added, all compatible with Suricata:
             - port_scan_sweep        (many unique ports from one IP)
             - beaconing              (regular-interval connections to one dest)
             - excessive_conn_rate    (connection rate spike — replaces blunt event_rate_burst)
             - rare_destination       (dest IP/port pair never seen before)
             - lateral_movement_net   (internal src → multiple internal dests)
"""
import math
import time
from collections import defaultdict, deque
from datetime import datetime, timezone
from threading import Lock
from typing import Optional

_lock = Lock()

# ─── Behavioral baselines ────────────────────────────────────────────────────
_ip_events:        dict = defaultdict(lambda: deque(maxlen=500))
_user_events:      dict = defaultdict(lambda: deque(maxlen=500))
_ip_countries:     dict = {}
_port_baseline:    dict = defaultdict(lambda: defaultdict(int))     # ip → port → count
_process_baseline: dict = defaultdict(lambda: defaultdict(int))     # host → proc → count
_auth_failures:    dict = defaultdict(lambda: deque(maxlen=200))

# ── Network-detector baselines (all Suricata-compatible) ─────────────────────
_ip_dest_ports:    dict = defaultdict(set)                          # ip → set of dest ports seen (1-min window tracking via deque)
_ip_port_history:  dict = defaultdict(lambda: deque(maxlen=500))    # ip → [(ts, port)]
_beacon_history:   dict = defaultdict(lambda: deque(maxlen=200))    # (src,dst) → [timestamps]
_conn_history:     dict = defaultdict(lambda: deque(maxlen=500))    # src_ip → [timestamps]
_dest_pair_seen:   dict = defaultdict(set)                          # src_ip → set of (dest_ip, dest_port)
_internal_lateral: dict = defaultdict(set)                          # src_ip → set of dest_ips (internal only)

# ─── Thresholds ──────────────────────────────────────────────────────────────
AUTH_FAIL_BURST_WINDOW  = 60
AUTH_FAIL_BURST_THRESH  = 5
RARE_PROC_THRESHOLD     = 3
RARE_PORT_THRESHOLD     = 3
EVENT_RATE_WINDOW       = 60
EVENT_RATE_THRESHOLD    = 10    # lowered from 30 — catches slow probes

PORT_SCAN_WINDOW        = 60    # seconds
PORT_SCAN_THRESHOLD     = 15    # unique dest ports in window = scan
BEACON_INTERVAL_WINDOW  = 300   # 5 minutes
BEACON_MIN_EVENTS       = 4     # minimum events to detect beaconing
BEACON_JITTER_TOLERANCE = 0.30  # 30% coefficient of variation = beaconing
CONN_RATE_WINDOW        = 30    # seconds
LATERAL_DEST_THRESHOLD  = 3     # distinct internal dests = lateral movement candidate

# Internal IP prefixes (RFC-1918)
_INTERNAL_PREFIXES = ("10.", "172.16.", "172.17.", "172.18.", "172.19.",
                      "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
                      "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
                      "172.30.", "172.31.", "192.168.")


def _is_internal(ip: Optional[str]) -> bool:
    if not ip:
        return False
    return any(ip.startswith(p) for p in _INTERNAL_PREFIXES)


# ─── Detector compatibility matrix ──────────────────────────────────────────
# SUPPORTED       = fires correctly for this source
# PARTIAL         = fires only if optional fields are present
# UNSUPPORTED     = source never provides required fields — detector is skipped

DETECTOR_COMPAT = {
    # detector_name             suricata       wazuh
    "auth_burst":              ("UNSUPPORTED", "SUPPORTED"),
    "event_rate_burst":        ("SUPPORTED",   "SUPPORTED"),
    "off_hours_auth":          ("UNSUPPORTED", "PARTIAL"),
    "rare_process":            ("UNSUPPORTED", "SUPPORTED"),
    "rare_port":               ("PARTIAL",     "UNSUPPORTED"),
    "behavior_shift":          ("UNSUPPORTED", "PARTIAL"),
    # ── new network detectors ──────────────────────────────────────────────
    "port_scan_sweep":         ("SUPPORTED",   "PARTIAL"),
    "beaconing":               ("SUPPORTED",   "PARTIAL"),
    "excessive_conn_rate":     ("SUPPORTED",   "PARTIAL"),
    "rare_destination":        ("SUPPORTED",   "PARTIAL"),
    "lateral_movement_net":    ("SUPPORTED",   "PARTIAL"),
}


def _extract_meta(event: dict) -> dict:
    """Pull common fields from event data."""
    data = event.get("data", {})
    if not isinstance(data, dict):
        return {}

    user = (data.get("user", {}).get("name") if isinstance(data.get("user"), dict) else
            data.get("syscheck", {}).get("uname_after") if isinstance(data.get("syscheck"), dict) else
            data.get("agent", {}).get("name") if isinstance(data.get("agent"), dict) else None)

    src_ip = (data.get("src_ip") or data.get("srcip") or
              (data.get("agent", {}).get("ip") if isinstance(data.get("agent"), dict) else None))

    hostname = (data.get("hostname") or
                (data.get("agent", {}).get("name") if isinstance(data.get("agent"), dict) else None))

    proc_name = (data.get("process", {}).get("name") if isinstance(data.get("process"), dict) else
                 data.get("win", {}).get("eventdata", {}).get("image", "").split("\\")[-1]
                 if isinstance(data.get("win"), dict) else None)

    dest_port  = data.get("dest_port") or data.get("dpt")
    dest_ip    = data.get("dest_ip") or data.get("destip") or data.get("dst_ip")
    event_type = (data.get("event_type") or
                  (data.get("rule", {}).get("description", "")
                   if isinstance(data.get("rule"), dict) else ""))
    proto      = str(data.get("proto", "")).upper()
    hour       = datetime.now(timezone.utc).hour

    return {
        "user":       user,
        "src_ip":     src_ip,
        "dest_ip":    dest_ip,
        "hostname":   hostname,
        "proc_name":  proc_name,
        "dest_port":  dest_port,
        "event_type": str(event_type),
        "proto":      proto,
        "hour":       hour,
    }


# ─── Legacy detectors (user/process context) ─────────────────────────────────
# Skipped automatically for Suricata events (no user/process fields).

def _check_auth_failure_burst(user: Optional[str], src_ip: Optional[str]) -> Optional[dict]:
    key = user or src_ip
    if not key:
        return None
    now = time.time()
    with _lock:
        q = _auth_failures[key]
        q.append(now)
        recent = [t for t in q if now - t < AUTH_FAIL_BURST_WINDOW]
    if len(recent) >= AUTH_FAIL_BURST_THRESH:
        return {
            "anomaly_type":  "auth_burst",
            "description":   f"Rapid authentication failures: {len(recent)} in {AUTH_FAIL_BURST_WINDOW}s",
            "anomaly_score": min(100, 40 + len(recent) * 3),
            "entity":        key,
        }
    return None


def _check_off_hours_auth(user: Optional[str], hour: int, event_type: str) -> Optional[dict]:
    if user and ("login" in event_type.lower() or "authentication" in event_type.lower()
                 or "logon" in event_type.lower()):
        if hour >= 22 or hour <= 5:
            return {
                "anomaly_type":  "off_hours_auth",
                "description":   f"Authentication by '{user}' at off-hours (UTC {hour:02d}:xx)",
                "anomaly_score": 45,
                "entity":        user or "unknown",
            }
    return None


def _check_rare_process(hostname: Optional[str], proc_name: Optional[str]) -> Optional[dict]:
    if not hostname or not proc_name:
        return None
    with _lock:
        count = _process_baseline[hostname][proc_name]
        _process_baseline[hostname][proc_name] += 1
    if 0 < count <= RARE_PROC_THRESHOLD:
        return {
            "anomaly_type":  "rare_process",
            "description":   f"Rare process '{proc_name}' on {hostname} (seen {count} times before)",
            "anomaly_score": 50,
            "entity":        f"{hostname}:{proc_name}",
        }
    return None


def _check_rare_port(src_ip: Optional[str], dest_port) -> Optional[dict]:
    if not src_ip or not dest_port:
        return None
    try:
        port = int(dest_port)
    except (TypeError, ValueError):
        return None
    if port in (80, 443, 22, 25, 53, 8080, 8443):
        return None
    with _lock:
        count = _port_baseline[src_ip][port]
        _port_baseline[src_ip][port] += 1
    if 0 < count <= RARE_PORT_THRESHOLD:
        return {
            "anomaly_type":  "rare_port",
            "description":   f"{src_ip} connecting to rare port {port} (seen {count} times)",
            "anomaly_score": 35,
            "entity":        f"{src_ip}:{port}",
        }
    return None


def _check_user_behavior_shift(user: Optional[str], hour: int) -> Optional[dict]:
    if not user:
        return None
    with _lock:
        q = _user_events[user]
        q.append((time.time(), hour, "login"))
        hours = [h for _, h, _ in q if len(q) > 10]
    if len(hours) < 10:
        return None
    mean_hour = sum(hours) / len(hours)
    variance  = sum((h - mean_hour) ** 2 for h in hours) / len(hours)
    std       = math.sqrt(variance)
    if std > 0 and abs(hour - mean_hour) > 2.5 * std:
        return {
            "anomaly_type":  "behavior_shift",
            "description":   f"User '{user}' acting at unusual hour {hour:02d}:xx (mean={mean_hour:.1f}, σ={std:.1f})",
            "anomaly_score": 55,
            "entity":        user,
        }
    return None


# ─── Network-layer detectors (Suricata-compatible) ───────────────────────────

def _check_event_rate_burst(src_ip: Optional[str]) -> Optional[dict]:
    """Detect abnormally high connection rate from a single IP (threshold lowered to 10/min)."""
    if not src_ip:
        return None
    now = time.time()
    with _lock:
        q = _conn_history[src_ip]
        q.append(now)
        recent = [t for t in q if now - t < EVENT_RATE_WINDOW]
    rate = len(recent)
    if rate >= EVENT_RATE_THRESHOLD:
        return {
            "anomaly_type":  "excessive_conn_rate",
            "description":   f"Abnormal connection rate from {src_ip}: {rate} events/{EVENT_RATE_WINDOW}s",
            "anomaly_score": min(100, 35 + rate * 2),
            "entity":        src_ip,
        }
    return None


def _check_port_scan_sweep(src_ip: Optional[str], dest_port) -> Optional[dict]:
    """
    Detect port-scan sweeps: many distinct destination ports from one source IP
    within a short time window.
    """
    if not src_ip or dest_port is None:
        return None
    try:
        port = int(dest_port)
    except (TypeError, ValueError):
        return None

    now = time.time()
    with _lock:
        q = _ip_port_history[src_ip]
        q.append((now, port))
        recent_ports = {p for t, p in q if now - t < PORT_SCAN_WINDOW}

    if len(recent_ports) >= PORT_SCAN_THRESHOLD:
        return {
            "anomaly_type":  "port_scan_sweep",
            "description":   (f"{src_ip} scanned {len(recent_ports)} unique ports "
                              f"in {PORT_SCAN_WINDOW}s"),
            "anomaly_score": min(100, 45 + len(recent_ports)),
            "entity":        src_ip,
        }
    return None


def _check_beaconing(src_ip: Optional[str], dest_ip: Optional[str]) -> Optional[dict]:
    """
    Detect beaconing: highly regular intervals between connections
    from the same source to the same destination.
    Uses coefficient of variation (std/mean) — low CV = suspiciously regular.
    """
    if not src_ip or not dest_ip:
        return None

    key = (src_ip, dest_ip)
    now = time.time()
    with _lock:
        q = _beacon_history[key]
        q.append(now)
        timestamps = [t for t in q if now - t < BEACON_INTERVAL_WINDOW]

    if len(timestamps) < BEACON_MIN_EVENTS:
        return None

    timestamps_sorted = sorted(timestamps)
    intervals = [timestamps_sorted[i+1] - timestamps_sorted[i]
                 for i in range(len(timestamps_sorted) - 1)]
    if not intervals:
        return None

    mean_iv = sum(intervals) / len(intervals)
    if mean_iv < 1:
        return None

    std_iv = math.sqrt(sum((x - mean_iv)**2 for x in intervals) / len(intervals))
    cv     = std_iv / mean_iv   # coefficient of variation

    if cv <= BEACON_JITTER_TOLERANCE:
        return {
            "anomaly_type":  "beaconing",
            "description":   (f"Beaconing detected: {src_ip} → {dest_ip}, "
                              f"{len(timestamps)} events, interval={mean_iv:.1f}s ±{std_iv:.1f}s (CV={cv:.2f})"),
            "anomaly_score": min(100, 60 + int((1 - cv) * 30)),
            "entity":        f"{src_ip}→{dest_ip}",
        }
    return None


def _check_rare_destination(src_ip: Optional[str], dest_ip: Optional[str],
                             dest_port) -> Optional[dict]:
    """
    Detect first-ever connections to a (dest_ip, dest_port) pair from a source IP.
    Flags truly novel destinations that have never been seen before.
    """
    if not src_ip or not dest_ip or dest_port is None:
        return None
    try:
        port = int(dest_port)
    except (TypeError, ValueError):
        return None

    pair = (dest_ip, port)
    with _lock:
        already_seen = pair in _dest_pair_seen[src_ip]
        _dest_pair_seen[src_ip].add(pair)

    if not already_seen:
        return {
            "anomaly_type":  "rare_destination",
            "description":   f"First-ever connection: {src_ip} → {dest_ip}:{port}",
            "anomaly_score": 30,
            "entity":        f"{src_ip}→{dest_ip}:{port}",
        }
    return None


def _check_lateral_movement_net(src_ip: Optional[str],
                                 dest_ip: Optional[str]) -> Optional[dict]:
    """
    Detect network-layer lateral movement: an internal source IP connecting
    to many distinct internal destination IPs within the session.
    """
    if not src_ip or not dest_ip:
        return None
    if not _is_internal(src_ip) or not _is_internal(dest_ip):
        return None
    if src_ip == dest_ip:
        return None

    with _lock:
        _internal_lateral[src_ip].add(dest_ip)
        distinct_dests = len(_internal_lateral[src_ip])

    if distinct_dests >= LATERAL_DEST_THRESHOLD:
        return {
            "anomaly_type":  "lateral_movement_net",
            "description":   (f"Internal lateral movement: {src_ip} has reached "
                              f"{distinct_dests} distinct internal hosts"),
            "anomaly_score": min(100, 55 + distinct_dests * 3),
            "entity":        src_ip,
        }
    return None


# ─── Main dispatcher ─────────────────────────────────────────────────────────

def analyze(event: dict) -> dict:
    """
    Run all applicable anomaly detectors against the event.

    User/process detectors are skipped for Suricata events because Suricata
    never provides user or process context fields.

    Network detectors run for all event sources.

    Returns:
        {
            "anomaly_detected":   bool,
            "anomalies":          list[dict],
            "max_anomaly_score":  int,
            "primary_anomaly":    str | None,
            "detectors_run":      list[str],
            "detectors_skipped":  list[str],
        }
    """
    meta     = _extract_meta(event)
    source   = event.get("source", "unknown").lower()
    detected = []
    run      = []
    skipped  = []

    is_suricata = (source == "suricata")

    is_auth_event = ("failed" in meta["event_type"].lower() or
                     "invalid" in meta["event_type"].lower() or
                     "authentication" in meta["event_type"].lower() or
                     "login" in meta["event_type"].lower())

    # ── auth_burst: Wazuh only ────────────────────────────────────────────
    if is_suricata:
        skipped.append("auth_burst")
    elif is_auth_event:
        run.append("auth_burst")
        r = _check_auth_failure_burst(meta["user"], meta["src_ip"])
        if r: detected.append(r)

    # ── excessive_conn_rate: all sources ─────────────────────────────────
    run.append("excessive_conn_rate")
    r = _check_event_rate_burst(meta["src_ip"])
    if r: detected.append(r)

    # ── off_hours_auth: Wazuh only ────────────────────────────────────────
    if is_suricata:
        skipped.append("off_hours_auth")
    else:
        run.append("off_hours_auth")
        r = _check_off_hours_auth(meta["user"], meta["hour"], meta["event_type"])
        if r: detected.append(r)

    # ── rare_process: Wazuh only ──────────────────────────────────────────
    if is_suricata:
        skipped.append("rare_process")
    else:
        run.append("rare_process")
        r = _check_rare_process(meta["hostname"], meta["proc_name"])
        if r: detected.append(r)

    # ── rare_port: both sources (Suricata has dest_port) ─────────────────
    run.append("rare_port")
    r = _check_rare_port(meta["src_ip"], meta["dest_port"])
    if r: detected.append(r)

    # ── behavior_shift: Wazuh only ────────────────────────────────────────
    if is_suricata:
        skipped.append("behavior_shift")
    else:
        run.append("behavior_shift")
        r = _check_user_behavior_shift(meta["user"], meta["hour"])
        if r: detected.append(r)

    # ── NEW: port_scan_sweep — all sources ────────────────────────────────
    run.append("port_scan_sweep")
    r = _check_port_scan_sweep(meta["src_ip"], meta["dest_port"])
    if r: detected.append(r)

    # ── NEW: beaconing — all sources ──────────────────────────────────────
    run.append("beaconing")
    r = _check_beaconing(meta["src_ip"], meta["dest_ip"])
    if r: detected.append(r)

    # ── NEW: rare_destination — all sources ───────────────────────────────
    run.append("rare_destination")
    r = _check_rare_destination(meta["src_ip"], meta["dest_ip"], meta["dest_port"])
    if r: detected.append(r)

    # ── NEW: lateral_movement_net — all sources ───────────────────────────
    run.append("lateral_movement_net")
    r = _check_lateral_movement_net(meta["src_ip"], meta["dest_ip"])
    if r: detected.append(r)

    max_score = max((a["anomaly_score"] for a in detected), default=0)
    primary   = (max(detected, key=lambda x: x["anomaly_score"])["anomaly_type"]
                 if detected else None)

    return {
        "anomaly_detected":  len(detected) > 0,
        "anomalies":         detected,
        "max_anomaly_score": max_score,
        "primary_anomaly":   primary,
        "detectors_run":     run,
        "detectors_skipped": skipped,
    }
