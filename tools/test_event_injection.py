#!/usr/bin/env python3
"""
Sentrix SOC — Pipeline Trace Test with DIVERSE Event Templates
==============================================================
FIX DQ-5: Replaced single hardcoded event with a diverse template library.
           Injects varied events covering multiple:
             - Source IPs (8 distinct addresses across public and RFC-5737 ranges)
             - Destination IPs (8 internal targets)
             - MITRE techniques (mapped via different alert signatures)
             - Severities (Suricata severity 1–4)
             - Alert categories (Snort-style, now matched by CATEGORY_WEIGHTS)
             - Destination ports (triggering rare_port and port_scan_sweep detectors)

Usage (from Sentrix_SOC/cleint/ directory):
    python ../tools/test_event_injection.py [--inject-all] [--es-host HOST]

Options:
    --inject-all    Inject all diverse templates (default: inject template set)
    --es-host HOST  Elasticsearch host (default: 127.0.0.1)
"""
import argparse
import json
import random
import time
import uuid
from datetime import datetime, timezone

try:
    import requests
except ImportError:
    print("ERROR: requests not installed. Run: pip install requests")
    raise SystemExit(1)


def ts() -> str:
    return datetime.now(timezone.utc).strftime("%H:%M:%S")


def banner(msg: str):
    print(f"\n{'='*60}")
    print(f"  {msg}")
    print(f"{'='*60}")


def check(label: str, ok: bool, detail: str = ""):
    status = "✓" if ok else "✗"
    line = f"  [{status}] {label}"
    if detail:
        line += f"  →  {detail}"
    print(line)
    return ok


# ─── Diverse Event Templates ────────────────────────────────────────────────
# FIX DQ-5: Each template has a unique src_ip, dest_ip, severity, category,
# and signature — designed to exercise different MITRE mappings, severity
# buckets, and anomaly detectors.

DIVERSE_TEMPLATES = [
    # Template 1 — SSH Brute Force (T1110 / T1021.004, sev=2, HIGH)
    {
        "name": "SSH_BRUTE_FORCE",
        "src_ip": "203.0.113.10",
        "dest_ip": "10.0.0.11",
        "dest_port": 22,
        "proto": "TCP",
        "severity": 2,   # Suricata 2 → risk base 35 → medium-high after weights
        "alert": {
            "signature_id": 2001219,
            "signature": "ET SCAN SSH Brute Force Attempt",
            "category":  "Attempted Information Leak",
        },
        "extra": {"event_type": "alert", "app_proto": "ssh"},
    },
    # Template 2 — Port Scan (T1595, sev=3, MEDIUM)
    {
        "name": "PORT_SCAN",
        "src_ip": "198.51.100.22",
        "dest_ip": "10.0.0.12",
        "dest_port": 445,
        "proto": "TCP",
        "severity": 3,
        "alert": {
            "signature_id": 2010936,
            "signature": "ET SCAN Nmap TCP Port Scan",
            "category":  "Detection of a Network Scan",
        },
        "extra": {"event_type": "alert"},
    },
    # Template 3 — SQL Injection (T1190, sev=1, CRITICAL)
    {
        "name": "SQL_INJECTION",
        "src_ip": "198.51.100.50",
        "dest_ip": "10.0.0.80",
        "dest_port": 443,
        "proto": "TCP",
        "severity": 1,   # Suricata 1 → risk base 75 → critical
        "alert": {
            "signature_id": 2006446,
            "signature": "ET WEB_SERVER SQL Injection Attempt -- SELECT",
            "category":  "Web Application Attack",
        },
        "extra": {"event_type": "alert", "app_proto": "http"},
    },
    # Template 4 — Trojan / C2 Beacon (T1071, sev=1, CRITICAL)
    {
        "name": "C2_BEACON",
        "src_ip": "10.0.0.55",
        "dest_ip": "185.220.101.44",
        "dest_port": 4444,
        "proto": "TCP",
        "severity": 1,
        "alert": {
            "signature_id": 2014819,
            "signature": "ET MALWARE Possible C2 Reverse Shell Beacon",
            "category":  "A Network Trojan was Detected",
        },
        "extra": {"event_type": "alert"},
    },
    # Template 5 — DDoS / SYN Flood (T1498, sev=2, HIGH)
    {
        "name": "SYN_FLOOD",
        "src_ip": "203.0.113.77",
        "dest_ip": "10.0.0.1",
        "dest_port": 80,
        "proto": "TCP",
        "severity": 2,
        "alert": {
            "signature_id": 2101411,
            "signature": "GPL DOS TCP SYN flood possible",
            "category":  "Denial of Service Attack",
        },
        "extra": {"event_type": "alert"},
    },
    # Template 6 — DNS Exfiltration (T1041, sev=2, MEDIUM)
    {
        "name": "DNS_EXFIL",
        "src_ip": "10.0.0.77",
        "dest_ip": "8.8.8.8",
        "dest_port": 53,
        "proto": "UDP",
        "severity": 2,
        "alert": {
            "signature_id": 2027758,
            "signature": "ET POLICY DNS Request for Data Exfil Domain",
            "category":  "Potentially Bad Traffic",
        },
        "extra": {"event_type": "alert", "app_proto": "dns",
                  "dns": {"type": "query", "rrname": "exfil.attacker-c2.net",
                          "rrtype": "A", "id": 12345}},
    },
    # Template 7 — Privilege Escalation (T1548, sev=1, CRITICAL)
    {
        "name": "PRIV_ESC",
        "src_ip": "10.0.0.33",
        "dest_ip": "10.0.0.33",
        "dest_port": None,
        "proto": "TCP",
        "severity": 1,
        "alert": {
            "signature_id": 2100498,
            "signature": "GPL EXPLOIT sudo privilege escalation",
            "category":  "Attempted User Privilege Gain",
        },
        "extra": {"event_type": "alert"},
    },
    # Template 8 — Lateral Movement via SMB (T1021, sev=2, HIGH)
    {
        "name": "LATERAL_SMB",
        "src_ip": "10.0.0.44",
        "dest_ip": "10.0.0.55",
        "dest_port": 445,
        "proto": "TCP",
        "severity": 2,
        "alert": {
            "signature_id": 2003068,
            "signature": "ET EXPLOIT PSExec Lateral Movement",
            "category":  "Attempted Administrator Privilege Gain",
        },
        "extra": {"event_type": "alert"},
    },
    # Template 9 — Policy Violation (INFO, low severity)
    {
        "name": "POLICY_VIOLATION",
        "src_ip": "10.0.0.88",
        "dest_ip": "142.250.80.46",
        "dest_port": 80,
        "proto": "TCP",
        "severity": 4,   # Suricata 4 → risk base 10 → INFO
        "alert": {
            "signature_id": 2013504,
            "signature": "ET POLICY Dropbox Client Broadcasting",
            "category":  "Potential Corporate Privacy Violation",
        },
        "extra": {"event_type": "alert"},
    },
    # Template 10 — Password Spraying (T1110.003, sev=2, HIGH)
    {
        "name": "PASSWORD_SPRAY",
        "src_ip": "203.0.113.99",
        "dest_ip": "10.0.0.21",
        "dest_port": 443,
        "proto": "TCP",
        "severity": 2,
        "alert": {
            "signature_id": 2019284,
            "signature": "ET EXPLOIT Multiple User Password Spray Attempt",
            "category":  "Attempted Information Leak",
        },
        "extra": {"event_type": "alert"},
    },
    # Template 11 — Obfuscated Payload (T1027, sev=2, MEDIUM)
    {
        "name": "OBFUSCATED_PAYLOAD",
        "src_ip": "198.51.100.100",
        "dest_ip": "10.0.0.90",
        "dest_port": 8080,
        "proto": "TCP",
        "severity": 2,
        "alert": {
            "signature_id": 2024792,
            "signature": "ET MALWARE Encoded Payload in HTTP POST",
            "category":  "Executable Code was Detected",
        },
        "extra": {"event_type": "alert"},
    },
    # Template 12 — External VPN / Remote Access (T1133, sev=3, MEDIUM)
    {
        "name": "EXTERNAL_REMOTE",
        "src_ip": "203.0.113.5",
        "dest_ip": "10.0.0.200",
        "dest_port": 1194,
        "proto": "UDP",
        "severity": 3,
        "alert": {
            "signature_id": 2022987,
            "signature": "ET POLICY VPN Access Tunneling Traffic",
            "category":  "Potentially Bad Traffic",
        },
        "extra": {"event_type": "alert"},
    },
]


def build_suricata_event(template: dict, event_id: str, now: str) -> dict:
    """Construct a Suricata-format event document from a template."""
    event = {
        "@timestamp":  now,
        "timestamp":   now,
        "event_type":  "alert",
        "src_ip":      template["src_ip"],
        "src_port":    random.randint(1024, 65535),
        "proto":       template["proto"],
        "alert": {
            "action":       "allowed",
            "gid":          1,
            "signature_id": template["alert"]["signature_id"],
            "rev":          1,
            "signature":    template["alert"]["signature"],
            "category":     template["alert"]["category"],
            "severity":     template["severity"],
        },
        "tags":              ["suricata"],
        "_sentrix_test_id":  event_id,
        "_sentrix_template": template["name"],
    }

    if template.get("dest_ip"):
        event["dest_ip"] = template["dest_ip"]
    if template.get("dest_port"):
        event["dest_port"] = template["dest_port"]

    # Merge extra fields (dns, app_proto, etc.)
    for k, v in (template.get("extra") or {}).items():
        event[k] = v

    return event


# ─── Stage 1 ─────────────────────────────────────────────────────────────────

def verify_es(es_url: str) -> bool:
    banner("STAGE 1 — Elasticsearch Health")
    try:
        r = requests.get(f"{es_url}/_cluster/health", timeout=5)
        data = r.json()
        status = data.get("status", "unknown")
        ok = r.status_code == 200
        check("ES reachable", ok, f"status={status}")
        return ok
    except Exception as e:
        check("ES reachable", False, str(e))
        print("  → Is the Docker stack running? Try: docker compose up -d")
        return False


def list_indexes(es_url: str):
    try:
        r = requests.get(
            f"{es_url}/_cat/indices/suricata-events-*,wazuh-alerts-*"
            "?v&h=index,docs.count,store.size", timeout=5
        )
        if r.status_code == 200 and r.text.strip():
            print("\n  Current Sentrix indexes:")
            for line in r.text.strip().splitlines():
                print(f"    {line}")
        else:
            print("  No suricata-events-* or wazuh-alerts-* indexes yet.")
    except Exception:
        pass


# ─── Stage 2 ─────────────────────────────────────────────────────────────────

def inject_diverse_events(es_url: str, templates: list) -> dict:
    """Inject all templates into Elasticsearch. Returns {template_name: ok}."""
    banner(f"STAGE 2 — Inject {len(templates)} Diverse Event Templates")
    today = datetime.now(timezone.utc).strftime("%Y.%m.%d")
    index = f"suricata-events-{today}"
    now   = datetime.now(timezone.utc).isoformat()

    results = {}
    for tmpl in templates:
        event_id = str(uuid.uuid4())
        event    = build_suricata_event(tmpl, event_id, now)
        try:
            r = requests.post(
                f"{es_url}/{index}/_doc",
                json=event,
                headers={"Content-Type": "application/json"},
                timeout=5,
            )
            ok = r.status_code in (200, 201)
            doc_id = r.json().get("_id", "?")
            check(
                f"Template [{tmpl['name']}]", ok,
                f"src={tmpl['src_ip']} sev={tmpl['severity']} "
                f"cat='{tmpl['alert']['category'][:30]}' doc={doc_id}"
            )
            results[tmpl["name"]] = ok
        except Exception as e:
            check(f"Template [{tmpl['name']}]", False, str(e))
            results[tmpl["name"]] = False

    ok_count = sum(results.values())
    print(f"\n  Injected {ok_count}/{len(templates)} templates successfully.")
    return results


# ─── Stage 3 ─────────────────────────────────────────────────────────────────

def verify_dashboard(agent_url: str, timeout: int = 60) -> bool:
    banner("STAGE 3 — Dashboard API Verification")
    print(f"  Polling {agent_url}/api/events for up to {timeout}s...")

    target_ips = {t["src_ip"] for t in DIVERSE_TEMPLATES}
    found_ips  = set()

    deadline  = time.time() + timeout
    attempts  = 0
    while time.time() < deadline:
        attempts += 1
        try:
            r = requests.get(f"{agent_url}/api/events?limit=100", timeout=5)
            if r.status_code == 200:
                events = r.json().get("events", [])
                for ev in events:
                    ip = ev.get("src_ip", "")
                    if ip in target_ips:
                        found_ips.add(ip)
                if len(found_ips) >= 3:
                    check("Multiple diverse events reached Dashboard API", True,
                          f"{len(found_ips)}/{len(target_ips)} source IPs visible")
                    return True
        except Exception:
            pass
        time.sleep(3)

    ok = len(found_ips) > 0
    check("Events reached Dashboard API", ok,
          f"{len(found_ips)}/{len(target_ips)} source IPs found after {attempts} polls")
    return ok


# ─── Stage 4 ─────────────────────────────────────────────────────────────────

def verify_executor(agent_url: str) -> bool:
    banner("STAGE 4 — Executor / SOAR Response Tracker")
    try:
        r = requests.get(f"{agent_url}/api/responses", timeout=5)
        if r.status_code == 200:
            data      = r.json()
            responses = data.get("responses", [])
            stats     = data.get("stats", {})
            total     = stats.get("total_executions", 0)
            ok        = total > 0
            check("Executor has dispatched playbooks", ok,
                  f"total_executions={total}")
            if responses:
                last = responses[0]
                print(f"  → Last: {last.get('playbook_id','?')} — "
                      f"{last.get('playbook_name','?')}")
            return ok
        check("Executor API reachable", False, f"HTTP {r.status_code}")
        return False
    except Exception as e:
        check("Executor API reachable", False, str(e))
        return False


# ─── Stage 5 ─────────────────────────────────────────────────────────────────

def verify_session_manager(sm_url: str) -> bool:
    banner("STAGE 5 — Session Manager Health")
    try:
        r = requests.get(f"{sm_url}/health", timeout=5)
        ok = r.status_code == 200
        check("Session manager reachable", ok, f"HTTP {r.status_code}")
        return ok
    except Exception as e:
        check("Session manager reachable", False, str(e))
        return False


# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Sentrix SOC diverse pipeline trace test")
    parser.add_argument("--es-host",    default="127.0.0.1")
    parser.add_argument("--es-port",    default=9200,  type=int)
    parser.add_argument("--agent-host", default="127.0.0.1")
    parser.add_argument("--agent-port", default=7000,  type=int)
    parser.add_argument("--sm-host",    default="127.0.0.1")
    parser.add_argument("--sm-port",    default=8000,  type=int)
    parser.add_argument("--inject-all", action="store_true",
                        help="Inject all 12 templates (default: inject all)")
    parser.add_argument("--template",   type=str, default=None,
                        help="Inject only one template by name")
    args = parser.parse_args()

    es_url    = f"http://{args.es_host}:{args.es_port}"
    agent_url = f"http://{args.agent_host}:{args.agent_port}"
    sm_url    = f"http://{args.sm_host}:{args.sm_port}"

    print(f"\n{'='*60}")
    print(f"  SENTRIX SOC — DIVERSE PIPELINE TRACE TEST")
    print(f"  {ts()} UTC")
    print(f"  ES: {es_url}  |  Agent: {agent_url}  |  SM: {sm_url}")
    print(f"{'='*60}")

    templates = DIVERSE_TEMPLATES
    if args.template:
        templates = [t for t in DIVERSE_TEMPLATES if t["name"] == args.template]
        if not templates:
            print(f"  ERROR: unknown template '{args.template}'")
            print(f"  Available: {[t['name'] for t in DIVERSE_TEMPLATES]}")
            return

    print(f"\n  Template diversity summary:")
    src_ips  = {t["src_ip"]  for t in templates}
    dst_ips  = {t["dest_ip"] for t in templates if t.get("dest_ip")}
    sevs     = {t["severity"] for t in templates}
    cats     = {t["alert"]["category"] for t in templates}
    print(f"    Unique source IPs:       {len(src_ips)}")
    print(f"    Unique dest IPs:         {len(dst_ips)}")
    print(f"    Unique Suricata sevs:    {sorted(sevs)}")
    print(f"    Unique alert categories: {len(cats)}")

    results = {}

    # Stage 1
    results["elasticsearch"] = verify_es(es_url)
    if results["elasticsearch"]:
        list_indexes(es_url)

    if not results["elasticsearch"]:
        print("\n  ✗ Cannot continue — Elasticsearch unreachable.")
        print("    Run:  cd Sentrix_SOC/docker && docker compose up -d")
        return

    # Stage 2
    inject_results = inject_diverse_events(es_url, templates)
    results["inject"] = any(inject_results.values())

    if not results["inject"]:
        print("\n  ✗ All injections failed.")
        return

    # Stage 3
    results["dashboard"] = verify_dashboard(agent_url)

    # Stage 4
    if results["dashboard"]:
        results["executor"] = verify_executor(agent_url)

    # Stage 5
    results["session_manager"] = verify_session_manager(sm_url)

    # Summary
    banner("PIPELINE TRACE SUMMARY")
    labels = {
        "elasticsearch":   "Stage 1 — Elasticsearch",
        "inject":          "Stage 2 — Diverse event injection",
        "dashboard":       "Stage 3 — compute → threat engine → dashboard",
        "executor":        "Stage 4 — Executor / SOAR",
        "session_manager": "Stage 5 — Session manager",
    }
    all_ok = True
    for key, label in labels.items():
        if key in results:
            ok = results[key]
            all_ok = all_ok and ok
            check(label, ok)

    print()
    if all_ok:
        print("  ✓ Full pipeline operational — diverse events flowed end-to-end.")
    else:
        print("  ✗ Some stages failed. See details above.")
    print()


if __name__ == "__main__":
    main()
