# pipeline/demo_generator.py
"""
REMOVED — Synthetic demo event generation has been permanently disabled.

This module previously generated fake Suricata/Wazuh events when no real
sensor data was available. It has been removed so the dashboard displays
ONLY real telemetry from live pipeline components:

    Suricata → Elasticsearch → collector.py → compute.py → dashboard
    Wazuh    → Elasticsearch → collector.py → compute.py → dashboard

When no real telemetry is present, the dashboard shows:
    NO LIVE TELEMETRY AVAILABLE

Do NOT call generate_demo_event() — it raises RuntimeError.
"""


def generate_demo_event() -> dict:
    raise RuntimeError(
        "generate_demo_event() has been permanently removed. "
        "The dashboard only displays real telemetry from "
        "Suricata / Wazuh / Elasticsearch pipeline components."
    )
