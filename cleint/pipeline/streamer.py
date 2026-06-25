# pipeline/streamer.py
import time
import requests
from pipeline.collector import collect
from pipeline.compute   import process
from pipeline.writer    import write
from logger import log
from config import SERVER_URL
from pipeline.wazuh import ensure_wazuh_api_ready


def stream(session: dict):
    """
    Main event streaming loop.

    Polls Elasticsearch via collector.collect() every 10 s for real telemetry
    from configured Wazuh / Suricata sensors.

    If no sensor services are configured, or no events arrive, the loop sleeps
    and retries without generating any synthetic data. The dashboard will show
    NO LIVE TELEMETRY AVAILABLE until real events flow from the pipeline.
    """
    while True:
        try:
            # ── Refresh service session if missing ───────────────────────
            if not session.get("services"):
                try:
                    resp = requests.post(
                        f"{SERVER_URL}/session/services",
                        json={"client_id": session["client_id"]},
                        timeout=5
                    )
                    session["services"] = resp.json().get("services", {})
                    if session["services"]:
                        log("Service session refreshed in streamer")
                except Exception as e:
                    log(f"Service refresh failed: {e}", "WARNING")

            ensure_wazuh_api_ready(session)

            # ── Live collection ──────────────────────────────────────────
            events_collected = 0
            for event in collect(session):
                write(event)
                process(event)
                events_collected += 1

            if events_collected == 0:
                if not session.get("services"):
                    log(
                        "No sensor services configured — "
                        "dashboard shows NO LIVE TELEMETRY AVAILABLE",
                        "WARNING"
                    )
                else:
                    log("No events returned from sensors this cycle", "DEBUG")

            time.sleep(10)

        except Exception as e:
            log(f"Streamer error: {e}", "WARNING")
            time.sleep(10)
