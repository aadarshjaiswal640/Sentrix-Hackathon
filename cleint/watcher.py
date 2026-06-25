# watcher.py
"""
Tails the local Suricata container's eve.json (written via the bind
mount set up in container_runner.py) and pushes each event through
the full threat-engine pipeline (compute.py) so local Suricata events
receive the same enrichment as events collected from Elasticsearch.
"""
import json
import time
from config import LOG_DIR
from logger import log

SURICATA_EVE_PATH = LOG_DIR / "suricata" / "eve.json"


def watch_suricata():
    """Generator — yields each new Suricata event as it's written to eve.json."""
    log(f"Watching {SURICATA_EVE_PATH} ...")

    waited = 0
    while not SURICATA_EVE_PATH.exists():
        time.sleep(2)
        waited += 2
        if waited % 10 == 0:
            log(f"Still waiting for eve.json to appear... ({waited}s)", "WARNING")
        if waited > 120:
            log("eve.json never appeared — is the Suricata container running?", "ERROR")
            return

    with open(SURICATA_EVE_PATH, "r") as f:
        f.seek(0, 2)
        while True:
            line = f.readline()
            if not line:
                time.sleep(1)
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            yield event


def run_watcher_and_print():
    """
    Tail eve.json and push every non-stats event through the threat engine.
    Previously this only printed events. Now every event is also routed
    through compute.process() so it is enriched, published to the dashboard,
    and evaluated by the executor — matching the behaviour of events collected
    from Elasticsearch via collector.py.
    """
    from pipeline.compute import process as compute_process

    for event in watch_suricata():
        evt_type = event.get("event_type", "unknown")

        if evt_type in ("stats", "flow"):
            continue

        log(f"[SURICATA-WATCHER] [{evt_type}] event received")
        print(f"[SURICATA] [{evt_type}] {event}")

        wrapped = {"source": "suricata", "data": event}
        try:
            compute_process(wrapped)
        except Exception as e:
            log(f"[SURICATA-WATCHER] compute.process error: {e}", "WARNING")
