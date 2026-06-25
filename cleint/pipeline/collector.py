# pipeline/collector.py
import requests
from logger import log


def _wazuh_headers(session: dict) -> dict:
    wazuh = (session.get("wazuh") or {})
    token = wazuh.get("token")
    if token:
        return {"Authorization": f"Bearer {token}"}
    return {}


def collect(session: dict):
    services = session.get("services", {})
    
    if not services:
        log("No services in session — skipping collection", "WARNING")
        return

    client_id = session["client_id"]

    # ─── Wazuh ────────────────────────────────────────
    try:
        wazuh_service = services.get("wazuh", {}) or {}
        url = wazuh_service.get("url")
        headers = _wazuh_headers(session)
        if not url:
            raise ValueError("Wazuh service URL missing")

        resp = requests.post(
            url,
            headers=headers,
            json={
                "query": {
                    "bool": {
                        "must_not": [
                            {"match": {"event_type": "stats"}},
                            {"match": {"event_type": "flow"}}
                        ]}
                    },
                "size": 50,
                "sort": [{"@timestamp": {"order": "desc"}}]
            },
            timeout=5
        )
        hits = resp.json().get("hits", {}).get("hits", [])
        for hit in hits:
            yield {"source": "wazuh", "data": hit["_source"]}

    except Exception as e:
        log(f"Wazuh collection failed: {e}", "WARNING")

    # ─── Suricata ─────────────────────────────────────
    try:
        url  = services["suricata"]["url"]
        resp = requests.post(
            url,
            json={
                "query": {
                    "match_all": {}
                },
                "size": 50,
                "sort": [{"@timestamp": {"order": "desc"}}]
            },
            timeout=5
        )
        hits = resp.json().get("hits", {}).get("hits", [])
        for hit in hits:
            yield {"source": "suricata", "data": hit["_source"]}

    except Exception as e:
        log(f"Suricata collection failed: {e}", "WARNING")