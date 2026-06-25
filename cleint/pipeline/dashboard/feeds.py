# pipeline/dashboard/feeds.py
import requests

FEEDS = {}

def register_feed(name: str):
    """Decorator — naya feed add karna = bas yeh lagao"""
    def decorator(fn):
        FEEDS[name] = fn
        return fn
    return decorator

@register_feed("suricata")
def suricata_feed(session: dict) -> list:
    try:
        url = session.get("services", {}).get("suricata", {}).get("url", "")
        if not url:
            return []
        resp = requests.post(
            url,
            json={
                "query": {
                    "bool": {
                        "must_not": [
                            {"match": {"event_type": "stats"}},
                            {"match": {"event_type": "flow"}}
                        ]
                    }
                },
                "size": 20,
                "sort": [{"@timestamp": {"order": "desc"}}]
            },
            timeout=5
        )
        hits = resp.json().get("hits", {}).get("hits", [])
        return [hit["_source"] for hit in hits]
    except Exception as e:
        return [{"error": str(e)}]


@register_feed("wazuh")
def wazuh_feed(session: dict) -> list:
    try:
        url = session.get("services", {}).get("wazuh", {}).get("url", "")
        if not url:
            return []
        resp = requests.post(
            url,
            json={
                "query": {
                    "match": {
                        "agent.id": session.get("client_id", "")
                    }
                },
                "size": 20,
                "sort": [{"@timestamp": {"order": "desc"}}]
            },
            timeout=5
        )
        hits = resp.json().get("hits", {}).get("hits", [])
        return [hit["_source"] for hit in hits]
    except Exception as e:
        return [{"error": str(e)}]