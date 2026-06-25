import requests
from logger import log
from storage import save_session


def ensure_wazuh_api_ready(session: dict) -> dict:
    """Authenticate once to the Wazuh API and persist the token for later runs."""
    services = session.get("services", {}) or {}
    wazuh_service = services.get("wazuh", {}) or {}

    if not wazuh_service:
        return {}

    api_url = wazuh_service.get("api_url")
    api_user = wazuh_service.get("api_user")
    api_password = wazuh_service.get("api_password")

    if not all([api_url, api_user, api_password]):
        return {}

    cached = session.get("wazuh", {}) or {}
    token = cached.get("token") or wazuh_service.get("token")
    if token:
        session.setdefault("wazuh", {}).update(
            {
                "token": token,
                "api_url": api_url,
                "api_user": api_user,
                "api_password": api_password,
            }
        )
        session.setdefault("services", {}).setdefault("wazuh", {}).update({"token": token})
        save_session(session)
        return session["wazuh"]

    auth_url = f"{api_url.rstrip('/')}/security/user/authenticate"
    try:
        resp = requests.post(
            auth_url,
            json={"username": api_user, "password": api_password},
            timeout=10,
            verify=False,
        )
        resp.raise_for_status()
        payload = resp.json() if resp.content else {}
        token = payload.get("data", {}).get("token") or payload.get("token")

        if token:
            session.setdefault("wazuh", {}).update(
                {
                    "token": token,
                    "api_url": api_url,
                    "api_user": api_user,
                    "api_password": api_password,
                }
            )
            session.setdefault("services", {}).setdefault("wazuh", {}).update({"token": token})
            save_session(session)
            log("Wazuh API token saved for future runs")
            return session["wazuh"]

        log("Wazuh API authenticate call returned no token", "WARNING")
    except Exception as exc:
        log(f"Wazuh API setup failed: {exc}", "WARNING")

    return {}
