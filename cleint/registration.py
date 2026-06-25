# registration.py
import socket
import platform
import uuid
import psutil
import requests
from datetime import datetime
from config import SERVER_URL
from storage import save_session
from logger import log

# ─── Collect Machine Info ─────────────────────────────
def collect_machine_info() -> dict:
    """Gather all system identifiers for registration."""
    try:
        hostname = socket.gethostname()
        ip = socket.gethostbyname(hostname)
        mac = ':'.join([
            '{:02x}'.format((uuid.getnode() >> i) & 0xff)
            for i in range(0, 48, 8)
        ][::-1])

        return {
            "hostname":     hostname,
            "username":     platform.node(),
            "ip":           ip,
            "mac":          mac,
            "os":           platform.system(),
            "os_version":   platform.version(),
            "architecture": platform.machine(),
            "cpu":          platform.processor(),
            "ram_gb":       round(psutil.virtual_memory().total / (1024**3), 2),
            "boot_time":    datetime.fromtimestamp(psutil.boot_time()).isoformat(),
            "timezone":     str(datetime.now().astimezone().tzname()),
            "registered_at": datetime.utcnow().isoformat()
        }
    except Exception as e:
        log(f"Failed to collect machine info: {e}", "ERROR")
        raise


# ─── Register with Server ─────────────────────────────
def register() -> dict:
    """
    Send machine info to server.
    Server returns UUID — we never generate it ourselves.
    """
    log("Starting registration...")
    machine_info = collect_machine_info()

    try:
        resp = requests.post(
            f"{SERVER_URL}/api/register",
            json=machine_info,
            timeout=10
        )
        resp.raise_for_status()
        data = resp.json()

        client_id = data.get("client_id")
        if not client_id:
            raise ValueError("Server did not return a client_id")

        session = {
            "client_id":    client_id,
            **machine_info
        }

        save_session(session)
        log(f"Registration successful. client_id={client_id}")
        return session

    except requests.ConnectionError:
        log("Server unreachable during registration", "ERROR")
        raise
    except Exception as e:
        log(f"Registration failed: {e}", "ERROR")
        raise