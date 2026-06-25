# systeminfo.py
import platform
import socket
import uuid
import psutil
import requests
from datetime import datetime
from logger import log
from config import SERVER_URL


# ─── Collect Full System Snapshot ─────────────────────
def collect_system_info(session: dict) -> dict:
    """Full system snapshot — sent when server requests it."""
    try:
        hostname = socket.gethostname()
        ip       = socket.gethostbyname(hostname)
        mac      = ':'.join([
            '{:02x}'.format((uuid.getnode() >> i) & 0xff)
            for i in range(0, 48, 8)
        ][::-1])

        mem  = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        cpu  = psutil.cpu_percent(interval=1)

        return {
            "client_id":    session["client_id"],
            "hostname":     hostname,
            "username":     session["username"],
            "ip":           ip,
            "mac":          mac,
            "os":           platform.system(),
            "os_version":   platform.version(),
            "architecture": platform.machine(),
            "cpu_name":     platform.processor(),
            "cpu_percent":  cpu,
            "ram_total_gb": round(mem.total    / (1024**3), 2),
            "ram_used_gb":  round(mem.used     / (1024**3), 2),
            "ram_percent":  mem.percent,
            "disk_total_gb":round(disk.total   / (1024**3), 2),
            "disk_used_gb": round(disk.used    / (1024**3), 2),
            "disk_percent": disk.percent,
            "boot_time":    datetime.fromtimestamp(psutil.boot_time()).isoformat(),
            "current_time": datetime.utcnow().isoformat(),
            "timezone":     str(datetime.now().astimezone().tzname()),
            "python":       platform.python_version(),
        }

    except Exception as e:
        log(f"Failed to collect system info: {e}", "ERROR")
        raise


# ─── Send to Server ───────────────────────────────────
def send_system_info(session: dict):
    """Push system snapshot to /api/system-info."""
    try:
        info = collect_system_info(session)
        requests.post(
            f"{SERVER_URL}/api/system-info",
            json=info,
            timeout=10
        )
        log("System info sent ✓")

    except requests.ConnectionError:
        log("Server unreachable — system info not sent", "WARNING")
    except Exception as e:
        log(f"Failed to send system info: {e}", "ERROR")