# config.py
import os
import platform
from pathlib import Path

# ─── Server ───────────────────────────────────────────
# Set SENTRIX_SERVER_URL in the environment to point at the session-manager.
# Defaults to localhost so the agent and session-manager can run on the same machine.
SERVER_URL = os.getenv("SENTRIX_SERVER_URL", "http://127.0.0.1:8000")

# ─── App Identity ─────────────────────────────────────
APP_NAME = "Sentrix"

# ─── Timing (seconds) ─────────────────────────────────
TIMING = {
    "heartbeat": 2,
    "retry": 7,
    "command_poll": 5,
    "log_sync": 1,
}

# ─── Cross-Platform Storage Path ──────────────────────
def get_app_data_dir() -> Path:
    system = platform.system()
    if system == "Windows":
        base = Path(os.environ.get("APPDATA", Path.home()))
    elif system == "Darwin":
        base = Path.home() / "Library" / "Application Support"
    else:  # Linux and everything else
        base = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config"))

    app_dir = base / APP_NAME
    app_dir.mkdir(parents=True, exist_ok=True)
    return app_dir

APP_DATA_DIR  = get_app_data_dir()
SESSION_FILE  = APP_DATA_DIR / "session.json"
LOG_DIR       = APP_DATA_DIR / "logs"
LOG_DIR.mkdir(parents=True, exist_ok=True)

# ─── Logging ──────────────────────────────────────────
LOG_LEVEL     = "INFO"
LOG_TO_SERVER = True
