# logger.py
import logging
import threading
import requests
from logging.handlers import RotatingFileHandler
from pathlib import Path
from config import LOG_DIR, LOG_LEVEL, LOG_TO_SERVER, SERVER_URL, APP_NAME

# ─── Local Rotating Logger ────────────────────────────
def get_logger(name: str = APP_NAME) -> logging.Logger:
    logger = logging.getLogger(name)
    logger.setLevel(getattr(logging, LOG_LEVEL))

    # Avoid duplicate handlers on re-import
    if logger.handlers:
        return logger

    # Console
    console = logging.StreamHandler()
    console.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))

    # File — 5MB per file, keep 3 backups
    log_file = LOG_DIR / f"{name}.log"
    file_handler = logging.FileHandler(log_file, encoding='utf-8')
    file_handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))

    logger.addHandler(console)
    logger.addHandler(file_handler)
    return logger


# ─── Server Log Sync (non-blocking) ───────────────────
def sync_log_to_server(message: str, level: str = "INFO"):
    if not LOG_TO_SERVER:
        return

    def _send():
        try:
            requests.post(
                f"{SERVER_URL}/api/logs",
                json={"message": message, "level": level},
                timeout=3
            )
        except Exception:
            pass  # Never crash because of logging

    threading.Thread(target=_send, daemon=True).start()


# ─── Unified log call ─────────────────────────────────
logger = get_logger()

def log(message: str, level: str = "INFO"):
    getattr(logger, level.lower(), logger.info)(message)
    sync_log_to_server(message, level)