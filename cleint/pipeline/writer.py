# pipeline/writer.py
import json
import os
from datetime import datetime
from logger import log

from config import LOG_DIR

def _ensure_dir():
    os.makedirs(LOG_DIR, exist_ok=True)

def write(event: dict):
    """
    Saves event to local JSON log file.
    One file per day per source.
    """
    _ensure_dir()
    
    source    = event.get("source", "unknown")
    today     = datetime.utcnow().strftime("%Y-%m-%d")
    log_file  = f"{LOG_DIR}/{source}_{today}.json"
    
    entry = {
        "timestamp": datetime.utcnow().isoformat(),
        "source":    source,
        "data":      event.get("data")
    }
    
    with open(log_file, "a") as f:
        f.write(json.dumps(entry) + "\n")