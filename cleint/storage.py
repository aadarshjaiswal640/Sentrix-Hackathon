# storage.py
import json
import hashlib
import requests
from pathlib import Path
from config import SESSION_FILE, SERVER_URL
from logger import log
from typing import Optional

# Fields added at runtime that must NOT be included in the verification hash.
# The server hashes only {client_id, **machine_info} — we must do the same.
_RUNTIME_FIELDS = {"wazuh", "services"}

# ─── Hashing ──────────────────────────────────────────
def _hash_data(data: dict) -> str:
    """SHA256 hash of the session data."""
    raw = json.dumps(data, sort_keys=True).encode()
    return hashlib.sha256(raw).hexdigest()


def _canonical_session(session: dict) -> dict:
    """
    Return only the fields the server will hash when verifying.
    Mirrors what session.py/_client_facing_view produces:
        {client_id, **machine_info}
    Runtime keys (wazuh, services) are excluded so they do not
    trigger false tamper-detection on restart.
    """
    return {k: v for k, v in session.items() if k not in _RUNTIME_FIELDS}


# ─── Write Session ────────────────────────────────────
def save_session(data: dict) -> None:
    """Save session locally. Hash is verified server-side."""
    try:
        SESSION_FILE.write_text(json.dumps(data, indent=2))
        log(f"Session saved -> {SESSION_FILE}")
    except Exception as e:
        log(f"Failed to save session: {e}", "ERROR")


# ─── Read Session ─────────────────────────────────────
def load_session() -> Optional[dict]:
    """Load session if exists."""
    try:
        if SESSION_FILE.exists():
            return json.loads(SESSION_FILE.read_text())
        return None
    except Exception as e:
        log(f"Failed to read session: {e}", "ERROR")
        return None


# ─── Verify Session with Server ───────────────────────
def verify_session(session: dict) -> str:
    """
    Send session hash to server for verification.
    Only canonical fields are hashed (excludes runtime keys like wazuh/services)
    to match exactly what the server hashes.
    Returns: 'valid' | 'tampered' | 'unknown' | 'unreachable'
    """
    try:
        canonical = _canonical_session(session)
        client_hash = _hash_data(canonical)
        resp = requests.post(
            f"{SERVER_URL}/api/verify-session",
            json={
                "client_id": session.get("client_id"),
                "hash": client_hash
            },
            timeout=5
        )
        result = resp.json().get("status", "unknown")
        log(f"Session verification: {result}")
        return result

    except requests.ConnectionError:
        log("Server unreachable during verification", "WARNING")
        return "unreachable"
    except Exception as e:
        log(f"Verification error: {e}", "ERROR")
        return "unknown"


# ─── Tamper Alert ─────────────────────────────────────
def report_tamper(session: dict) -> None:
    """Alert server admin — request new UUID approval."""
    try:
        requests.post(
            f"{SERVER_URL}/api/tamper-alert",
            json={
                "client_id": session.get("client_id"),
                "message": "Session file tampered or mismatched. Requesting re-registration approval."
            },
            timeout=5
        )
        log("Tamper alert sent to server admin", "WARNING")
    except Exception as e:
        log(f"Failed to send tamper alert: {e}", "ERROR")
