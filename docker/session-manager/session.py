# session.py
from typing import Optional
import uuid
import json
import hashlib
import redis
from datetime import datetime

r = redis.Redis(host="redis", port=6379, decode_responses=True)
sessions = {}
# ─── Helpers ──────────────────────────────────────────
def _key(client_id: str) -> str:
    return f"sentrix:client:{client_id}"

def _hash_session(data: dict) -> str:
    raw = json.dumps(data, sort_keys=True).encode()
    return hashlib.sha256(raw).hexdigest()


def _client_facing_view(client_id: str, machine_info: dict) -> dict:
    return {"client_id": client_id, **machine_info}


# ─── Register ─────────────────────────────────────────
def new_session(client: str, ip: str, machine_info: dict) -> dict:
    mac = machine_info.get("mac", "")
    for key in r.keys("sentrix:client:*"):
        raw = r.get(key)
        if raw:
            existing = json.loads(raw)
            if existing.get("machine", {}).get("mac") == mac:
                # Same machine — update it in place and refresh the hash so the
                # client's cached session still verifies against the server.
                existing["client"] = client
                existing["ip"] = ip
                existing["status"] = "online"
                existing["last_seen"] = datetime.utcnow().isoformat()
                existing["machine"] = machine_info
                existing["hash"] = _hash_session(_client_facing_view(existing["client_id"], machine_info))
                r.set(key, json.dumps(existing))
                return existing
    client_id = str(uuid.uuid4())

    # IMPORTANT: this must mirror EXACTLY what the client caches locally
    # in session.json (see cleint/registration.py -> register()):
    #     session = {"client_id": client_id, **machine_info}
    # storage.py's verify_session() hashes that local file as-is.
    # If we hash the full server-side record instead (nested "machine",
    # "services", "token", "commands", etc.) the hash can NEVER match,
    # and every agent gets flagged "tampered" on every restart.
    client_hash = _hash_session(_client_facing_view(client_id, machine_info))

    session = {
        "client_id":  client_id,
        "client":     client,
        "ip":         ip,
        "status":     "online",
        "created":    datetime.utcnow().isoformat(),
        "last_seen":  datetime.utcnow().isoformat(),
        "alerts":     [],
        "commands":   [],
        "machine":    machine_info,
        "services": {
            "wazuh":    {"status": "active"},
            "suricata": {"status": "active"}
            },
        "token": str(uuid.uuid4()),
        "hash": client_hash,
    }

    r.set(_key(client_id), json.dumps(session))
    return session


# ─── Get ──────────────────────────────────────────────
def get_session(client_id: str) -> Optional[dict]:
    raw = r.get(_key(client_id))
    return json.loads(raw) if raw else None

def get_all_sessions() -> list:
    keys = r.keys("sentrix:client:*")
    return [json.loads(r.get(k)) for k in keys]


# ─── Heartbeat update ─────────────────────────────────
def update_heartbeat(client_id: str, payload: dict):
    session = get_session(client_id)
    if not session:
        return False
    session["status"]    = "online"
    session["last_seen"] = datetime.utcnow().isoformat()
    session["ip"]        = payload.get("ip", session["ip"])
    r.set(_key(client_id), json.dumps(session))
    return True


# ─── Verify hash ──────────────────────────────────────
def verify_session_hash(client_id: str, client_hash: str) -> str:
    session = get_session(client_id)
    if not session:
        return "unknown"

    machine_info = session.get("machine") or {}
    expected = _hash_session(_client_facing_view(client_id, machine_info))
    if expected != session.get("hash"):
        session["hash"] = expected
        r.set(_key(client_id), json.dumps(session))

    return "valid" if expected == client_hash else "tampered"


# ─── Commands ─────────────────────────────────────────
def push_command(client_id: str, command: str, args: str = "") -> str:
    session = get_session(client_id)
    if not session:
        return None
    cmd_id = str(uuid.uuid4())[:8]
    session["commands"].append({
        "cmd_id":  cmd_id,
        "command": command,
        "args":    args,
        "status":  "pending",
        "result":  None,
        "issued":  datetime.utcnow().isoformat()
    })
    r.set(_key(client_id), json.dumps(session))
    return cmd_id

def pop_pending_command(client_id: str) -> dict | None:
    session = get_session(client_id)
    if not session:
        return None
    for cmd in session["commands"]:
        if cmd["status"] == "pending":
            cmd["status"] = "sent"
            r.set(_key(client_id), json.dumps(session))
            return cmd
    return None

def store_command_result(client_id: str, cmd_id: str, result: str):
    session = get_session(client_id)
    if not session:
        return
    for cmd in session["commands"]:
        if cmd["cmd_id"] == cmd_id:
            cmd["status"] = "done"
            cmd["result"] = result
    r.set(_key(client_id), json.dumps(session))
