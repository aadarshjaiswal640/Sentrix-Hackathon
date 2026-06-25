# app.py
import asyncio
import json
import os
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request as _UrllibRequest, urlopen
import redis
from fastapi import FastAPI, HTTPException, Response, Depends, Request

WAZUH_API_USER = os.getenv("WAZUH_API_USER", "sentrix")
WAZUH_API_PASSWORD = os.getenv("WAZUH_API_PASSWORD", "Sentrix@2026!")
UPSTREAM_DASHBOARD_URL = os.getenv("SENTRIX_DASHBOARD_URL", "http://127.0.0.1:7000")
from pydantic import BaseModel
from typing import Optional
from datetime import datetime
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse


from session import (
    new_session, get_session, get_all_sessions,
    update_heartbeat, verify_session_hash,
    push_command, pop_pending_command, store_command_result, sessions
)
from auth import require, require_role, login_user

app = FastAPI(title="Sentrix Session Manager")
r = redis.Redis(host="redis", port=6379, decode_responses=True)

TAMPER_PREFIX = "sentrix:tamper:"


def _dashboard_html_candidates() -> list:
    candidates = []
    env_path = os.getenv("SENTRIX_DASHBOARD_HTML")
    if env_path:
        candidates.append(Path(env_path))

    candidates.extend([
        Path("/app/dashboard.html"),
        Path(__file__).resolve().parent / "dashboard.html",
        Path("/app/dashboard_assets/index.html"),
        Path("/app/index.html"),
    ])

    repo_root = None
    try:
        repo_root = Path(__file__).resolve().parents[2]
    except IndexError:
        repo_root = None

    if repo_root:
        candidates.append(repo_root / "cleint" / "pipeline" / "dashboard" / "index.html")

    return [p for p in candidates if p]


def _dashboard_html() -> Optional[str]:
    for path in _dashboard_html_candidates():
        if path.exists():
            return path.read_text(encoding="utf-8")
    return None


def _elastic_url(index: str) -> str:
    host = os.getenv("SENTRIX_ES_HOST", "127.0.0.1")
    return f"http://{host}:9200/{index}/_search"


def _session_to_dashboard_payload(session: dict) -> dict:
    machine = session.get("machine") or {}
    return {
        "client_id": session.get("client_id"),
        "client": session.get("client") or machine.get("hostname"),
        "hostname": machine.get("hostname") or session.get("client"),
        "ip": session.get("ip") or machine.get("ip"),
        "status": session.get("status", "offline"),
        "created": session.get("created"),
        "last_seen": session.get("last_seen"),
        "alerts": session.get("alerts", []),
        "commands": session.get("commands", []),
        "machine": machine,
        "services": session.get("services", {}),
        "token": session.get("token"),
        "hash": session.get("hash"),
    }


def _dashboard_sessions() -> list:
    all_sessions = get_all_sessions()
    return [_session_to_dashboard_payload(s) for s in all_sessions if isinstance(s, dict)]


def _tamper_key(client_id: str) -> str:
    return f"{TAMPER_PREFIX}{client_id}"

def get_tamper_alert(client_id: str) -> Optional[dict]:
    raw = r.get(_tamper_key(client_id))
    return json.loads(raw) if raw else None

def set_tamper_alert(client_id: str, alert: dict) -> None:
    r.set(_tamper_key(client_id), json.dumps(alert))

def get_all_tamper_alerts() -> dict:
    out = {}
    for key in r.keys(f"{TAMPER_PREFIX}*"):
        client_id = key[len(TAMPER_PREFIX):]
        raw = r.get(key)
        if raw:
            out[client_id] = json.loads(raw)
    return out


def resolve_tamper_alert(client_id: str, approved: bool) -> dict:
    alert = get_tamper_alert(client_id)
    if not alert:
        raise HTTPException(status_code=404, detail="No tamper alert found")

    if approved:
        r.delete(f"sentrix:client:{client_id}")

    alert["status"] = "approved" if approved else "rejected"
    set_tamper_alert(client_id, alert)
    return alert

# ─── Models ───────────────────────────────────────────
class RegisterPayload(BaseModel):
    hostname:     str
    username:     str
    ip:           str
    mac:          str
    os:           str
    os_version:   str
    architecture: str
    cpu:          str
    ram_gb:       float
    boot_time:    str
    timezone:     str
    registered_at:str

class HeartbeatPayload(BaseModel):
    client_id:    str
    hostname:     str
    username:     str
    ip:           str
    current_time: str
    uptime:       int
    online:       bool

class ServicePayload(BaseModel):
    client_id: str

class ContainerPayload(BaseModel):
    client_id: str

class VerifyPayload(BaseModel):
    client_id: str
    hash:      str

class TamperPayload(BaseModel):
    client_id: str
    message:   str

class LogPayload(BaseModel):
    message: str
    level:   str = "INFO"

class CommandResult(BaseModel):
    client_id: str
    cmd_id:    str
    command:   str
    result:    str

class CommandPoll(BaseModel):
    client_id: str

class SystemInfoPayload(BaseModel):
    client_id:    str
    hostname:     str
    ip:           str
    cpu_percent:  float
    ram_used_gb:  float
    ram_percent:  float
    disk_percent: float
    current_time: str

class LoginPayload(BaseModel):
    username: str
    password: str

# ─── Auth ─────────────────────────────────────────────
@app.post("/auth/login")
def login(payload: LoginPayload):
    return login_user(payload.username, payload.password)

@app.get("/auth/me")
def me(user=Depends(require("view_dashboard"))):
    return user

# ─── Services ─────────────────────────────────────────
@app.post("/session/services")
def get_services(payload: ServicePayload):
    s = get_session(payload.client_id)
    if not s:
        raise HTTPException(status_code=403, detail="Client not authenticated")
    return {
        "session_id": s["client_id"],
        "client_id":  payload.client_id,
        "services": {
            "wazuh": {
                "url":         _elastic_url("wazuh-alerts-*"),
                "api_url":     os.getenv("WAZUH_API_URL", "https://127.0.0.1:55000"),
                "api_user":    WAZUH_API_USER,
                "api_password": WAZUH_API_PASSWORD,
                "token":       s.get("token", ""),
                "status":      "active"
            },
            "suricata": {
                "url":    _elastic_url("suricata-events-*"),
                "token":  s.get("token", ""),
                "status": "active"
            }
        }
    }

@app.post("/session/containers")
def get_containers(payload: ContainerPayload):
    container_plan = [
        {
            "name":       "sentrix-suricata",
            "image":      "jasonish/suricata:latest",
            "args":       ["-i", "eth0"],
            "cap_add":    ["NET_ADMIN", "SYS_NICE"],
            "config_url": "/session/containers/suricata-config",
        }
    ]
    return {"client_id": payload.client_id, "containers": container_plan}

@app.get("/session/containers/suricata-config")
def get_suricata_config():
    config_path = Path(__file__).parent / "suricata.yaml"
    if config_path.exists():
        return Response(content=config_path.read_text(), media_type="application/x-yaml")
    return Response(content="", media_type="application/x-yaml")

# ─── Agent Routes (no auth — agent has no token yet) ──
@app.post("/api/register")
def register(payload: RegisterPayload):
    session = new_session(
        client=payload.hostname,
        ip=payload.ip,
        machine_info=payload.dict()
    )
    return {"client_id": session["client_id"]}

@app.post("/api/heartbeat")
def heartbeat(payload: HeartbeatPayload):
    ok = update_heartbeat(payload.client_id, payload.dict())
    if not ok:
        raise HTTPException(status_code=404, detail="Client not found")
    return {"status": "ok"}

@app.post("/api/verify-session")
def api_verify_session(payload: VerifyPayload):
    status = verify_session_hash(payload.client_id, payload.hash)
    return {"status": status}

@app.post("/api/tamper-alert")
def tamper_alert(payload: TamperPayload):
    print(f"TAMPER ALERT: {payload.client_id} — {payload.message}")
    alert = {
        "client_id": payload.client_id,
        "message":   payload.message,
        "status":    "pending",
        "timestamp": datetime.utcnow().isoformat()
    }
    set_tamper_alert(payload.client_id, alert)
    return {"status": "pending", "action": "await_approval"}

@app.post("/api/command")
def command_poll(payload: CommandPoll):
    cmd = pop_pending_command(payload.client_id)
    if not cmd:
        return {"command": None}
    return cmd

@app.post("/api/command/result")
def command_result(payload: CommandResult):
    store_command_result(payload.client_id, payload.cmd_id, payload.result)
    return {"status": "stored"}

@app.post("/api/system-info")
def system_info(payload: SystemInfoPayload):
    print(f"[SYSINFO] {payload.client_id} — CPU:{payload.cpu_percent}% RAM:{payload.ram_percent}%")
    return {"status": "received"}

@app.post("/api/logs")
def receive_log(payload: LogPayload):
    print(f"[CLIENT LOG] [{payload.level}] {payload.message}")
    return {"status": "logged"}

# ─── Admin Routes (RBAC protected) ────────────────────
@app.get("/sessions",
    dependencies=[Depends(require("view_agents"))])
def get_sessions_list():
    result = _dashboard_sessions()
    print(f"[DASHBOARD][/sessions] count={len(result)}")
    return result


@app.get("/api/sessions")
def get_api_sessions():
    result = _dashboard_sessions()
    print(f"[DASHBOARD][/api/sessions] count={len(result)}")
    return {"sessions": result, "count": len(result)}

@app.get("/session/{client_id}",
    dependencies=[Depends(require("view_agents"))])
def session_detail(client_id: str):
    s = get_session(client_id)
    if not s:
        raise HTTPException(status_code=404, detail="Not found")
    return s


@app.post("/admin/tamper/approve",
    dependencies=[Depends(require("approve_tamper")),
        Depends(require_role(["admin@SOC","admin@Super"]))])
def approve_tamper(client_id: str):
    resolve_tamper_alert(client_id, approved=True)
    return {"status": "approved"}

@app.post("/admin/tamper/reject",
    dependencies=[Depends(require("approve_tamper")),
        Depends(require_role(["admin@SOC","admin@Super"]))])
def reject_tamper(client_id: str):
    resolve_tamper_alert(client_id, approved=False)
    return {"status": "rejected"}

@app.get("/admin/tamper/status/{client_id}")
def tamper_status(client_id: str):
    alert = get_tamper_alert(client_id)
    if not alert:
        return {"status": "not_found"}
    return alert

@app.get("/admin/tamper/alerts",
    dependencies=[Depends(require("view_agents")),
        Depends(require_role(["admin@SOC","admin@Super"]))])
def get_tamper_alerts_route():
    return get_all_tamper_alerts()

@app.post("/admin/command",
    dependencies=[Depends(require("run_commands"))])
def admin_push_command(
    client_id: str,
    command: str,
    args: str = "",
    user=Depends(require("run_commands"))
):
    roles = user["roles"]

    if command in ["shell", "disconnect"]:
        if not any(role in ["admin@SOC", "admin@Super"] for role in roles):
            raise HTTPException(status_code=403, detail="Admin role required")

    cmd_id = push_command(client_id, command, args)

    if not cmd_id:
        raise HTTPException(status_code=404, detail="Client not found")

    return {"cmd_id": cmd_id}

# ─── Dashboard ────────────────────────────────────────
@app.get("/dashboard", response_class=HTMLResponse)
def dashboard():
    html = _dashboard_html()
    if html:
        return html
    return "<h1>Dashboard HTML not found</h1>"

@app.get("/api/agent")
def agent_info(user=Depends(require("view_dashboard"))):
    all_sessions = _dashboard_sessions()
    if all_sessions:
        s = all_sessions[0]
        machine = s.get("machine") or {}
        return {
            "client_id": s.get("client_id"),
            "hostname":  s.get("hostname") or s.get("client"),
            "ip":        s.get("ip"),
            "os":        machine.get("os"),
            "status":    s.get("status", "online"),
            "timestamp": s.get("last_seen") or datetime.utcnow().isoformat(),
        }
    return {
        "client_id": None,
        "hostname":  None,
        "ip":        None,
        "os":        None,
        "status":    "offline",
        "timestamp": datetime.utcnow().isoformat(),
    }

@app.get("/api/events")
def get_events(limit: int = 50):
    all_sessions = _dashboard_sessions()[:limit]
    events = []
    for s in all_sessions:
        machine = s.get("machine") or {}
        events.append({
            "timestamp":      s.get("last_seen") or s.get("created") or datetime.utcnow().isoformat(),
            "source":         "SESSION-MANAGER",
            "severity":       "INFO" if s.get("status") == "online" else "LOW",
            "technique_id":   "T1059",
            "technique_name": "Session heartbeat",
            "kill_chain":     "Session",
            "src_ip":         s.get("ip") or machine.get("ip") or "127.0.0.1",
            "dest_ip":        "",
            "campaign_id":    "",
            "anomaly_detected": bool(s.get("alerts")),
            "primary_anomaly": "tamper_alert" if s.get("alerts") else "",
            "confidence":     "HIGH" if s.get("status") == "online" else "MEDIUM",
            "score":          30 if s.get("status") == "online" else 10,
        })
    print(f"[DASHBOARD][/api/events] count={len(events)}")
    return {"count": len(events), "timestamp": datetime.utcnow().isoformat(), "events": events}

@app.get("/api/campaigns")
def get_campaigns():
    all_sessions = _dashboard_sessions()
    campaigns = []
    for s in all_sessions:
        if s.get("alerts"):
            campaigns.append({
                "campaign_id": f"tamper-{s['client_id'][:8]}",
                "name": "Pending Tamper Review",
                "severity": "HIGH",
                "status": "active"
            })
    stats = {
        "total_alerts_in_memory": sum(len(s.get("alerts", [])) for s in all_sessions),
        "active_campaigns":       len(campaigns),
        "tracked_ips":            len({s.get("ip") for s in all_sessions if s.get("ip")}),
        "tracked_users":          len({(s.get("machine") or {}).get("username") for s in all_sessions if (s.get("machine") or {}).get("username")}),
    }
    return {"campaigns": campaigns, "stats": stats, "timestamp": datetime.utcnow().isoformat()}

@app.get("/api/responses")
def get_responses(limit: int = 50):
    return {
        "responses": [],
        "stats": {
            "total_responses": 0, "automated": 0, "manual": 0,
            "total_actions": 0, "successful_actions": 0, "playbook_usage": {}
        },
        "timestamp": datetime.utcnow().isoformat()
    }

@app.get("/api/executive-summary")
def executive_summary():
    return {
        "posture": "NORMAL",
        "summary_text": "No detections recorded yet.",
        "total_events": 0, "critical_count": 0, "high_count": 0,
        "campaign_count": 0, "anomaly_count": 0, "top_techniques": []
    }

@app.get("/api/iocs")
def get_iocs():
    return {"ip_iocs": [], "domain_iocs": [], "process_iocs": []}

# ─── SSE live session stream ───────────────────────────
@app.get("/api/stream")
async def event_stream(request: Request):
    async def generator():
        while True:
            if await request.is_disconnected():
                break
            payload = {
                "type":      "session-update",
                "timestamp": datetime.utcnow().isoformat(),
                "sessions":  _dashboard_sessions(),
            }
            yield f"event: session-update\ndata: {json.dumps(payload)}\n\n"
            await asyncio.sleep(5)

    return StreamingResponse(
        generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control":               "no-cache",
            "X-Accel-Buffering":           "no",
            "Access-Control-Allow-Origin": "*",
        },
    )

# ─── Proxy: forward remaining /api/* to agent dashboard (port 7000) ───────────
@app.api_route("/api/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"])
async def proxy_dashboard_api(path: str, request: Request):
    """
    Forward API routes the session-manager does not own (threat feed, MITRE,
    campaigns from threat engine, etc.) to the agent dashboard server at port 7000.
    """
    upstream_url = f"{UPSTREAM_DASHBOARD_URL.rstrip('/')}/api/{quote(path, safe='/')}"
    body = await request.body()
    headers = {
        k: v for k, v in request.headers.items()
        if k.lower() not in {"host", "content-length", "connection"}
    }

    try:
        req = _UrllibRequest(upstream_url, data=body or None, headers=headers, method=request.method)
        with urlopen(req, timeout=5) as resp:
            payload      = resp.read()
            content_type = resp.headers.get_content_type()
            return Response(content=payload, media_type=content_type)
    except HTTPError as exc:
        payload = exc.read().decode("utf-8", errors="ignore")
        return JSONResponse(status_code=exc.code, content={"error": payload})
    except URLError as exc:
        return JSONResponse(
            status_code=502,
            content={"error": f"Agent dashboard upstream unavailable: {exc.reason}"}
        )

@app.get("/login", response_class=HTMLResponse)
def login_page():
    login_path = Path(__file__).parent / "login.html"
    if login_path.exists():
        return login_path.read_text(encoding="utf-8")
    return "<h1>Login page not found</h1>"

# ─── Health ───────────────────────────────────────────
@app.get("/health")
def health():
    return {"status": "ok", "time": datetime.utcnow().isoformat()}

# ─── Root — serve the SOC dashboard ──────────────────
@app.get("/", response_class=HTMLResponse)
def root():
    return dashboard()
