# main.py
import time
import threading
import requests
from config import TIMING, SERVER_URL
from storage import load_session, verify_session, report_tamper
from registration import register
from logger import log
from pipeline.streamer import stream
from container_runner import setup_and_run
from watcher import run_watcher_and_print
from pipeline.dashboard.server import launch
from pipeline.wazuh import ensure_wazuh_api_ready


def needs_re_registration(status: str) -> bool:
    return status in {"unknown", "tampered"}


def heartbeat_loop(session: dict):
    import psutil, socket
    from datetime import datetime
    while True:
        try:
            payload = {
                "client_id":    session["client_id"],
                "hostname":     session["hostname"],
                "username":     session["username"],
                "ip":           socket.gethostbyname(socket.gethostname()),
                "current_time": datetime.utcnow().isoformat(),
                "uptime":       int(time.time() - psutil.boot_time()),
                "online":       True
            }
            requests.post(f"{SERVER_URL}/api/heartbeat", json=payload, timeout=5)
            log("Heartbeat sent")
        except requests.ConnectionError:
            log("Heartbeat failed — server unreachable, retrying...", "WARNING")
        except Exception as e:
            log(f"Heartbeat error: {e}", "ERROR")
        time.sleep(TIMING["heartbeat"])


def command_loop(session: dict):
    while True:
        try:
            resp = requests.post(
                f"{SERVER_URL}/api/command",
                json={"client_id": session["client_id"]},
                timeout=5
            )
            data = resp.json()
            if data.get("command"):
                log(f"Command received: {data['command']}")
                from commands import handle_command
                handle_command(data, session)
        except requests.ConnectionError:
            log("Command poll failed — retrying...", "WARNING")
        except Exception as e:
            log(f"Command poll error: {e}", "ERROR")
        time.sleep(TIMING["command_poll"])


def boot():
    log("=" * 40)
    log("Sentrix Agent Starting...")
    log("=" * 40)

    # Step 1 — Load or Register
    session = load_session()

    if session is None:
        log("No session found — registering as new client...")
        while True:
            try:
                session = register()
                break
            except Exception:
                log(f"Registration failed, retrying in {TIMING['retry']}s...", "WARNING")
                time.sleep(TIMING["retry"])

    else:
        log(f"Session found. client_id={session['client_id']}")

        # Step 2 — Verify with server
        status = verify_session(session)

        if status == "tampered":
            log("TAMPER DETECTED — alerting admin", "ERROR")
            report_tamper(session)
            log("Waiting for admin approval...", "WARNING")

            while True:
                try:
                    resp = requests.get(
                        f"{SERVER_URL}/admin/tamper/status/{session['client_id']}",
                        timeout=5
                    )
                    data = resp.json()

                    if data.get("status") == "approved":
                        log("Admin approved — re-registering", "WARNING")
                        from config import SESSION_FILE
                        if SESSION_FILE.exists():
                            SESSION_FILE.unlink()
                        session = register()
                        break

                    elif data.get("status") == "rejected":
                        log("Admin rejected — shutting down", "ERROR")
                        import sys
                        sys.exit(0)

                except Exception as e:
                    log(f"Approval poll failed: {e}", "WARNING")

                time.sleep(10)

        elif status == "unreachable":
            log("Server offline — proceeding with cached session", "WARNING")

        elif needs_re_registration(status):
            log("Server no longer recognizes this session — re-registering", "WARNING")
            from config import SESSION_FILE
            if SESSION_FILE.exists():
                SESSION_FILE.unlink()
            session = register()

        elif status == "valid":
            log("Session verified OK")

    # Step 2.5 — Pull Service Session
    try:
        resp = requests.post(
            f"{SERVER_URL}/session/services",
            json={"client_id": session["client_id"]},
            timeout=5
        )
        resp.raise_for_status()
        service_session = resp.json()
        session["services"] = service_session.get("services", {})
        log("Service session pulled OK")
    except requests.HTTPError as e:
        log(f"Service session pull rejected by server: {e}", "WARNING")
        session["services"] = {}
        if getattr(e.response, "status_code", None) in {403, 404}:
            log("Server session is missing — re-registering client", "WARNING")
            from config import SESSION_FILE
            if SESSION_FILE.exists():
                SESSION_FILE.unlink()
            session = register()
            session["services"] = {}
    except Exception as e:
        log(f"Service session pull failed: {e}", "WARNING")
        session["services"] = {}

    ensure_wazuh_api_ready(session)
    # Step 2.6 — Request + run containers (Suricata, etc.)
    log("Requesting container plan from server...")
    started = setup_and_run(session)
    if started:
        log(f"Containers running: {started}")
    else:
        log("No containers started — Suricata output will not be available", "WARNING")
    # Step 3 — Launch threads (sirf ek baar)
    log("Launching threads...")
    launch(session)
    threading.Thread(target=heartbeat_loop, args=(session,), daemon=True).start()
    threading.Thread(target=command_loop,   args=(session,), daemon=True).start()
    threading.Thread(target=stream,         args=(session,), daemon=True).start()
    threading.Thread(target=run_watcher_and_print, daemon=True).start()
    log("Sentrix Agent running.")

    while True:
        time.sleep(1)


if __name__ == "__main__":
    boot()