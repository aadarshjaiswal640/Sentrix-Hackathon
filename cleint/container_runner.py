# container_runner.py
"""
Asks the server which containers to run, pulls + starts them locally
via Docker, and exposes the local log path so watcher.py can tail it.
First run: pulls image + creates container.
Every run after: just starts the existing container if it's stopped.
"""
import subprocess
import requests
from pathlib import Path
from config import SERVER_URL, LOG_DIR
from logger import log

SURICATA_LOCAL_LOG_DIR = LOG_DIR / "suricata"
SURICATA_CONFIG_PATH   = LOG_DIR / "suricata.yaml"


def _docker_available() -> bool:
    try:
        subprocess.run(["docker", "--version"], capture_output=True, check=True)
        return True
    except Exception:
        return False


def _container_exists(name: str) -> bool:
    result = subprocess.run(
        ["docker", "ps", "-a", "--filter", f"name=^{name}$", "--format", "{{.Names}}"],
        capture_output=True, text=True
    )
    return name in result.stdout.split()


def _container_running(name: str) -> bool:
    result = subprocess.run(
        ["docker", "ps", "--filter", f"name=^{name}$", "--format", "{{.Names}}"],
        capture_output=True, text=True
    )
    return name in result.stdout.split()


def fetch_container_plan(session: dict) -> list:
    """Ask the server what containers should run on this client."""
    try:
        resp = requests.post(
            f"{SERVER_URL}/session/containers",
            json={"client_id": session["client_id"]},
            timeout=10
        )
        resp.raise_for_status()
        return resp.json().get("containers", [])
    except Exception as e:
        log(f"Failed to fetch container plan: {e}", "ERROR")
        return []


def fetch_config(config_url: str, save_to: Path):
    if not config_url:
        log("No config URL provided — skipping config fetch")
        return

    try:
        resp = requests.get(f"{SERVER_URL}{config_url}", timeout=10)
        resp.raise_for_status()
        save_to.write_text(resp.text)
        log(f"Config saved to {save_to}")
    except Exception as exc:
        log(f"Failed to fetch container config: {exc}", "WARNING")


def ensure_container(spec: dict):
    """Pull + create on first run, just start on later runs."""
    name = spec["name"]
    config_url = spec.get("config_url")

    if not _docker_available():
        log("Docker not available on this host — cannot run containers", "ERROR")
        return False

    if _container_running(name):
        log(f"{name} already running")
        return True

    if _container_exists(name):
        log(f"{name} exists but stopped — starting it")
        try:
            subprocess.run(["docker", "start", name], check=True)
        except Exception as exc:
            log(f"Failed to start existing container {name}: {exc}", "ERROR")
            return False
        return True

    # First run for this container: fetch config if provided, pull image, create + start
    log(f"First-run setup for {name} — pulling {spec['image']}")
    SURICATA_LOCAL_LOG_DIR.mkdir(parents=True, exist_ok=True)
    fetch_config(config_url, SURICATA_CONFIG_PATH)

    try:
        subprocess.run(["docker", "pull", spec["image"]], check=True)

        cmd = ["docker", "run", "-d", "--name", name]
        for cap in spec.get("cap_add", []):
            cmd += ["--cap-add", cap]
        cmd += ["-v", f"{SURICATA_LOCAL_LOG_DIR}:/var/log/suricata"]
        if config_url or SURICATA_CONFIG_PATH.exists():
            cmd += ["-v", f"{SURICATA_CONFIG_PATH}:/etc/suricata/suricata.yaml"]
            cmd += ["-v", f"{Path(SURICATA_CONFIG_PATH).parent / 'rules'}:/var/lib/suricata/rules"]
        cmd += [spec["image"]] + spec.get("args", [])
        subprocess.run(cmd, check=True)
    except Exception as exc:
        log(f"Failed to create/start container {name}: {exc}", "ERROR")
        return False

    log(f"{name} started — image={spec['image']} args={spec.get('args')}")
    return True


def setup_and_run(session: dict):
    """Entry point called from main.py at boot."""
    containers = fetch_container_plan(session)
    if not containers:
        log("No containers returned by server", "WARNING")
        return []

    started = []
    for spec in containers:
        if ensure_container(spec):
            started.append(spec["name"])
    return started
