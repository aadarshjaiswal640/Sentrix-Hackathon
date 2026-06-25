# installer.py
import platform
import shutil
import subprocess
from logger import log

def is_installed(binary_name: str) -> bool:
    return shutil.which(binary_name) is not None

def check_prerequisites() -> dict:
    """Returns what's missing so main.py can decide whether to proceed."""
    status = {
        "suricata": is_installed("suricata"),
        "wazuh_agent": is_installed("wazuh-agent") or is_installed("wazuh-control"),
    }
    for tool, ok in status.items():
        log(f"Prerequisite check — {tool}: {'OK' if ok else 'MISSING'}")
    return status

def print_install_instructions(missing: list):
    system = platform.system()
    log(f"Missing components: {missing}. Manual install required on {system}.", "WARNING")
    if "suricata" in missing:
        if system == "Linux":
            print("Install Suricata:  sudo apt install suricata  (or your distro's package manager)")
        elif system == "Windows":
            print("Download Suricata for Windows: https://suricata.io/download/")
    if "wazuh_agent" in missing:
        print("Install Wazuh agent from your Wazuh manager's deployment page:")
        print("  http://<manager-ip>:55000  or  https://documentation.wazuh.com/current/installation-guide/wazuh-agent/")