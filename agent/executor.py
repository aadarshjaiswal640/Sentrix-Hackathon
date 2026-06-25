import shlex
import subprocess
from typing import Any, Dict, List, Optional


class ExecutorService:
    """Minimal executor used by the agent for remediation and investigation commands."""

    def evaluate(self, enriched: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        return []

    def execute(self, command: str, args: Optional[List[str]] = None) -> Dict[str, Any]:
        return execute_command(command, args or [])


def execute_command(command: str, args: Optional[List[str]] = None) -> Dict[str, Any]:
    args = args or []
    try:
        completed = subprocess.run(
            [command, *args],
            shell=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
        return {
            "status": "executed" if completed.returncode == 0 else "failed",
            "command": command,
            "args": args,
            "stdout": completed.stdout,
            "stderr": completed.stderr,
            "returncode": completed.returncode,
        }
    except FileNotFoundError:
        return {
            "status": "failed",
            "command": command,
            "args": args,
            "stdout": "",
            "stderr": f"Command not found: {command}",
            "returncode": 127,
        }
    except subprocess.TimeoutExpired as exc:
        return {
            "status": "failed",
            "command": command,
            "args": args,
            "stdout": "",
            "stderr": f"Command timed out after {exc.timeout}s",
            "returncode": 124,
        }
    except Exception as exc:  # pragma: no cover - defensive
        return {
            "status": "failed",
            "command": command,
            "args": args,
            "stdout": "",
            "stderr": str(exc),
            "returncode": 1,
        }


def run_investigation(command: str, args: Optional[List[str]] = None) -> Dict[str, Any]:
    return execute_command(command, args or [])


def run_remediation(command: str, args: Optional[List[str]] = None) -> Dict[str, Any]:
    return execute_command(command, args or [])


# Compatibility alias for the old import name used elsewhere in the project.
executor_service = ExecutorService
