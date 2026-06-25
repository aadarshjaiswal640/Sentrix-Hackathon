# executor_service/__init__.py
"""
ExecutorService — Automated SOAR response service.
Service contract: ExecutorService().evaluate(enriched_event)
"""
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

if os.path.exists(str(ROOT / "executor_service")):
    import importlib
    package_name = "pipeline.executor_service"
    try:
        importlib.import_module(package_name)
    except Exception:
        pass

from pipeline.executor_service.response_engine import evaluate as _evaluate
from pipeline.executor_service.dispatcher import get_execution_history, get_response_stats


class ExecutorService:
    def evaluate(self, enriched: dict) -> list:
        """
        Evaluate enriched event and trigger automated playbook execution.
        Returns list of execution records.
        """
        return _evaluate(enriched)
