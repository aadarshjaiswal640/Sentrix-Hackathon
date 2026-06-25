import importlib
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1] / "cleint"
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def test_pipeline_executor_service_imports():
    module = importlib.import_module("pipeline.executor_service")
    assert hasattr(module, "ExecutorService")
