import importlib.util
import socket
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CLIENT_ROOT = ROOT / "cleint"
sys.path.insert(0, str(CLIENT_ROOT))

spec = importlib.util.spec_from_file_location(
    "dashboard_server",
    CLIENT_ROOT / "pipeline" / "dashboard" / "server.py",
)
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)


class DashboardServerTests(unittest.TestCase):
    def test_finds_another_port_when_requested_port_is_busy(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind(("127.0.0.1", 0))
            sock.listen(1)
            busy_port = sock.getsockname()[1]
            chosen = module.find_available_port(busy_port, max_attempts=3)

        self.assertNotEqual(chosen, busy_port)
        self.assertGreaterEqual(chosen, busy_port)


if __name__ == "__main__":
    unittest.main()
