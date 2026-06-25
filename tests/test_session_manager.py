import base64
import importlib.util
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
APP_DIR = ROOT / "docker" / "session-manager"
sys.path.insert(0, str(APP_DIR))

import session as session_module
from fastapi.testclient import TestClient

APP_PATH = APP_DIR / "app.py"

spec = importlib.util.spec_from_file_location("session_manager_app", APP_PATH)
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)


class SessionManagerTests(unittest.TestCase):
    def test_container_plan_is_returned_when_session_is_missing(self):
        with patch.object(module, "get_session", return_value=None):
            result = module.get_containers(module.ContainerPayload(client_id="missing"))

        self.assertEqual(result["containers"][0]["name"], "sentrix-suricata")
        self.assertEqual(result["client_id"], "missing")

    def test_local_admin_login_returns_admin_token(self):
        result = module.login_user("admin", "sentrix123")

        self.assertIn("access_token", result)
        payload_segment = result["access_token"].split(".")[1]
        padded = payload_segment + "=" * (-len(payload_segment) % 4)
        payload = json.loads(base64.b64decode(padded.encode()).decode())
        self.assertIn("admin@SOC", payload["realm_access"]["roles"])

    def test_agent_can_poll_tamper_status_without_bearer_token(self):
        client = TestClient(module.app)
        with patch.object(module, "get_tamper_alert", return_value=None):
            response = client.get("/admin/tamper/status/test-client")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"status": "not_found"})

    def test_reused_session_updates_hash_when_machine_info_changes(self):
        existing = {
            "client_id": "existing-client",
            "client": "old-host",
            "ip": "1.1.1.1",
            "status": "online",
            "created": "2024-01-01T00:00:00",
            "last_seen": "2024-01-01T00:00:00",
            "alerts": [],
            "commands": [],
            "machine": {"mac": "aa:bb", "hostname": "old-host", "registered_at": "old"},
            "services": {"wazuh": {"status": "active"}},
            "token": "old-token",
            "hash": "stale-hash",
        }

        fake_r = unittest.mock.Mock()
        fake_r.keys.return_value = ["sentrix:client:existing-client"]
        fake_r.get.return_value = json.dumps(existing)

        with patch.object(session_module, "r", fake_r):
            updated = session_module.new_session(
                client="new-host",
                ip="2.2.2.2",
                machine_info={"mac": "aa:bb", "hostname": "new-host", "registered_at": "new"},
            )

        self.assertEqual(updated["machine"]["hostname"], "new-host")
        self.assertEqual(
            updated["hash"],
            session_module._hash_session({"client_id": "existing-client", "mac": "aa:bb", "hostname": "new-host", "registered_at": "new"}),
        )

    def test_verify_session_hash_refreshes_stale_hash_for_existing_session(self):
        existing = {
            "client_id": "existing-client",
            "machine": {"mac": "aa:bb", "hostname": "host-one", "registered_at": "now"},
            "hash": "stale-hash",
        }

        fake_r = unittest.mock.Mock()
        fake_r.get.return_value = json.dumps(existing)
        fake_r.set.return_value = True

        with patch.object(session_module, "r", fake_r):
            self.assertEqual(
                session_module.verify_session_hash(
                    "existing-client",
                    session_module._hash_session({"client_id": "existing-client", "mac": "aa:bb", "hostname": "host-one", "registered_at": "now"}),
                ),
                "valid",
            )

        self.assertTrue(fake_r.set.called)


if __name__ == "__main__":
    unittest.main()
