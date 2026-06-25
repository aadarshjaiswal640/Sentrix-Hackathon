import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "cleint"))

from cleint.pipeline.wazuh import ensure_wazuh_api_ready


class WazuhPipelineTests(unittest.TestCase):
    def test_persists_wazuh_api_credentials_and_token(self):
        session = {
            "client_id": "client-1",
            "services": {
                "wazuh": {
                    "api_url": "https://wazuh.example",
                    "api_user": "sentrix",
                    "api_password": "secret",
                }
            },
        }

        class FakeResponse:
            content = b'{"data": {"token": "abc123"}}'

            def raise_for_status(self):
                return None

            def json(self):
                return {"data": {"token": "abc123"}}

        with patch("cleint.pipeline.wazuh.requests.post", return_value=FakeResponse()) as mock_post, patch(
            "cleint.pipeline.wazuh.save_session"
        ) as mock_save:
            cfg = ensure_wazuh_api_ready(session)

        self.assertEqual(cfg["token"], "abc123")
        self.assertEqual(session["services"]["wazuh"]["token"], "abc123")
        self.assertEqual(session["wazuh"]["api_user"], "sentrix")
        self.assertEqual(mock_post.call_count, 2)
        self.assertEqual(mock_post.call_args_list[0].args[0], "https://wazuh.example/security/user/authenticate")
        mock_save.assert_called_once_with(session)


if __name__ == "__main__":
    unittest.main()
