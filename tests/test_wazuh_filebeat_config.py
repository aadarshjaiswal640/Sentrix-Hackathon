from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
CONFIG_PATH = ROOT / "docker" / "wazuh" / "filebeat.yml"


class WazuhFilebeatConfigTests(unittest.TestCase):
    def test_wazuh_filebeat_targets_the_local_elasticsearch_service(self):
        self.assertTrue(CONFIG_PATH.exists(), f"Missing config file: {CONFIG_PATH}")
        content = CONFIG_PATH.read_text(encoding="utf-8")
        self.assertIn("sentrix-elastic", content)
        self.assertIn("http://sentrix-elastic:9200", content)


if __name__ == "__main__":
    unittest.main()
