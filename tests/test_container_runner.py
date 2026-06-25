import unittest
from unittest.mock import patch

from cleint import container_runner


class ContainerRunnerTests(unittest.TestCase):
    @patch("cleint.container_runner.fetch_config")
    @patch("cleint.container_runner._docker_available", return_value=True)
    @patch("cleint.container_runner._container_running", return_value=False)
    @patch("cleint.container_runner._container_exists", return_value=False)
    @patch("cleint.container_runner.subprocess.run")
    def test_ensure_container_skips_config_fetch_when_not_provided(
        self,
        mock_run,
        mock_container_exists,
        mock_container_running,
        mock_docker_available,
        mock_fetch_config,
    ):
        spec = {
            "name": "sentrix-thr-test",
            "image": "sentrix/threat-engine:test",
            "args": [],
        }

        result = container_runner.ensure_container(spec)

        self.assertTrue(result)
        mock_fetch_config.assert_not_called()
        self.assertGreaterEqual(mock_run.call_count, 2)


if __name__ == "__main__":
    unittest.main()
