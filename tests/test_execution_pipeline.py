import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "cleint"))

from pipeline import compute
from pipeline.executor_service import ExecutorService


class ExecutionPipelineTests(unittest.TestCase):
    def test_compute_process_orchestrates_threat_engine_dashboard_and_executor(self):
        event = {
            "source": "test",
            "data": {
                "src_ip": "1.2.3.4",
                "dest_ip": "10.0.0.5",
                "hostname": "host-1",
                "user": {"name": "alice"},
                "process": {"name": "cmd.exe"},
            },
        }

        class FakeThreatEngine:
            def process(self, incoming_event):
                return {
                    **incoming_event,
                    "risk": {"score": 70, "src_ip": "1.2.3.4", "dest_ip": "10.0.0.5"},
                    "mitre": {"technique_id": "T1190", "technique_name": "Exploit"},
                    "anomaly": {"anomaly_detected": False},
                    "campaign": {"campaign_id": "CAM-1", "is_multi_stage": False},
                    "ai_analysis": {"summary": "High severity event", "technique_context": "Exploit"},
                    "response": {
                        "auto_playbooks": [
                            {
                                "id": "PB-001",
                                "name": "Block Malicious IP",
                                "actions": ["block_ip"],
                                "severity_threshold": 60,
                                "auto_execute": True,
                            }
                        ]
                    },
                }

        class FakeDashboard:
            def __init__(self):
                self.published = []

            def publish(self, enriched):
                self.published.append(enriched)

        class FakeExecutor:
            def __init__(self):
                self.enriched_events = []

            def evaluate(self, enriched):
                self.enriched_events.append(enriched)
                return [{"playbook_id": "PB-001", "action_count": 1}]

        fake_threat_engine = FakeThreatEngine()
        fake_dashboard = FakeDashboard()
        fake_executor = FakeExecutor()

        with patch("pipeline.compute._get_services", return_value=(fake_threat_engine, fake_dashboard, fake_executor)):
            compute.process(event)

        self.assertEqual(len(fake_dashboard.published), 1)
        self.assertEqual(len(fake_executor.enriched_events), 1)
        self.assertEqual(fake_executor.enriched_events[0]["response"]["auto_playbooks"][0]["id"], "PB-001")
        self.assertEqual(fake_executor.enriched_events[0]["risk"]["score"], 70)

    def test_executor_service_dispatches_auto_playbooks_for_threshold_match(self):
        service = ExecutorService()
        enriched = {
            "risk": {"score": 60},
            "response": {
                "auto_playbooks": [
                    {
                        "id": "PB-001",
                        "name": "Block Malicious IP",
                        "actions": ["block_ip"],
                        "severity_threshold": 60,
                        "auto_execute": True,
                    }
                ]
            },
        }

        with patch("pipeline.executor_service.response_engine.dispatch", return_value={"playbook_id": "PB-001"}) as mock_dispatch:
            records = service.evaluate(enriched)

        self.assertEqual(records, [{"playbook_id": "PB-001"}])
        mock_dispatch.assert_called_once()


if __name__ == "__main__":
    unittest.main()
