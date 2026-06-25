# executor_service/response_engine.py
"""
Response Engine
Evaluates enriched events against response thresholds and
auto-triggers appropriate playbook execution via the dispatcher.
"""
from logger import log
from pipeline.executor_service.dispatcher import dispatch


def evaluate(enriched: dict) -> list:
    """
    Service contract: Executor.evaluate(enriched_event)
    Evaluates an enriched event and auto-executes qualifying playbooks.
    Returns list of execution records (one per triggered playbook).
    """
    response_ctx = enriched.get("response", {})
    auto_playbooks = response_ctx.get("auto_playbooks", [])
    score = enriched.get("risk", {}).get("score", 0)

    execution_records = []

    for playbook in auto_playbooks:
        threshold = playbook.get("severity_threshold", 100)
        if score >= threshold:
            log(
                f"[RESPONSE ENGINE] Triggering playbook {playbook['id']} "
                f"({playbook['name']}) — score={score}, threshold={threshold}",
                "WARNING"
            )
            record = dispatch(enriched, playbook)
            execution_records.append(record)

    return execution_records
