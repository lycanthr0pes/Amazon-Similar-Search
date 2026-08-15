"""Deterministic support code for the local AI review harness.

The package initializer deliberately imports no harness or third-party module.  The external
launcher imports the stdlib-only preflight module through this package before a verified zipapp
or its dependencies may execute.
"""

from __future__ import annotations

from importlib import import_module
from typing import Any

__all__ = [
    "ReviewReport",
    "TaskSpec",
    "TddEvidence",
    "Verdict",
    "canonical_outer_broker_evidence_bytes",
    "canonical_prepared_broker_batch_bytes",
    "execute_prepared_broker_outer",
    "finalize_provisioned_broker_execution",
    "inspect_git_diff",
    "judge",
    "measure_broker_outer_runtime",
    "prepare_broker_outer_ledger",
    "prepare_provisioned_broker_execution",
]


_EXPORTS = {
    "ReviewReport": ("tools.ai_review.models", "ReviewReport"),
    "TaskSpec": ("tools.ai_review.models", "TaskSpec"),
    "TddEvidence": ("tools.ai_review.models", "TddEvidence"),
    "Verdict": ("tools.ai_review.models", "Verdict"),
    "canonical_outer_broker_evidence_bytes": (
        "tools.ai_review.broker_outer_executor",
        "canonical_outer_broker_evidence_bytes",
    ),
    "canonical_prepared_broker_batch_bytes": (
        "tools.ai_review.broker_phase_protocol",
        "canonical_prepared_broker_batch_bytes",
    ),
    "execute_prepared_broker_outer": (
        "tools.ai_review.broker_outer_executor",
        "execute_prepared_broker_outer",
    ),
    "finalize_provisioned_broker_execution": (
        "tools.ai_review.broker_phase_protocol",
        "finalize_provisioned_broker_execution",
    ),
    "inspect_git_diff": ("tools.ai_review.policy", "inspect_git_diff"),
    "judge": ("tools.ai_review.judge", "judge"),
    "measure_broker_outer_runtime": (
        "tools.ai_review.broker_outer_executor",
        "measure_broker_outer_runtime",
    ),
    "prepare_broker_outer_ledger": (
        "tools.ai_review.broker_outer_executor",
        "prepare_broker_outer_ledger",
    ),
    "prepare_provisioned_broker_execution": (
        "tools.ai_review.broker_phase_protocol",
        "prepare_provisioned_broker_execution",
    ),
}


def __getattr__(name: str) -> Any:
    """Load convenience exports only when a caller explicitly requests one."""

    try:
        module_name, attribute = _EXPORTS[name]
    except KeyError as exc:
        raise AttributeError(name) from exc
    value = getattr(import_module(module_name), attribute)
    globals()[name] = value
    return value
