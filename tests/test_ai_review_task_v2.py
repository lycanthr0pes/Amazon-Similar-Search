from __future__ import annotations

import pytest
from pydantic import ValidationError

from tools.ai_review.models import TaskSpec


def task_payload() -> dict:
    return {
        "schema_version": "2.0",
        "task_id": "TASK-V2",
        "base_sha": "1" * 40,
        "trusted_harness_sha256": "2" * 64,
        "objective": "exact test pathsをtaskへ固定する",
        "requirements": [{"id": "REQ-1", "text": "REDとGREENで同じテストを使う"}],
        "review_prompts": {
            "reviewer_sha256": "3" * 64,
            "adversary_sha256": "4" * 64,
        },
        "candidate_commit": {
            "message": "TASK-V2",
            "author_name": "AI Review Coordinator",
            "author_email": "review@example.invalid",
            "timestamp": 946684800,
            "timezone": "+0000",
        },
        "acceptance_tests": [
            {
                "id": "AT-TEST",
                "kind": "test",
                "command": ["pytest", "tests/test_feature.py"],
                "expected_exit_code": 0,
                "expected_red_exit_codes": [1],
                "expected_red_fingerprint_sha256": "5" * 64,
                "test_paths": ["tests/test_feature.py"],
            }
        ],
        "allowed_paths": ["src/**", "tests/**"],
        "denied_paths": [".env", "cache/**"],
        "limits": {"max_changed_files": 10, "max_added_lines": 100},
        "network_policy": "deny",
    }


def test_task_v2_requires_exact_test_paths() -> None:
    payload = task_payload()
    payload["acceptance_tests"][0].pop("test_paths")

    with pytest.raises(ValidationError, match="exact test_paths"):
        TaskSpec.model_validate(payload)


def test_task_v2_rejects_test_paths_outside_tests() -> None:
    payload = task_payload()
    payload["acceptance_tests"][0]["test_paths"] = ["src/feature.py"]

    with pytest.raises(ValidationError, match="below tests"):
        TaskSpec.model_validate(payload)


def test_task_v1_remains_diagnostic_compatible_without_test_paths() -> None:
    payload = task_payload()
    payload["schema_version"] = "1.0"
    payload["acceptance_tests"][0].pop("test_paths")

    assert TaskSpec.model_validate(payload).schema_version == "1.0"


def test_task_v2_canonicalizes_test_path_order() -> None:
    payload = task_payload()
    payload["acceptance_tests"][0]["test_paths"] = [
        "tests/test_z.py",
        "tests/test_a.py",
    ]

    task = TaskSpec.model_validate(payload)

    assert task.acceptance_tests[0].test_paths == [
        "tests/test_a.py",
        "tests/test_z.py",
    ]
