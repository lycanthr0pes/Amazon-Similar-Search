from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import zlib
from pathlib import Path

import pytest
from pydantic import ValidationError

import tools.ai_review.policy as ai_policy
from tools.ai_review.codex_adapter import CodexAdapter
from tools.ai_review.codex_adapter import CodexInvocation
from tools.ai_review.build_zipapp import build_trusted_zipapp
from tools.ai_review.judge import build_test_manifest_sha256
from tools.ai_review.judge import judge as _judge
from tools.ai_review.models import Finding
from tools.ai_review.models import DiffFile
from tools.ai_review.models import GateResult
from tools.ai_review.models import PolicyReport
from tools.ai_review.models import ReviewReport
from tools.ai_review.models import TaskSpec
from tools.ai_review.models import TddEvidence
from tools.ai_review.models import Verdict
from tools.ai_review.cli import _load_json
from tools.ai_review.cli import _reinspect_policy
from tools.ai_review.cli import _write_json
from tools.ai_review.cli import main
from tools.ai_review.policy import inspect_git_diff as _inspect_git_diff
from tools.ai_review.policy import GitInspectionError
from tools.ai_review.trusted_runtime import RuntimeTrustError
from tools.ai_review.trusted_runtime import verify_trusted_zipapp


BASE_SHA = "1" * 40
PATCH_SHA = "2" * 64
HEAD_SHA = "3" * 40
HARNESS_SHA = "c" * 64
TASK_SHA = "f" * 64
CANONICAL_COMMIT_ENV = {
    "GIT_AUTHOR_DATE": "2000-01-01T00:00:00+00:00",
    "GIT_COMMITTER_DATE": "2000-01-01T00:00:00+00:00",
}


def inspect_git_diff(repo: Path, task: TaskSpec, **kwargs) -> PolicyReport:
    return _inspect_git_diff(repo, task, task_sha256=TASK_SHA, **kwargs)


def judge(task, policy, reviews, gates, tdd) -> Verdict:
    return _judge(task, policy, reviews, gates, tdd, task_sha256=TASK_SHA)


def task_payload(base_sha: str = BASE_SHA) -> dict:
    return {
        "schema_version": "1.0",
        "task_id": "TASK-TEST",
        "base_sha": base_sha,
        "trusted_harness_sha256": HARNESS_SHA,
        "objective": "回帰をテスト先行で修正する",
        "requirements": [{"id": "REQ-1", "text": "期待する結果を返す"}],
        "review_prompts": {
            "reviewer_sha256": "a" * 64,
            "adversary_sha256": "b" * 64,
        },
        "candidate_commit": {
            "message": "TASK-TEST",
            "author_name": "Harness Test",
            "author_email": "test@example.com",
            "timestamp": 946_684_800,
            "timezone": "+0000",
        },
        "acceptance_tests": [
            {
                "id": "AT-1",
                "kind": "test",
                "command": ["uv", "run", "pytest", "tests/test_example.py"],
                "expected_exit_code": 0,
                "expected_red_exit_codes": [1],
                "expected_red_fingerprint_sha256": "7" * 64,
            }
        ],
        "allowed_paths": ["src/**", "tests/**"],
        "denied_paths": ["**/*.pdf", "uv.lock"],
        "limits": {
            "max_changed_files": 2,
            "max_added_lines": 10,
            "max_file_bytes": 1_000_000,
            "max_total_bytes": 2_000_000,
        },
        "network_policy": "deny",
        "out_of_scope": ["UI変更"],
    }


def run_git(repo: Path, *args: str, extra_env: dict[str, str] | None = None) -> str:
    environment = None
    if extra_env is not None:
        environment = os.environ.copy()
        environment.update(extra_env)
    result = subprocess.run(
        ["git", *args],
        cwd=repo,
        check=True,
        capture_output=True,
        env=environment,
        text=True,
        shell=False,
    )
    return result.stdout.strip()


def init_repo(tmp_path: Path) -> tuple[Path, str]:
    repo = tmp_path / "repo"
    repo.mkdir()
    run_git(repo, "init", "-q")
    run_git(repo, "config", "user.email", "test@example.com")
    run_git(repo, "config", "user.name", "Harness Test")
    (repo / "src").mkdir()
    (repo / "src" / "example.py").write_text("VALUE = 1\n", encoding="utf-8")
    run_git(repo, "add", "src/example.py")
    run_git(repo, "commit", "-qm", "base")
    return repo, run_git(repo, "rev-parse", "HEAD")


def commit_all(repo: Path, message: str = "TASK-TEST") -> str:
    run_git(repo, "add", "-A")
    run_git(repo, "commit", "-qm", message, extra_env=CANONICAL_COMMIT_ENV)
    return run_git(repo, "rev-parse", "HEAD")


def replace_loose_object(repo: Path, object_id: str, object_type: str, content: bytes) -> None:
    object_path = repo / ".git" / "objects" / object_id[:2] / object_id[2:]
    object_path.chmod(0o644)
    header = f"{object_type} {len(content)}\0".encode("ascii")
    object_path.write_bytes(zlib.compress(header + content))
    object_path.chmod(0o444)


def passing_policy() -> PolicyReport:
    return PolicyReport(
        task_id="TASK-TEST",
        task_sha256=TASK_SHA,
        passed=True,
        trusted_harness_sha256=HARNESS_SHA,
        base_sha=BASE_SHA,
        head_sha=HEAD_SHA,
        patch_sha256=PATCH_SHA,
        changed_files=[
            DiffFile(
                path="src/example.py",
                status="M",
                additions=1,
                deletions=0,
                binary=False,
                content_sha256="d" * 64,
            ),
            DiffFile(
                path="tests/test_example.py",
                status="A",
                additions=1,
                deletions=0,
                binary=False,
                content_sha256="e" * 64,
            ),
        ],
        total_added_lines=2,
        violations=[],
    )


def accepting_review(role: str) -> ReviewReport:
    return ReviewReport(
        task_id="TASK-TEST",
        task_sha256=TASK_SHA,
        role=role,
        reviewer_id=f"agent-{role}",
        session_id=f"session-{role}",
        prompt_sha256=("a" if role == "reviewer" else "b") * 64,
        decision="accept",
        base_sha=BASE_SHA,
        head_sha=HEAD_SHA,
        patch_sha256=PATCH_SHA,
        summary="問題を確認できなかった",
        findings=[],
        unverified=[],
        external_calls=False,
    )


def passing_tdd() -> TddEvidence:
    test_patch_sha256 = "4" * 64
    return TddEvidence(
        schema_version="2.0",
        task_id="TASK-TEST",
        task_sha256=TASK_SHA,
        base_sha=BASE_SHA,
        head_sha=HEAD_SHA,
        patch_sha256=PATCH_SHA,
        acceptance_test_id="AT-1",
        command=["uv", "run", "pytest", "tests/test_example.py"],
        test_paths=["tests/test_example.py"],
        test_manifest_sha256=build_test_manifest_sha256(
            passing_policy(), ["tests/test_example.py"]
        ),
        test_patch_sha256=test_patch_sha256,
        red_snapshot_sha256="8" * 64,
        green_snapshot_sha256="a" * 64,
        red={
            "exit_code": 1,
            "log_sha256": "5" * 64,
            "failure_fingerprint_sha256": "7" * 64,
            "test_patch_sha256": test_patch_sha256,
        },
        green={
            "exit_code": 0,
            "log_sha256": "6" * 64,
            "test_patch_sha256": test_patch_sha256,
        },
    )


def passing_gate() -> GateResult:
    return GateResult(
        task_id="TASK-TEST",
        task_sha256=TASK_SHA,
        head_sha=HEAD_SHA,
        patch_sha256=PATCH_SHA,
        acceptance_test_id="AT-1",
        command=["uv", "run", "pytest", "tests/test_example.py"],
        expected_exit_code=0,
        passed=True,
        exit_code=0,
        evidence_sha256="9" * 64,
    )


def test_task_and_review_contracts_reject_unknown_or_unsafe_values():
    payload = task_payload()
    payload["unexpected"] = True
    with pytest.raises(ValidationError):
        TaskSpec.model_validate(payload)

    with pytest.raises(ValidationError):
        TaskSpec.model_validate({**task_payload(), "network_policy": "allow"})

    with pytest.raises(ValidationError):
        TaskSpec.model_validate({**task_payload(), "allowed_paths": ["../src/**"]})

    review = accepting_review("reviewer").model_dump()
    review["external_calls"] = True
    with pytest.raises(ValidationError):
        ReviewReport.model_validate(review)

    tdd = passing_tdd().model_dump()
    tdd["unexpected"] = True
    with pytest.raises(ValidationError):
        TddEvidence.model_validate(tdd)


def test_json_loader_rejects_duplicate_object_keys(tmp_path):
    payload = tmp_path / "duplicate.json"
    payload.write_text('{"passed": true, "passed": false}\n', encoding="utf-8")

    with pytest.raises(ValueError, match="duplicate JSON key"):
        _load_json(payload)


def test_structured_input_requires_private_artifact_root_and_fixed_task_hash(tmp_path):
    artifact_root = tmp_path / "artifacts"
    artifact_root.mkdir(mode=0o700)
    task = artifact_root / "task.json"
    task.write_text("{}\n", encoding="utf-8")

    with pytest.raises(ValueError, match="task SHA-256"):
        _load_json(task, trusted_root=artifact_root, expected_sha256="0" * 64)

    candidate_task = tmp_path / "candidate-task.json"
    candidate_task.write_text("{}\n", encoding="utf-8")
    with pytest.raises(ValueError, match="trusted artifact root"):
        _load_json(candidate_task, trusted_root=artifact_root)


def test_structured_input_rejects_hardlink_into_artifact_root(tmp_path):
    artifact_root = tmp_path / "artifacts"
    artifact_root.mkdir(mode=0o700)
    candidate = tmp_path / "candidate.json"
    candidate.write_text("{}\n", encoding="utf-8")
    linked = artifact_root / "task.json"
    os.link(candidate, linked)

    with pytest.raises(ValueError, match="hardlink"):
        _load_json(linked, trusted_root=artifact_root)


def test_cli_validation_error_never_echoes_input_values(tmp_path, capsys):
    artifact_root = tmp_path / "artifacts"
    artifact_root.mkdir(mode=0o700)
    candidate = tmp_path / "candidate"
    candidate.mkdir()
    task = artifact_root / "task.json"
    task.write_text('{"unexpected": "SUPERSECRET"}\n', encoding="utf-8")
    task_sha256 = hashlib.sha256(task.read_bytes()).hexdigest()

    exit_code = main(
        [
            "policy",
            "--task",
            str(task),
            "--repo",
            str(candidate),
            "--artifact-root",
            str(artifact_root),
            "--expected-task-sha256",
            task_sha256,
        ]
    )

    captured = capsys.readouterr()
    assert exit_code == 2
    assert "SUPERSECRET" not in captured.err
    assert "extra_forbidden" in captured.err


def test_policy_cli_rejects_source_tree_execution_instead_of_trusted_zipapp(tmp_path, capsys):
    artifact_root = tmp_path / "artifacts"
    artifact_root.mkdir(mode=0o700)
    candidate, base_sha = init_repo(tmp_path)
    task = artifact_root / "task.json"
    task.write_text(json.dumps(task_payload(base_sha)) + "\n", encoding="utf-8")
    task_sha256 = hashlib.sha256(task.read_bytes()).hexdigest()

    exit_code = main(
        [
            "policy",
            "--task",
            str(task),
            "--repo",
            str(candidate),
            "--artifact-root",
            str(artifact_root),
            "--expected-task-sha256",
            task_sha256,
        ]
    )

    captured = capsys.readouterr()
    assert exit_code == 2
    assert "isolated Python (-I)" in captured.err


@pytest.mark.parametrize(
    ("model_type", "payload"),
    [
        (PolicyReport, {**passing_policy().model_dump(), "passed": "yes"}),
        (ReviewReport, {**accepting_review("reviewer").model_dump(), "external_calls": "no"}),
        (GateResult, {**passing_gate().model_dump(), "passed": "yes"}),
    ],
)
def test_json_contracts_reject_boolean_string_coercion(model_type, payload):
    with pytest.raises(ValidationError):
        model_type.model_validate(payload)


@pytest.mark.parametrize(
    ("passed", "exit_code"),
    [(True, 1), (False, 0)],
)
def test_gate_result_rejects_exit_code_contradictions(passed, exit_code):
    with pytest.raises(ValidationError, match="contradicts"):
        GateResult(
            task_id="TASK-TEST",
            task_sha256=TASK_SHA,
            head_sha=HEAD_SHA,
            patch_sha256=PATCH_SHA,
            acceptance_test_id="AT-1",
            command=["uv", "run", "pytest", "tests/test_example.py"],
            expected_exit_code=0,
            passed=passed,
            exit_code=exit_code,
            evidence_sha256="9" * 64,
        )


def test_inspect_git_diff_accepts_allowed_text_change_and_verifies_hash(tmp_path):
    repo, base_sha = init_repo(tmp_path)
    (repo / "src" / "example.py").write_text("VALUE = 1\nVALUE = 2\n", encoding="utf-8")
    head_sha = commit_all(repo)
    task = TaskSpec.model_validate(task_payload(base_sha))

    initial = inspect_git_diff(repo, task)
    expected_hash = initial.patch_sha256
    assert expected_hash is not None
    report = inspect_git_diff(repo, task, expected_patch_sha256=expected_hash)

    assert report.passed is True
    assert report.patch_sha256 == expected_hash
    assert report.head_sha == head_sha
    assert report.total_added_lines == 1
    assert [item.path for item in report.changed_files] == ["src/example.py"]

    mismatch = inspect_git_diff(repo, task, expected_patch_sha256="f" * 64)
    assert mismatch.passed is False
    assert "patch SHA-256 does not match the expected value" in mismatch.violations


def test_inspect_git_diff_rejects_replace_refs(tmp_path):
    repo, base_sha = init_repo(tmp_path)
    (repo / ".env").write_text("OUTSCRAPER_API_KEY=must-not-be-read\n", encoding="utf-8")
    malicious_head = commit_all(repo, "actual candidate")

    run_git(repo, "reset", "--hard", base_sha)
    (repo / "src" / "example.py").write_text("VALUE = 2\n", encoding="utf-8")
    benign_head = commit_all(repo, "replacement candidate")
    run_git(repo, "replace", malicious_head, benign_head)
    run_git(repo, "reset", "--hard", malicious_head)

    task = TaskSpec.model_validate(task_payload(base_sha))
    with pytest.raises(GitInspectionError, match="replace ref"):
        inspect_git_diff(repo, task)


def test_inspect_git_diff_ignores_external_diff_configuration(tmp_path, monkeypatch):
    repo, base_sha = init_repo(tmp_path)
    (repo / "src" / "example.py").write_text("VALUE = 2\n", encoding="utf-8")
    commit_all(repo)
    run_git(repo, "config", "diff.external", "/bin/true")
    monkeypatch.setenv("GIT_EXTERNAL_DIFF", "/bin/true")

    task = TaskSpec.model_validate(task_payload(base_sha))
    report = inspect_git_diff(repo, task)
    monkeypatch.delenv("GIT_EXTERNAL_DIFF")
    run_git(repo, "config", "--unset", "diff.external")
    trusted = inspect_git_diff(repo, task)

    assert report.passed is True
    assert report.patch_sha256 == trusted.patch_sha256
    assert report.patch_sha256 != hashlib.sha256(b"").hexdigest()


def test_inspect_git_diff_requires_one_direct_squash_commit(tmp_path):
    repo, base_sha = init_repo(tmp_path)
    (repo / ".env").write_text("OUTSCRAPER_API_KEY=must-not-be-read\n", encoding="utf-8")
    commit_all(repo, "intermediate secret")
    (repo / ".env").unlink()
    (repo / "src" / "example.py").write_text("VALUE = 2\n", encoding="utf-8")
    commit_all(repo, "hide intermediate secret")

    task = TaskSpec.model_validate(task_payload(base_sha))
    with pytest.raises(GitInspectionError, match="single squash commit"):
        inspect_git_diff(repo, task)


def test_policy_rejects_candidate_controlled_commit_message(tmp_path):
    repo, base_sha = init_repo(tmp_path)
    (repo / "src" / "example.py").write_text("VALUE = 2\n", encoding="utf-8")
    commit_all(repo, "candidate-controlled metadata")

    report = inspect_git_diff(repo, TaskSpec.model_validate(task_payload(base_sha)))

    assert report.passed is False
    assert "candidate commit message does not match the task contract" in report.violations


def test_policy_rejects_dirty_or_untracked_candidate_worktree(tmp_path):
    repo, base_sha = init_repo(tmp_path)
    (repo / "src" / "example.py").write_text("VALUE = 2\n", encoding="utf-8")
    commit_all(repo)
    (repo / "src" / "example.py").write_text("UNCOMMITTED = True\n", encoding="utf-8")

    with pytest.raises(GitInspectionError, match="worktree content differs from HEAD"):
        inspect_git_diff(repo, TaskSpec.model_validate(task_payload(base_sha)))


@pytest.mark.parametrize("index_flag", ["--assume-unchanged", "--skip-worktree"])
def test_policy_rejects_index_flags_that_hide_dirty_files(tmp_path, index_flag):
    repo, base_sha = init_repo(tmp_path)
    (repo / "src" / "example.py").write_text("VALUE = 2\n", encoding="utf-8")
    commit_all(repo)
    run_git(repo, "update-index", index_flag, "src/example.py")
    (repo / "src" / "example.py").write_text("HIDDEN = 'malicious'\n", encoding="utf-8")

    with pytest.raises(GitInspectionError, match="index flags"):
        inspect_git_diff(repo, TaskSpec.model_validate(task_payload(base_sha)))


def test_policy_detects_worktree_mode_change_despite_local_config(tmp_path):
    repo, base_sha = init_repo(tmp_path)
    (repo / "src" / "example.py").write_text("VALUE = 2\n", encoding="utf-8")
    commit_all(repo)
    run_git(repo, "config", "core.filemode", "false")
    (repo / "src" / "example.py").chmod(0o755)

    with pytest.raises(GitInspectionError, match="tracked file mode differs from HEAD"):
        inspect_git_diff(repo, TaskSpec.model_validate(task_payload(base_sha)))


def test_policy_glob_star_does_not_cross_directory_boundaries(tmp_path):
    repo, base_sha = init_repo(tmp_path)
    nested = repo / "src" / "nested"
    nested.mkdir()
    (nested / "example.py").write_text("VALUE = 2\n", encoding="utf-8")
    commit_all(repo)
    payload = task_payload(base_sha)
    payload["allowed_paths"] = ["src/*.py"]
    task = TaskSpec.model_validate(payload)

    report = inspect_git_diff(repo, task)

    assert report.passed is False
    assert "path is outside allowed_paths: src/nested/example.py" in report.violations


def test_policy_denies_nested_pdf_with_double_star_pattern(tmp_path):
    repo, base_sha = init_repo(tmp_path)
    docs = repo / "docs"
    docs.mkdir()
    (docs / "restored.pdf").write_text("stale document\n", encoding="utf-8")
    commit_all(repo)
    payload = task_payload(base_sha)
    payload["allowed_paths"] = ["docs/**"]

    report = inspect_git_diff(repo, TaskSpec.model_validate(payload))

    assert report.passed is False
    assert "denied path changed: docs/restored.pdf" in report.violations


def test_policy_denies_pdf_case_insensitively(tmp_path):
    repo, base_sha = init_repo(tmp_path)
    (repo / "docs").mkdir()
    (repo / "docs" / "stale.PDF").write_text("%PDF plain text marker\n", encoding="utf-8")
    commit_all(repo)
    payload = task_payload(base_sha)
    payload["allowed_paths"] = ["docs/**"]
    payload["limits"]["max_changed_files"] = 4
    task = TaskSpec.model_validate(payload)

    report = inspect_git_diff(repo, task)

    assert report.passed is False
    assert "denied path changed: docs/stale.PDF" in report.violations


def test_policy_rejects_mode_only_changes(tmp_path):
    repo, base_sha = init_repo(tmp_path)
    (repo / "src" / "example.py").chmod(0o755)
    commit_all(repo)

    report = inspect_git_diff(repo, TaskSpec.model_validate(task_payload(base_sha)))

    assert report.passed is False
    assert "file mode changes are not supported: src/example.py" in report.violations


def test_policy_treats_modified_copy_as_a_new_file_without_git_similarity_drivers(tmp_path):
    repo, base_sha = init_repo(tmp_path)
    original = "".join(f"LINE_{index:02d} = {index}\n" for index in range(40))
    (repo / "src" / "example.py").write_text(original, encoding="utf-8")
    for index in range(20):
        (repo / "src" / f"decoy_{index:02d}.py").write_text(f"DECOY = {index}\n", encoding="utf-8")
    run_git(repo, "add", "src")
    run_git(repo, "commit", "--amend", "--no-edit", extra_env=CANONICAL_COMMIT_ENV)
    base_sha = run_git(repo, "rev-parse", "HEAD")
    copied = original.replace("LINE_20 = 20", "LINE_20 = 999")
    (repo / "src" / "near_copy.py").write_text(copied, encoding="utf-8")
    commit_all(repo)
    run_git(repo, "config", "diff.renameLimit", "1")
    payload = task_payload(base_sha)
    payload["limits"]["max_added_lines"] = 100

    report = inspect_git_diff(repo, TaskSpec.model_validate(payload))

    assert report.passed is True


def test_policy_detects_binary_blob_even_when_attributes_force_text(tmp_path):
    repo, base_sha = init_repo(tmp_path)
    (repo / ".gitattributes").write_text("*.bin diff\n", encoding="utf-8")
    run_git(repo, "add", ".gitattributes")
    run_git(repo, "commit", "-qm", "trusted attributes")
    base_sha = run_git(repo, "rev-parse", "HEAD")
    (repo / "src" / "payload.bin").write_bytes(b"safe-looking\x00payload")
    commit_all(repo)
    payload = task_payload(base_sha)
    payload["allowed_paths"] = ["src/**"]

    report = inspect_git_diff(repo, TaskSpec.model_validate(payload))

    assert report.passed is False
    assert "binary diff is not supported: src/payload.bin" in report.violations


def test_policy_rejects_large_single_line_blob_before_patch_generation(tmp_path):
    repo, base_sha = init_repo(tmp_path)
    (repo / "src" / "example.py").write_text("X" * 128, encoding="utf-8")
    commit_all(repo)
    payload = task_payload(base_sha)
    payload["limits"]["max_file_bytes"] = 64
    payload["limits"]["max_total_bytes"] = 64

    report = inspect_git_diff(repo, TaskSpec.model_validate(payload))

    assert report.passed is False
    assert "file size 128 exceeds 64: src/example.py" in report.violations
    assert report.patch_sha256 is None


@pytest.mark.parametrize("environment_name", [".env", ".env.local"])
def test_inspect_git_diff_fails_closed_for_protected_env_without_hashing_patch(
    tmp_path, environment_name
):
    repo, base_sha = init_repo(tmp_path)
    (repo / environment_name).write_text("OUTSCRAPER_API_KEY=must-not-be-read\n", encoding="utf-8")
    commit_all(repo)
    task = TaskSpec.model_validate(task_payload(base_sha))

    report = inspect_git_diff(repo, task)

    assert report.passed is False
    assert report.patch_sha256 is None
    assert f"protected path changed: {environment_name}" in report.violations


def test_protected_diff_stops_before_copy_cleanliness_and_blob_inspection(tmp_path, monkeypatch):
    repo, base_sha = init_repo(tmp_path)
    (repo / ".env").write_text("OUTSCRAPER_API_KEY=must-not-be-read\n", encoding="utf-8")
    commit_all(repo)
    payload = task_payload(base_sha)
    payload["allowed_paths"] = [".env"]

    def unexpected_inspection(*args, **kwargs):
        raise AssertionError("protected content must stop all later inspection")

    monkeypatch.setattr(ai_policy, "_base_blob_paths", unexpected_inspection)
    monkeypatch.setattr(ai_policy, "_reject_dirty_worktree", unexpected_inspection)
    monkeypatch.setattr(ai_policy, "_blob_size", unexpected_inspection)
    report = inspect_git_diff(repo, TaskSpec.model_validate(payload))

    assert report.passed is False
    assert report.patch_sha256 is None
    assert "protected path changed: .env" in report.violations


def test_inspect_git_diff_rejects_env_example_even_when_task_explicitly_allows_it(tmp_path):
    repo, base_sha = init_repo(tmp_path)
    (repo / ".env.example").write_text("OUTSCRAPER_API_KEY=\n", encoding="utf-8")
    commit_all(repo)
    payload = task_payload(base_sha)
    payload["allowed_paths"] = [".env.example"]
    task = TaskSpec.model_validate(payload)

    report = inspect_git_diff(repo, task)

    assert report.passed is False
    assert "protected path changed: .env.example" in report.violations
    assert report.patch_sha256 is None


def test_inspect_git_diff_accepts_unchanged_empty_env_example_baseline(tmp_path):
    repo, _initial = init_repo(tmp_path)
    (repo / ".env.example").write_text("OUTSCRAPER_API_KEY=\n", encoding="utf-8")
    run_git(repo, "add", ".env.example")
    run_git(repo, "commit", "-qm", "safe template")
    base_sha = run_git(repo, "rev-parse", "HEAD")
    (repo / "src" / "example.py").write_text("VALUE = 2\n", encoding="utf-8")
    commit_all(repo)

    report = inspect_git_diff(repo, TaskSpec.model_validate(task_payload(base_sha)))

    assert report.passed is True


def test_inspect_git_diff_rejects_configured_env_example_baseline_without_echo(tmp_path):
    repo, _initial = init_repo(tmp_path)
    (repo / ".env.example").write_text(
        "OUTSCRAPER_API_KEY=live-value-must-not-appear\n",
        encoding="utf-8",
    )
    run_git(repo, "add", ".env.example")
    run_git(repo, "commit", "-qm", "unsafe template")
    base_sha = run_git(repo, "rev-parse", "HEAD")
    (repo / "src" / "example.py").write_text("VALUE = 2\n", encoding="utf-8")
    commit_all(repo)

    with pytest.raises(GitInspectionError, match="not a safe empty template") as captured:
        inspect_git_diff(repo, TaskSpec.model_validate(task_payload(base_sha)))

    assert "live-value" not in str(captured.value)


def test_inspect_git_diff_enforces_path_count_line_limit_and_patch_claim(tmp_path):
    repo, base_sha = init_repo(tmp_path)
    (repo / "src" / "example.py").write_text("VALUE = 1\nA = 1\nB = 2\n", encoding="utf-8")
    (repo / "README.md").write_text("outside\n", encoding="utf-8")
    commit_all(repo)
    payload = task_payload(base_sha)
    payload["limits"] = {"max_changed_files": 1, "max_added_lines": 1}
    task = TaskSpec.model_validate(payload)

    report = inspect_git_diff(repo, task, expected_patch_sha256="f" * 64)

    assert report.passed is False
    assert "path is outside allowed_paths: README.md" in report.violations
    assert "changed file count 2 exceeds 1" in report.violations
    assert report.patch_sha256 is None
    assert "patch SHA-256 was not computed because restricted content changed" in report.violations


def test_inspect_git_diff_rejects_delete_rename_binary_and_gitlink(tmp_path):
    repo, base_sha = init_repo(tmp_path)
    (repo / "src" / "example.py").unlink()
    commit_all(repo, "delete")
    task = TaskSpec.model_validate(task_payload(base_sha))
    deletion = inspect_git_diff(repo, task)
    assert deletion.passed is False
    assert "unsupported Git status D: src/example.py" in deletion.violations

    run_git(repo, "reset", "--hard", base_sha)
    run_git(repo, "mv", "src/example.py", "src/renamed.py")
    commit_all(repo, "rename")
    rename = inspect_git_diff(repo, task)
    assert rename.passed is False
    assert any(violation.startswith("unsupported Git status D:") for violation in rename.violations)

    run_git(repo, "reset", "--hard", base_sha)
    (repo / "src" / "copy.py").write_text("VALUE = 1\n", encoding="utf-8")
    commit_all(repo)
    copied = inspect_git_diff(repo, task)
    assert copied.passed is False
    assert "Git copy is not supported: src/example.py -> src/copy.py" in copied.violations

    run_git(repo, "reset", "--hard", base_sha)
    (repo / "src" / "binary.bin").write_bytes(b"\x00binary")
    commit_all(repo)
    binary = inspect_git_diff(repo, task)
    assert binary.passed is False
    assert "binary diff is not supported: src/binary.bin" in binary.violations

    run_git(repo, "reset", "--hard", base_sha)
    (repo / "src" / "example.py").unlink()
    (repo / "src" / "example.py").symlink_to("target.py")
    commit_all(repo)
    type_change = inspect_git_diff(repo, task)
    assert type_change.passed is False
    assert "unsupported Git status T: src/example.py" in type_change.violations
    assert "unsupported Git file mode 120000: src/example.py" in type_change.violations


def test_policy_ignores_local_submodule_suppression_and_rejects_gitlink(tmp_path):
    repo, base_sha = init_repo(tmp_path)
    (repo / "src" / "example.py").write_text("VALUE = 2\n", encoding="utf-8")
    run_git(repo, "add", "src/example.py")
    run_git(repo, "update-index", "--add", "--cacheinfo", f"160000,{base_sha},src/vendor")
    run_git(repo, "commit", "-qm", "TASK-TEST", extra_env=CANONICAL_COMMIT_ENV)
    run_git(repo, "config", "diff.ignoreSubmodules", "all")

    report = inspect_git_diff(repo, TaskSpec.model_validate(task_payload(base_sha)))

    assert report.passed is False
    assert any("src/vendor" in violation for violation in report.violations)
    assert "unsupported Git file mode 160000: src/vendor" in report.violations


def test_policy_rejects_git_attribute_filter_without_executing_it(tmp_path):
    repo, base_sha = init_repo(tmp_path)
    (repo / "src" / "example.py").write_text("VALUE = 2\n", encoding="utf-8")
    commit_all(repo)
    marker = repo / "filter-executed"
    attributes = repo / ".git" / "info" / "attributes"
    attributes.write_text("src/example.py filter=evil\n", encoding="utf-8")
    run_git(repo, "config", "filter.evil.clean", f"touch {marker}")

    with pytest.raises(GitInspectionError, match="shared or external metadata"):
        inspect_git_diff(repo, TaskSpec.model_validate(task_payload(base_sha)))

    assert not marker.exists()


def test_policy_rejects_external_git_common_directory(tmp_path):
    repo, base_sha = init_repo(tmp_path)
    (repo / "src" / "example.py").write_text("VALUE = 2\n", encoding="utf-8")
    commit_all(repo)
    git_directory = repo / ".git"
    external_common = tmp_path / "external-common"
    git_directory.rename(external_common)
    git_directory.mkdir()
    shutil.copy2(external_common / "HEAD", git_directory / "HEAD")
    shutil.copy2(external_common / "index", git_directory / "index")
    relative_common = os.path.relpath(external_common, git_directory)
    (git_directory / "commondir").write_text(relative_common + "\n", encoding="utf-8")

    with pytest.raises(GitInspectionError, match="shared or external metadata"):
        inspect_git_diff(repo, TaskSpec.model_validate(task_payload(base_sha)))


def test_policy_rejects_symlinked_or_hardlinked_git_metadata(tmp_path):
    repo, base_sha = init_repo(tmp_path)
    (repo / "src" / "example.py").write_text("VALUE = 2\n", encoding="utf-8")
    commit_all(repo)
    git_directory = repo / ".git"
    external_objects = tmp_path / "external-objects"
    (git_directory / "objects").rename(external_objects)
    (git_directory / "objects").symlink_to(external_objects, target_is_directory=True)

    with pytest.raises(GitInspectionError, match="must not contain symlinks"):
        inspect_git_diff(repo, TaskSpec.model_validate(task_payload(base_sha)))

    (git_directory / "objects").unlink()
    external_objects.rename(git_directory / "objects")
    external_head = tmp_path / "external-head"
    shutil.copy2(git_directory / "HEAD", external_head)
    (git_directory / "HEAD").unlink()
    os.link(external_head, git_directory / "HEAD")

    with pytest.raises(GitInspectionError, match="must not be hardlinks"):
        inspect_git_diff(repo, TaskSpec.model_validate(task_payload(base_sha)))


def test_policy_rejects_loose_blob_whose_content_does_not_match_object_id(tmp_path):
    repo, base_sha = init_repo(tmp_path)
    tracked = repo / "src" / "example.py"
    tracked.write_text("VALUE = 2\n", encoding="utf-8")
    commit_all(repo)
    blob_id = run_git(repo, "rev-parse", "HEAD:src/example.py")
    replace_loose_object(repo, blob_id, "blob", b"MALICIOUS = True\n")

    with pytest.raises(GitInspectionError, match="blob content does not match its object id"):
        inspect_git_diff(repo, TaskSpec.model_validate(task_payload(base_sha)))


def test_policy_rejects_loose_commit_whose_content_does_not_match_object_id(tmp_path):
    repo, base_sha = init_repo(tmp_path)
    (repo / "src" / "example.py").write_text("VALUE = 2\n", encoding="utf-8")
    commit_all(repo)
    base_content = subprocess.run(
        ["git", "cat-file", "commit", base_sha],
        cwd=repo,
        check=True,
        capture_output=True,
    ).stdout
    replace_loose_object(repo, base_sha, "commit", base_content + b"tampered\n")

    with pytest.raises(GitInspectionError, match="hash mismatch|commit content does not match"):
        inspect_git_diff(repo, TaskSpec.model_validate(task_payload(base_sha)))


def test_policy_rejects_loose_tree_whose_content_does_not_match_object_id(tmp_path):
    repo, base_sha = init_repo(tmp_path)
    (repo / "src" / "example.py").write_text("VALUE = 2\n", encoding="utf-8")
    commit_all(repo)
    tree_id = run_git(repo, "rev-parse", f"{base_sha}^{{tree}}")
    tree_content = subprocess.run(
        ["git", "cat-file", "tree", tree_id],
        cwd=repo,
        check=True,
        capture_output=True,
    ).stdout
    replace_loose_object(repo, tree_id, "tree", tree_content + b"tampered")

    with pytest.raises(GitInspectionError, match="tree content does not match its object id"):
        inspect_git_diff(repo, TaskSpec.model_validate(task_payload(base_sha)))


def test_policy_rejects_tracked_parent_directory_symlink(tmp_path):
    repo, base_sha = init_repo(tmp_path)
    (repo / "src" / "example.py").write_text("VALUE = 2\n", encoding="utf-8")
    commit_all(repo)
    outside = tmp_path / "outside-src"
    (repo / "src").rename(outside)
    (repo / "src").symlink_to(outside, target_is_directory=True)
    (outside / "untracked-secret.txt").write_text("must-not-be-read\n", encoding="utf-8")

    with pytest.raises(GitInspectionError, match="must not contain symlinks"):
        inspect_git_diff(repo, TaskSpec.model_validate(task_payload(base_sha)))


def test_policy_rejects_tracked_worktree_hardlink(tmp_path):
    repo, base_sha = init_repo(tmp_path)
    tracked = repo / "src" / "example.py"
    tracked.write_text("VALUE = 2\n", encoding="utf-8")
    commit_all(repo)
    outside = tmp_path / "outside-source.py"
    outside.write_text("VALUE = 2\n", encoding="utf-8")
    tracked.unlink()
    os.link(outside, tracked)

    with pytest.raises(GitInspectionError, match="must not be a hardlink"):
        inspect_git_diff(repo, TaskSpec.model_validate(task_payload(base_sha)))


def test_policy_stops_before_blob_reads_when_path_count_exceeds_limit(tmp_path, monkeypatch):
    repo, base_sha = init_repo(tmp_path)
    (repo / "src" / "example.py").write_text("VALUE = 2\n", encoding="utf-8")
    (repo / "src" / "one.py").write_text("ONE = 1\n", encoding="utf-8")
    (repo / "src" / "two.py").write_text("TWO = 2\n", encoding="utf-8")
    commit_all(repo)

    def unexpected_blob_read(*args, **kwargs):
        raise AssertionError("blob content inspection must not start after the path limit fails")

    monkeypatch.setattr(ai_policy, "_blob_size", unexpected_blob_read)
    report = inspect_git_diff(repo, TaskSpec.model_validate(task_payload(base_sha)))

    assert report.passed is False
    assert "changed file count 3 exceeds 2" in report.violations


def test_policy_rechecks_worktree_after_content_inspection(tmp_path, monkeypatch):
    repo, base_sha = init_repo(tmp_path)
    tracked = repo / "src" / "example.py"
    tracked.write_text("VALUE = 2\n", encoding="utf-8")
    commit_all(repo)
    original_numstat = ai_policy._numstat

    def mutate_after_numstat(*args, **kwargs):
        stats = original_numstat(*args, **kwargs)
        tracked.write_text("UNREVIEWED = True\n", encoding="utf-8")
        return stats

    monkeypatch.setattr(ai_policy, "_numstat", mutate_after_numstat)

    with pytest.raises(GitInspectionError, match="worktree content differs from HEAD"):
        inspect_git_diff(repo, TaskSpec.model_validate(task_payload(base_sha)))


def test_policy_rechecks_head_after_content_inspection(tmp_path, monkeypatch):
    repo, base_sha = init_repo(tmp_path)
    tracked = repo / "src" / "example.py"
    tracked.write_text("VALUE = 2\n", encoding="utf-8")
    head_a = commit_all(repo)
    run_git(repo, "reset", "--hard", base_sha)
    tracked.write_text("VALUE = 3\n", encoding="utf-8")
    head_b = commit_all(repo)
    run_git(repo, "reset", "--hard", head_a)
    original_numstat = ai_policy._numstat

    def move_head_after_numstat(*args, **kwargs):
        stats = original_numstat(*args, **kwargs)
        run_git(repo, "update-ref", "HEAD", head_b)
        return stats

    monkeypatch.setattr(ai_policy, "_numstat", move_head_after_numstat)

    with pytest.raises(GitInspectionError, match="HEAD changed during policy inspection"):
        inspect_git_diff(repo, TaskSpec.model_validate(task_payload(base_sha)))


def test_judge_reinspection_rejects_dirty_candidate_and_changed_task(tmp_path):
    repo, base_sha = init_repo(tmp_path)
    (repo / "src" / "example.py").write_text("VALUE = 2\n", encoding="utf-8")
    commit_all(repo)
    task = TaskSpec.model_validate(task_payload(base_sha))
    stored = inspect_git_diff(repo, task)

    assert _reinspect_policy(repo, task, TASK_SHA, stored) == stored

    (repo / "src" / "example.py").write_text("UNREVIEWED = True\n", encoding="utf-8")
    with pytest.raises(GitInspectionError, match="worktree content differs from HEAD"):
        _reinspect_policy(repo, task, TASK_SHA, stored)

    (repo / "src" / "example.py").write_text("VALUE = 2\n", encoding="utf-8")
    narrow_payload = task_payload(base_sha)
    narrow_payload["allowed_paths"] = ["tests/**"]
    narrow_task = TaskSpec.model_validate(narrow_payload)
    with pytest.raises(ValueError, match="stored policy evidence"):
        _reinspect_policy(repo, narrow_task, TASK_SHA, stored)


def test_judge_reinspection_rejects_moved_head(tmp_path):
    repo, base_sha = init_repo(tmp_path)
    (repo / "src" / "example.py").write_text("VALUE = 2\n", encoding="utf-8")
    commit_all(repo)
    task = TaskSpec.model_validate(task_payload(base_sha))
    stored = inspect_git_diff(repo, task)
    (repo / "src" / "example.py").write_text("VALUE = 3\n", encoding="utf-8")
    commit_all(repo)

    with pytest.raises(GitInspectionError, match="single squash commit"):
        _reinspect_policy(repo, task, TASK_SHA, stored)


def test_judge_requires_human_review_until_provenance_is_attested():
    verdict = judge(
        TaskSpec.model_validate(task_payload()),
        passing_policy(),
        [accepting_review("reviewer"), accepting_review("adversary")],
        [passing_gate()],
        passing_tdd(),
    )

    assert verdict.status == "human_review"
    assert verdict.human_approval_required is True
    assert verdict.reasons == [
        "review provenance is self-reported until a trusted coordinator attests it"
    ]


@pytest.mark.parametrize(
    ("gates", "expected_reason"),
    [
        ([], "missing acceptance gates: AT-1"),
        (
            [
                {
                    "task_id": "TASK-TEST",
                    "task_sha256": TASK_SHA,
                    "head_sha": HEAD_SHA,
                    "patch_sha256": PATCH_SHA,
                    "acceptance_test_id": "AT-UNKNOWN",
                    "command": ["true"],
                    "expected_exit_code": 0,
                    "passed": True,
                    "exit_code": 0,
                    "evidence_sha256": "9" * 64,
                }
            ],
            "unknown acceptance gates: AT-UNKNOWN",
        ),
        (
            [
                {
                    "task_id": "TASK-TEST",
                    "task_sha256": TASK_SHA,
                    "head_sha": HEAD_SHA,
                    "patch_sha256": PATCH_SHA,
                    "acceptance_test_id": "AT-1",
                    "command": ["false"],
                    "expected_exit_code": 0,
                    "passed": True,
                    "exit_code": 0,
                    "evidence_sha256": "9" * 64,
                }
            ],
            "gate AT-1 command does not match the task",
        ),
    ],
)
def test_judge_requires_exact_task_acceptance_gates(gates, expected_reason):
    verdict = judge(
        TaskSpec.model_validate(task_payload()),
        passing_policy(),
        [accepting_review("reviewer"), accepting_review("adversary")],
        [GateResult.model_validate(gate) for gate in gates],
        passing_tdd(),
    )

    assert verdict.status == "fail"
    assert expected_reason in verdict.reasons


def test_judge_rejects_duplicate_acceptance_gate_ids():
    verdict = judge(
        TaskSpec.model_validate(task_payload()),
        passing_policy(),
        [accepting_review("reviewer"), accepting_review("adversary")],
        [passing_gate(), passing_gate()],
        passing_tdd(),
    )

    assert verdict.status == "fail"
    assert "acceptance gates must appear exactly once: AT-1" in verdict.reasons


@pytest.mark.parametrize(
    ("field", "value", "expected_reason"),
    [
        ("task_id", "TASK-OTHER", "TDD evidence task id does not match the task"),
        ("head_sha", "7" * 40, "TDD evidence head SHA does not match policy evidence"),
        (
            "patch_sha256",
            "7" * 64,
            "TDD evidence patch SHA-256 does not match policy evidence",
        ),
        (
            "acceptance_test_id",
            "AT-UNKNOWN",
            "TDD evidence references an unknown acceptance test",
        ),
        ("command", ["false"], "TDD evidence command does not match the task"),
    ],
)
def test_judge_binds_tdd_evidence_to_candidate_and_acceptance_test(field, value, expected_reason):
    payload = passing_tdd().model_dump()
    payload[field] = value
    verdict = judge(
        TaskSpec.model_validate(task_payload()),
        passing_policy(),
        [accepting_review("reviewer"), accepting_review("adversary")],
        [passing_gate()],
        TddEvidence.model_validate(payload),
    )

    assert verdict.status == "fail"
    assert expected_reason in verdict.reasons


def test_judge_rejects_unbound_test_manifest_and_quality_gate_as_tdd():
    task_data = task_payload()
    task_data["acceptance_tests"][0]["kind"] = "quality"
    task_data["acceptance_tests"][0].pop("expected_red_exit_codes")
    task_data["acceptance_tests"][0].pop("expected_red_fingerprint_sha256")
    evidence = passing_tdd().model_copy(update={"test_manifest_sha256": "0" * 64})
    verdict = judge(
        TaskSpec.model_validate(task_data),
        passing_policy(),
        [accepting_review("reviewer"), accepting_review("adversary")],
        [passing_gate()],
        evidence,
    )

    assert verdict.status == "fail"
    assert "TDD evidence must reference an acceptance test of kind test" in verdict.reasons
    assert "TDD test manifest SHA-256 does not match policy evidence" in verdict.reasons


def test_judge_binds_gate_and_all_evidence_to_raw_task_and_candidate():
    policy = passing_policy().model_copy(update={"task_id": "TASK-OTHER"})
    review = accepting_review("reviewer").model_copy(update={"task_sha256": "0" * 64})
    gate = passing_gate().model_copy(update={"patch_sha256": "0" * 64})
    evidence = passing_tdd().model_copy(update={"task_sha256": "0" * 64})
    verdict = judge(
        TaskSpec.model_validate(task_payload()),
        policy,
        [review, accepting_review("adversary")],
        [gate],
        evidence,
    )

    assert verdict.status == "fail"
    assert "policy task id does not match the task" in verdict.reasons
    assert "reviewer raw task SHA-256 does not match the task input" in verdict.reasons
    assert "gate AT-1 candidate digest does not match policy evidence" in verdict.reasons
    assert "TDD evidence raw task SHA-256 does not match the task input" in verdict.reasons


def test_judge_rejects_policy_from_another_trusted_harness():
    policy = passing_policy().model_copy(update={"trusted_harness_sha256": "d" * 64})
    verdict = judge(
        TaskSpec.model_validate(task_payload()),
        policy,
        [accepting_review("reviewer"), accepting_review("adversary")],
        [passing_gate()],
        passing_tdd(),
    )

    assert verdict.status == "fail"
    assert "policy trusted harness SHA-256 does not match the task" in verdict.reasons


def test_judge_requires_distinct_review_provenance_and_expected_prompts():
    reviewer = accepting_review("reviewer")
    adversary = accepting_review("adversary").model_copy(
        update={
            "reviewer_id": reviewer.reviewer_id,
            "session_id": reviewer.session_id,
            "prompt_sha256": reviewer.prompt_sha256,
        }
    )
    verdict = judge(
        TaskSpec.model_validate(task_payload()),
        passing_policy(),
        [reviewer, adversary],
        [passing_gate()],
        passing_tdd(),
    )

    assert verdict.status == "fail"
    assert "reviewer and adversary must use distinct reviewer ids" in verdict.reasons
    assert "reviewer and adversary must use distinct session ids" in verdict.reasons
    assert "adversary prompt SHA-256 does not match the task" in verdict.reasons


def test_judge_fails_closed_for_missing_role_or_high_finding():
    task = TaskSpec.model_validate(task_payload())
    missing_role = judge(
        task,
        passing_policy(),
        [accepting_review("reviewer")],
        [passing_gate()],
        passing_tdd(),
    )
    assert missing_role.status == "fail"
    assert "missing review roles: adversary" in missing_role.reasons

    adversary = ReviewReport(
        task_id="TASK-TEST",
        task_sha256=TASK_SHA,
        role="adversary",
        reviewer_id="agent-adversary",
        session_id="session-adversary",
        prompt_sha256="b" * 64,
        decision="changes_required",
        base_sha=BASE_SHA,
        head_sha=HEAD_SHA,
        patch_sha256=PATCH_SHA,
        summary="境界値で失敗する",
        findings=[
            {
                "id": "ADV-1",
                "severity": "high",
                "requirement_id": "REQ-1",
                "path": "src/example.py",
                "line": 1,
                "evidence": "空入力で例外になる",
                "proposed_test": "空入力を追加する",
            }
        ],
        unverified=[],
        external_calls=False,
    )
    blocked = judge(
        task,
        passing_policy(),
        [accepting_review("reviewer"), adversary],
        [passing_gate()],
        passing_tdd(),
    )
    assert blocked.status == "fail"
    assert blocked.blocking_findings == ["adversary:ADV-1"]


def test_judge_rejects_finding_with_unknown_requirement_id():
    reviewer = ReviewReport(
        task_id="TASK-TEST",
        task_sha256=TASK_SHA,
        role="reviewer",
        reviewer_id="agent-reviewer",
        session_id="session-reviewer",
        prompt_sha256="a" * 64,
        decision="accept",
        base_sha=BASE_SHA,
        head_sha=HEAD_SHA,
        patch_sha256=PATCH_SHA,
        summary="存在しない要件への参照を検出",
        findings=[
            Finding(
                id="REV-UNKNOWN",
                severity="low",
                requirement_id="REQ-UNKNOWN",
                evidence="要件IDがtaskに存在しない",
            )
        ],
        unverified=[],
        external_calls=False,
    )
    verdict = judge(
        TaskSpec.model_validate(task_payload()),
        passing_policy(),
        [reviewer, accepting_review("adversary")],
        [passing_gate()],
        passing_tdd(),
    )
    assert verdict.status == "fail"
    assert any("references unknown requirement REQ-UNKNOWN" in reason for reason in verdict.reasons)


def test_medium_finding_requires_human_review_even_when_accepted():
    reviewer = accepting_review("reviewer").model_copy(
        update={"findings": [Finding(id="REV-1", severity="medium", evidence="仕様判断が必要")]}
    )
    verdict = judge(
        TaskSpec.model_validate(task_payload()),
        passing_policy(),
        [reviewer, accepting_review("adversary")],
        [passing_gate()],
        passing_tdd(),
    )
    assert verdict.status == "human_review"


@pytest.mark.parametrize(
    ("update", "expected_reason"),
    [
        (
            {"red": {"exit_code": 0}},
            "RED phase exit code does not match the task's expected failure",
        ),
        (
            {"red": {"failure_fingerprint_sha256": "0" * 64}},
            "RED phase failure fingerprint does not match the task",
        ),
        ({"green": {"exit_code": 1}}, "GREEN phase did not pass"),
        (
            {"green": {"test_patch_sha256": "7" * 64}},
            "test patch changed between RED and GREEN",
        ),
    ],
)
def test_judge_fails_closed_when_tdd_evidence_is_not_red_green_or_frozen(update, expected_reason):
    payload = passing_tdd().model_dump()
    for phase, values in update.items():
        payload[phase].update(values)
    evidence = TddEvidence.model_validate(payload)
    verdict = judge(
        TaskSpec.model_validate(task_payload()),
        passing_policy(),
        [accepting_review("reviewer"), accepting_review("adversary")],
        [passing_gate()],
        evidence,
    )
    assert verdict.status == "fail"
    assert expected_reason in verdict.reasons


def test_judge_defensively_rejects_reused_v2_red_green_snapshot():
    evidence = passing_tdd().model_copy(
        update={"green_snapshot_sha256": passing_tdd().red_snapshot_sha256}
    )
    verdict = judge(
        TaskSpec.model_validate(task_payload()),
        passing_policy(),
        [accepting_review("reviewer"), accepting_review("adversary")],
        [passing_gate()],
        evidence,
    )

    assert verdict.status == "fail"
    assert "TDD v2 RED and GREEN snapshots must be distinct" in verdict.reasons


def make_codex_context(tmp_path: Path) -> tuple[Path, Path, Path]:
    (tmp_path / "candidate").mkdir(exist_ok=True)
    trusted_cwd = tmp_path / "trusted-coordinator"
    trusted_cwd.mkdir(mode=0o700)
    schema = trusted_cwd / "review.schema.json"
    schema.write_text('{"type": "object"}\n', encoding="utf-8")
    output_dir = tmp_path / "review-output"
    output_dir.mkdir(mode=0o700)
    return trusted_cwd, schema, output_dir / "review.json"


def test_codex_adapter_is_read_only_and_dry_run_by_default(monkeypatch, tmp_path):
    def unexpected_run(*args, **kwargs):
        raise AssertionError("subprocess must not run during a dry-run")

    monkeypatch.setattr(subprocess, "run", unexpected_run)
    trusted_cwd, schema, output = make_codex_context(tmp_path)
    adapter = CodexAdapter()
    result = adapter.run(
        prompt="Review the fixed diff.",
        output_schema=schema,
        output_path=output,
        cwd=trusted_cwd,
        candidate_repo=tmp_path / "candidate",
    )

    assert isinstance(result, CodexInvocation)
    assert result.argv == (
        "codex",
        "exec",
        "--ephemeral",
        "--sandbox",
        "read-only",
        "--ignore-user-config",
        "--output-schema",
        str(schema.resolve()),
        "-o",
        str(output.resolve()),
        "-",
    )
    assert not output.exists()


def test_codex_adapter_disables_execution_until_os_isolation_exists(tmp_path):
    trusted_cwd, schema, output = make_codex_context(tmp_path)
    with pytest.raises(ValueError, match="execution is disabled"):
        CodexAdapter().run(
            prompt="Review only.",
            output_schema=schema,
            output_path=output,
            cwd=trusted_cwd,
            candidate_repo=tmp_path / "candidate",
            execute=True,
        )


def test_codex_adapter_rejects_environment_file_paths(tmp_path):
    trusted_cwd, _schema, output = make_codex_context(tmp_path)
    with pytest.raises(ValueError, match="environment file"):
        CodexAdapter().build_invocation(
            output_schema=trusted_cwd / ".env.schema",
            output_path=output,
            cwd=trusted_cwd,
            candidate_repo=tmp_path / "candidate",
        )


def test_json_and_adapter_inputs_reject_symlinks_to_environment_files(tmp_path):
    trusted_cwd, _schema, output = make_codex_context(tmp_path)
    environment_file = tmp_path / ".env"
    environment_file.write_text('{"secret": "must-not-be-read"}\n', encoding="utf-8")
    task_link = tmp_path / "task.json"
    task_link.symlink_to(environment_file)
    with pytest.raises(ValueError, match="symlink"):
        _load_json(task_link)

    schema_link = tmp_path / "review.schema.json"
    schema_link.symlink_to(environment_file)
    with pytest.raises(ValueError, match="symlink"):
        CodexAdapter().build_invocation(
            output_schema=schema_link,
            output_path=output,
            cwd=trusted_cwd,
            candidate_repo=tmp_path / "candidate",
        )

    output_link = output
    output_link.symlink_to(environment_file)
    with pytest.raises(ValueError, match="symlink"):
        CodexAdapter().build_invocation(
            output_schema=trusted_cwd / "review.schema.json",
            output_path=output_link,
            cwd=trusted_cwd,
            candidate_repo=tmp_path / "candidate",
        )
    with pytest.raises(ValueError, match="symlink"):
        _write_json({"safe": False}, output_link)


@pytest.mark.parametrize(
    ("relative_path", "is_directory"),
    [
        (".env", False),
        (".env.local", False),
        (".envrc", False),
        (".netrc", False),
        ("nested/.aws/credentials", False),
        ("nested/.docker/config.json", False),
        (".streamlit/secrets.toml", False),
        ("cache", True),
    ],
)
def test_codex_adapter_requires_secret_free_checkout(tmp_path, relative_path, is_directory):
    trusted_cwd, schema, output = make_codex_context(tmp_path)
    sensitive_path = trusted_cwd / relative_path
    if is_directory:
        sensitive_path.mkdir(parents=True)
    else:
        sensitive_path.parent.mkdir(parents=True, exist_ok=True)
        sensitive_path.write_text("must-not-be-read\n", encoding="utf-8")

    with pytest.raises(ValueError, match="secret-free"):
        CodexAdapter().run(
            prompt="Review only.",
            output_schema=schema,
            output_path=output,
            cwd=trusted_cwd,
            candidate_repo=tmp_path / "candidate",
        )


def test_env_example_blocks_dry_run_even_when_it_looks_empty(tmp_path):
    trusted_cwd, schema, output = make_codex_context(tmp_path)
    (trusted_cwd / ".env.example").write_text("OUTSCRAPER_API_KEY=\n", encoding="utf-8")
    with pytest.raises(ValueError, match="secret-free"):
        CodexAdapter().run(
            prompt="Review only.",
            output_schema=schema,
            output_path=output,
            cwd=trusted_cwd,
            candidate_repo=tmp_path / "candidate",
        )


def test_secret_free_checkout_rejects_sensitive_symlink(tmp_path):
    trusted_cwd, schema, output = make_codex_context(tmp_path)
    target = trusted_cwd / "secret-source"
    target.write_text("must-not-be-read\n", encoding="utf-8")
    (trusted_cwd / ".env").symlink_to(target.name)
    with pytest.raises(ValueError, match="secret-free"):
        CodexAdapter().run(
            prompt="Review only.",
            output_schema=schema,
            output_path=output,
            cwd=trusted_cwd,
            candidate_repo=tmp_path / "candidate",
        )


@pytest.mark.parametrize(
    "relative_path",
    ["nested/.env", "nested/.streamlit/secrets.toml", "nested/cache"],
)
def test_secret_free_checkout_rejects_nested_sensitive_paths(tmp_path, relative_path):
    trusted_cwd, schema, output = make_codex_context(tmp_path)
    sensitive = trusted_cwd / relative_path
    if sensitive.name == "cache":
        sensitive.mkdir(parents=True)
    else:
        sensitive.parent.mkdir(parents=True, exist_ok=True)
        sensitive.write_text("must-not-be-read\n", encoding="utf-8")

    with pytest.raises(ValueError, match="secret-free"):
        CodexAdapter().run(
            prompt="Review only.",
            output_schema=schema,
            output_path=output,
            cwd=trusted_cwd,
            candidate_repo=tmp_path / "candidate",
        )


@pytest.mark.parametrize("instruction_path", ["AGENTS.md", "AGENTS.override.md", ".git"])
def test_codex_adapter_rejects_candidate_checkout_as_working_directory(tmp_path, instruction_path):
    trusted_cwd, schema, output = make_codex_context(tmp_path)
    (trusted_cwd / instruction_path).write_text("candidate-controlled\n", encoding="utf-8")

    with pytest.raises(ValueError, match="trusted coordinator directory"):
        CodexAdapter().run(
            prompt="Review only.",
            output_schema=schema,
            output_path=output,
            cwd=trusted_cwd,
            candidate_repo=tmp_path / "candidate",
        )


def test_codex_adapter_rejects_ancestor_agent_instructions(tmp_path):
    (tmp_path / "AGENTS.md").write_text("ancestor-controlled\n", encoding="utf-8")
    trusted_cwd, schema, output = make_codex_context(tmp_path)

    with pytest.raises(ValueError, match="trusted coordinator directory"):
        CodexAdapter().run(
            prompt="Review only.",
            output_schema=schema,
            output_path=output,
            cwd=trusted_cwd,
            candidate_repo=tmp_path / "candidate",
        )


def test_codex_adapter_rejects_output_inside_candidate_repo(tmp_path):
    trusted_cwd, schema, _output = make_codex_context(tmp_path)
    candidate = tmp_path / "candidate"
    output_parent = candidate / "private"
    output_parent.mkdir(parents=True, mode=0o700)

    with pytest.raises(ValueError, match="candidate repository"):
        CodexAdapter().run(
            prompt="Review only.",
            output_schema=schema,
            output_path=output_parent / "review.json",
            cwd=trusted_cwd,
            candidate_repo=candidate,
        )


def test_trusted_zipapp_is_deterministic_and_bound_to_external_runtime(tmp_path):
    source_root = Path(__file__).resolve().parents[1]
    output_root = tmp_path / "runtime"
    output_root.mkdir(mode=0o700)
    first = output_root / "first.pyz"
    second = output_root / "second.pyz"
    first_sha = build_trusted_zipapp(source_root, first)
    second_sha = build_trusted_zipapp(source_root, second)
    assert first_sha == second_sha
    assert first.read_bytes() == second.read_bytes()
    task_file = source_root / "specs" / "tasks" / "TASK-006-ai-review-harness.task.json"
    checked_in_task = TaskSpec.model_validate(json.loads(task_file.read_text(encoding="utf-8")))
    assert checked_in_task.trusted_harness_sha256 == first_sha
    assert (
        checked_in_task.review_prompts.reviewer_sha256
        == hashlib.sha256(
            (source_root / "specs" / "prompts" / "reviewer.md").read_bytes()
        ).hexdigest()
    )
    assert (
        checked_in_task.review_prompts.adversary_sha256
        == hashlib.sha256(
            (source_root / "specs" / "prompts" / "adversary.md").read_bytes()
        ).hexdigest()
    )

    coordinator = tmp_path / "coordinator"
    coordinator.mkdir(mode=0o700)
    candidate = tmp_path / "candidate"
    candidate.mkdir()
    interpreter = tmp_path / "trusted-python"
    interpreter.write_text("placeholder\n", encoding="utf-8")

    evidence = verify_trusted_zipapp(
        expected_sha256=first_sha,
        candidate_repo=candidate,
        zipapp_path=first,
        executable=interpreter,
        cwd=coordinator,
        module_search_paths=[str(first)],
        isolated=True,
        runtime_module_file=f"{first}/tools/ai_review/trusted_runtime.py",
    )

    assert evidence.sha256 == first_sha
    assert evidence.zipapp_path == first.resolve()


@pytest.mark.parametrize("isolated", [False, None])
def test_trusted_zipapp_rejects_non_isolated_python(tmp_path, isolated):
    source_root = Path(__file__).resolve().parents[1]
    runtime_root = tmp_path / "runtime"
    runtime_root.mkdir(mode=0o700)
    archive = runtime_root / "harness.pyz"
    digest = build_trusted_zipapp(source_root, archive)
    coordinator = tmp_path / "coordinator"
    coordinator.mkdir(mode=0o700)
    candidate = tmp_path / "candidate"
    candidate.mkdir()
    interpreter = tmp_path / "trusted-python"
    interpreter.write_text("placeholder\n", encoding="utf-8")

    with pytest.raises(RuntimeTrustError, match="isolated Python"):
        verify_trusted_zipapp(
            expected_sha256=digest,
            candidate_repo=candidate,
            zipapp_path=archive,
            executable=interpreter,
            cwd=coordinator,
            module_search_paths=[str(archive)],
            isolated=isolated,
            runtime_module_file=f"{archive}/tools/ai_review/trusted_runtime.py",
        )


def test_trusted_zipapp_rejects_candidate_paths_and_digest_mismatch(tmp_path):
    source_root = Path(__file__).resolve().parents[1]
    runtime_root = tmp_path / "runtime"
    runtime_root.mkdir(mode=0o700)
    archive = runtime_root / "harness.pyz"
    digest = build_trusted_zipapp(source_root, archive)
    coordinator = tmp_path / "coordinator"
    coordinator.mkdir(mode=0o700)
    candidate = tmp_path / "candidate"
    candidate.mkdir()
    interpreter = tmp_path / "trusted-python"
    interpreter.write_text("placeholder\n", encoding="utf-8")

    with pytest.raises(RuntimeTrustError, match="SHA-256"):
        verify_trusted_zipapp(
            expected_sha256="f" * 64,
            candidate_repo=candidate,
            zipapp_path=archive,
            executable=interpreter,
            cwd=coordinator,
            module_search_paths=[str(archive)],
            isolated=True,
            runtime_module_file=f"{archive}/tools/ai_review/trusted_runtime.py",
        )

    with pytest.raises(RuntimeTrustError, match="candidate repository"):
        verify_trusted_zipapp(
            expected_sha256=digest,
            candidate_repo=candidate,
            zipapp_path=archive,
            executable=interpreter,
            cwd=coordinator,
            module_search_paths=[str(archive), str(candidate)],
            isolated=True,
            runtime_module_file=f"{archive}/tools/ai_review/trusted_runtime.py",
        )

    with pytest.raises(RuntimeTrustError, match="first Python module search path"):
        verify_trusted_zipapp(
            expected_sha256=digest,
            candidate_repo=candidate,
            zipapp_path=archive,
            executable=interpreter,
            cwd=coordinator,
            module_search_paths=[str(tmp_path), str(archive)],
            isolated=True,
            runtime_module_file=f"{archive}/tools/ai_review/trusted_runtime.py",
        )


def test_preflight_fd_paths_are_revalidated_without_following_generic_symlinks(tmp_path):
    source_root = Path(__file__).resolve().parents[1]
    runtime_root = tmp_path / "runtime"
    runtime_root.mkdir(mode=0o700)
    archive = runtime_root / "harness.pyz"
    digest = build_trusted_zipapp(source_root, archive)
    coordinator = tmp_path / "coordinator"
    coordinator.mkdir(mode=0o700)
    candidate = tmp_path / "candidate"
    candidate.mkdir()
    interpreter = tmp_path / "trusted-python"
    interpreter.write_text("placeholder\n", encoding="utf-8")
    descriptor = os.open(archive, os.O_RDONLY)
    fd_path = Path(f"/proc/self/fd/{descriptor}")
    try:
        evidence = verify_trusted_zipapp(
            expected_sha256=digest,
            candidate_repo=candidate,
            zipapp_path=fd_path,
            executable=interpreter,
            cwd=coordinator,
            module_search_paths=[str(fd_path)],
            isolated=True,
            runtime_module_file=f"{fd_path}/tools/ai_review/trusted_runtime.py",
        )
    finally:
        os.close(descriptor)

    assert evidence.sha256 == digest
    assert evidence.zipapp_path == fd_path


def test_json_loader_accepts_only_digest_bound_preflight_fd(tmp_path):
    payload = b'{"task_id":"TASK-FD"}\n'
    task = tmp_path / "task.json"
    task.write_bytes(payload)
    descriptor = os.open(task, os.O_RDONLY)
    fd_path = Path(f"/proc/self/fd/{descriptor}")
    try:
        assert _load_json(fd_path, expected_sha256=hashlib.sha256(payload).hexdigest()) == {
            "task_id": "TASK-FD"
        }
        with pytest.raises(ValueError, match="expected SHA-256"):
            _load_json(fd_path)
    finally:
        os.close(descriptor)


def test_json_output_rejects_neutral_symlink_without_overwriting_target(tmp_path):
    target = tmp_path / "neutral-target.json"
    target.write_text('{"original": true}\n', encoding="utf-8")
    output = tmp_path / "review.json"
    output.symlink_to(target.name)

    with pytest.raises(ValueError, match="symlink"):
        _write_json({"safe": False}, output)

    assert target.read_text(encoding="utf-8") == '{"original": true}\n'


def test_json_output_rejects_broken_symlink_and_symlinked_parent(tmp_path):
    broken = tmp_path / "broken.json"
    broken.symlink_to("missing-target.json")
    with pytest.raises(ValueError, match="symlink"):
        _write_json({"safe": False}, broken)

    real_parent = tmp_path / "real-parent"
    real_parent.mkdir()
    linked_parent = tmp_path / "linked-parent"
    linked_parent.symlink_to(real_parent.name, target_is_directory=True)
    with pytest.raises(ValueError, match="symlink"):
        _write_json({"safe": False}, linked_parent / "review.json")


def test_json_output_rejects_existing_hardlink_without_overwriting_target(tmp_path):
    target = tmp_path / "source.py"
    target.write_text("ORIGINAL = True\n", encoding="utf-8")
    output = tmp_path / "review.json"
    os.link(target, output)

    with pytest.raises(ValueError, match="already exists"):
        _write_json({"safe": False}, output)

    assert target.read_text(encoding="utf-8") == "ORIGINAL = True\n"


def test_structured_output_must_stay_inside_trusted_artifact_root(tmp_path):
    artifact_root = tmp_path / "artifacts"
    artifact_root.mkdir(mode=0o700)
    outside = tmp_path / "outside.json"

    with pytest.raises(ValueError, match="trusted artifact root"):
        _write_json({"safe": True}, outside, trusted_root=artifact_root)

    assert not outside.exists()


def test_checked_in_schemas_match_pydantic_contracts():
    root = Path(__file__).resolve().parents[1]
    models = {
        "task.schema.json": TaskSpec,
        "policy.schema.json": PolicyReport,
        "gate.schema.json": GateResult,
        "review.schema.json": ReviewReport,
        "tdd-evidence.schema.json": TddEvidence,
        "verdict.schema.json": Verdict,
    }
    for filename, model_type in models.items():
        checked_in = json.loads((root / "specs" / "schemas" / filename).read_text())
        assert checked_in == model_type.model_json_schema()
