from __future__ import annotations

import hashlib
import json
import os
import stat
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

from tools.ai_review.models import TaskSpec
from tools.ai_review.phase_protocol import EMPTY_INITIAL_ARTIFACTS_SHA256
from tools.ai_review.phase_protocol import canonical_json_bytes
from tools.ai_review.policy import inspect_git_diff
from tools.ai_review.runtime_release import build_runtime_manifest
from tools.ai_review.runtime_release import generate_coordinator_keypair
from tools.ai_review.runtime_release import main as release_main
from tools.ai_review.workflow_init import WorkflowInitializationError
from tools.ai_review.workflow_init import initialize_workflow


_CANDIDATE_COMMIT_ENV = {
    "GIT_AUTHOR_DATE": "2000-01-01T00:00:00+00:00",
    "GIT_COMMITTER_DATE": "2000-01-01T00:00:00+00:00",
    "GIT_AUTHOR_NAME": "Workflow Test",
    "GIT_COMMITTER_NAME": "Workflow Test",
    "GIT_AUTHOR_EMAIL": "workflow@example.invalid",
    "GIT_COMMITTER_EMAIL": "workflow@example.invalid",
}


def _candidate_uid() -> int:
    return 65_534 if os.geteuid() != 65_534 else 65_533


def _run_git(repo: Path, *arguments: str, env: dict[str, str] | None = None) -> str:
    process_env = os.environ.copy()
    if env is not None:
        process_env.update(env)
    completed = subprocess.run(
        ["git", *arguments],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
        env=process_env,
        shell=False,
    )
    return completed.stdout.strip()


def _task_payload(*, base_sha: str, harness_sha256: str) -> dict[str, object]:
    return {
        "schema_version": "2.0",
        "task_id": "TASK-WORKFLOW-INIT",
        "base_sha": base_sha,
        "trusted_harness_sha256": harness_sha256,
        "objective": "credentialなしで初期phase requestを生成する",
        "requirements": [{"id": "REQ-1", "text": "承認済みpatchだけを固定する"}],
        "review_prompts": {
            "reviewer_sha256": "2" * 64,
            "adversary_sha256": "3" * 64,
        },
        "candidate_commit": {
            "message": "TASK-WORKFLOW-INIT",
            "author_name": "Workflow Test",
            "author_email": "workflow@example.invalid",
            "timestamp": 946684800,
            "timezone": "+0000",
        },
        "acceptance_tests": [
            {
                "id": "AT-1",
                "kind": "test",
                "command": ["pytest", "tests/test_feature.py"],
                "expected_exit_code": 0,
                "expected_red_exit_codes": [1],
                "expected_red_fingerprint_sha256": "4" * 64,
                "test_paths": ["tests/test_feature.py"],
            }
        ],
        "allowed_paths": ["src/feature.py", "tests/test_feature.py"],
        "denied_paths": [".env", "cache/**"],
        "limits": {"max_changed_files": 2, "max_added_lines": 20},
        "network_policy": "deny",
    }


def _make_candidate(tmp_path: Path) -> tuple[Path, str]:
    candidate = tmp_path / "candidate"
    candidate.mkdir()
    _run_git(candidate, "init", "-q")
    _run_git(candidate, "config", "user.name", "Workflow Test")
    _run_git(candidate, "config", "user.email", "workflow@example.invalid")
    (candidate / "src").mkdir()
    (candidate / "src" / "feature.py").write_text("VALUE = 1\n", encoding="utf-8")
    _run_git(candidate, "add", "src/feature.py")
    _run_git(candidate, "commit", "-qm", "base")
    base_sha = _run_git(candidate, "rev-parse", "HEAD")
    (candidate / "src" / "feature.py").write_text("VALUE = 2\n", encoding="utf-8")
    (candidate / "tests").mkdir()
    (candidate / "tests" / "test_feature.py").write_text(
        "def test_feature():\n    assert True\n",
        encoding="utf-8",
    )
    _run_git(candidate, "add", "src/feature.py", "tests/test_feature.py")
    _run_git(
        candidate,
        "commit",
        "-qm",
        "TASK-WORKFLOW-INIT",
        env=_CANDIDATE_COMMIT_ENV,
    )
    return candidate, base_sha


def _make_zipapp(path: Path) -> Path:
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("__main__.py", "raise SystemExit(0)\n")
    path.chmod(0o600)
    return path


def _write(path: Path, raw: bytes) -> Path:
    path.write_bytes(raw)
    path.chmod(0o600)
    return path


def _release_fixture(tmp_path: Path) -> dict[str, object]:
    tmp_path.mkdir(parents=True, exist_ok=True)
    tmp_path.chmod(0o700)
    candidate, base_sha = _make_candidate(tmp_path)
    runtime = tmp_path / "runtime"
    runtime.mkdir(mode=0o700)
    harness = _make_zipapp(runtime / "harness.pyz")
    task_payload = _task_payload(
        base_sha=base_sha,
        harness_sha256=hashlib.sha256(harness.read_bytes()).hexdigest(),
    )
    task = _write(
        runtime / "task.json",
        (json.dumps(task_payload, ensure_ascii=False, sort_keys=True) + "\n").encode(),
    )
    private_key = runtime / "coordinator-private.pem"
    public_key = runtime / "coordinator-public.pem"
    generate_coordinator_keypair(private_key=private_key, public_key=public_key)
    dependency_lock = _write(runtime / "uv.lock", b"version = 1\n")
    schema_bundle = _write(runtime / "schemas.json", b'{"schema_version":"1.0"}\n')
    egress_policy = _write(
        runtime / "broker-egress-policy.json",
        (
            Path(__file__).resolve().parents[1] / "specs/policies/broker-egress-policy.json"
        ).read_bytes(),
    )
    pricing_policy = _write(
        runtime / "openai-pricing-policy.json",
        (
            Path(__file__).resolve().parents[1] / "specs/policies/openai-pricing-policy.json"
        ).read_bytes(),
    )
    manifest = runtime / "runtime-manifest.json"
    manifest_sha256 = build_runtime_manifest(
        output=manifest,
        python=Path(sys.executable).resolve(strict=True),
        harness=harness,
        task=task,
        dependency_lock=dependency_lock,
        schema_bundle=schema_bundle,
        coordinator_public_key=public_key,
        broker_egress_policy=egress_policy,
        openai_pricing_policy=pricing_policy,
        coordinator_image_digest="sha256:" + "1" * 64,
        offline_runner_image_digest="sha256:" + "2" * 64,
        broker_image_digest="sha256:" + "3" * 64,
        broker_gateway_image_digest="sha256:" + "4" * 64,
        broker_packet_reservation_limit=544_000,
        broker_packet_cost_limit_microusd=4_540_000,
    )
    parsed_task = TaskSpec.model_validate(task_payload)
    policy = inspect_git_diff(
        candidate,
        parsed_task,
        task_sha256=hashlib.sha256(task.read_bytes()).hexdigest(),
    )
    assert policy.passed and policy.patch_sha256 is not None
    output_parent = tmp_path / "outputs"
    output_parent.mkdir(mode=0o700)
    return {
        "candidate": candidate,
        "task": task,
        "public_key": public_key,
        "manifest": manifest,
        "manifest_sha256": manifest_sha256,
        "patch_sha256": policy.patch_sha256,
        "output_parent": output_parent,
    }


def _initialize(fixture: dict[str, object], output_name: str = "initial"):
    return initialize_workflow(
        task=fixture["task"],
        runtime_manifest=fixture["manifest"],
        expected_runtime_manifest_sha256=fixture["manifest_sha256"],
        coordinator_public_key=fixture["public_key"],
        candidate_repo=fixture["candidate"],
        candidate_uid=_candidate_uid(),
        expected_patch_sha256=fixture["patch_sha256"],
        output_dir=fixture["output_parent"] / output_name,
    )


def test_empty_initial_artifact_digest_is_canonical_empty_set() -> None:
    assert EMPTY_INITIAL_ARTIFACTS_SHA256 == hashlib.sha256(canonical_json_bytes([])).hexdigest()


def test_initialize_workflow_revalidates_and_freezes_canonical_first_request(
    tmp_path: Path,
) -> None:
    fixture = _release_fixture(tmp_path)

    initialized = _initialize(fixture)
    request_path = fixture["output_parent"] / "initial" / "phase-request.json"
    raw = request_path.read_bytes()

    assert initialized.request.phase == "snapshot"
    assert initialized.request.sequence == 1
    assert initialized.request.candidate_sha256 == fixture["patch_sha256"]
    assert initialized.request.input_artifacts_sha256 == EMPTY_INITIAL_ARTIFACTS_SHA256
    assert raw == canonical_json_bytes(initialized.request)
    assert initialized.phase_request_file_sha256 == hashlib.sha256(raw).hexdigest()
    assert stat.S_IMODE(request_path.stat().st_mode) == 0o400
    assert stat.S_IMODE(request_path.parent.stat().st_mode) == 0o500
    second = _initialize(fixture, "second")
    assert second.request.workflow_id != initialized.request.workflow_id


def test_initialize_workflow_rejects_dirty_candidate_without_creating_output(
    tmp_path: Path,
) -> None:
    fixture = _release_fixture(tmp_path)
    (fixture["candidate"] / "untracked.txt").write_text("dirty\n", encoding="utf-8")
    output = fixture["output_parent"] / "initial"

    with pytest.raises(WorkflowInitializationError, match="untracked|dirty|worktree"):
        _initialize(fixture)

    assert not output.exists()


def test_initialize_workflow_rejects_wrong_patch_binding(tmp_path: Path) -> None:
    fixture = _release_fixture(tmp_path)
    fixture["patch_sha256"] = "f" * 64

    with pytest.raises(WorkflowInitializationError, match="patch SHA-256"):
        _initialize(fixture)


def test_initialize_workflow_requires_external_manifest_digest_anchor(tmp_path: Path) -> None:
    fixture = _release_fixture(tmp_path)
    fixture["manifest_sha256"] = "f" * 64

    with pytest.raises(WorkflowInitializationError, match="manifest.*SHA-256"):
        _initialize(fixture)


def test_initialize_workflow_rejects_v1_task_even_with_rehashed_manifest(tmp_path: Path) -> None:
    fixture = _release_fixture(tmp_path)
    task_payload = json.loads(fixture["task"].read_bytes())
    task_payload["schema_version"] = "1.0"
    task_raw = (json.dumps(task_payload, sort_keys=True) + "\n").encode()
    fixture["task"].write_bytes(task_raw)
    manifest_payload = json.loads(fixture["manifest"].read_bytes())
    manifest_payload["task"]["sha256"] = hashlib.sha256(task_raw).hexdigest()
    manifest_raw = (
        json.dumps(manifest_payload, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode()
    fixture["manifest"].write_bytes(manifest_raw)
    fixture["manifest_sha256"] = hashlib.sha256(manifest_raw).hexdigest()

    with pytest.raises(WorkflowInitializationError, match="TaskSpec v2"):
        _initialize(fixture)


def test_initialize_workflow_rejects_task_or_public_key_outside_manifest(tmp_path: Path) -> None:
    fixture = _release_fixture(tmp_path)
    wrong_task = _write(tmp_path / "wrong-task.json", fixture["task"].read_bytes())
    fixture["task"] = wrong_task
    with pytest.raises(WorkflowInitializationError, match="task.*manifest"):
        _initialize(fixture, "wrong-task")

    fixture = _release_fixture(tmp_path / "second-fixture")
    wrong_key = _write(tmp_path / "wrong-key.pem", fixture["public_key"].read_bytes())
    fixture["public_key"] = wrong_key
    with pytest.raises(WorkflowInitializationError, match="public key.*manifest"):
        _initialize(fixture, "wrong-key")


def test_initialize_workflow_rejects_symlink_self_owned_and_overwrite(tmp_path: Path) -> None:
    fixture = _release_fixture(tmp_path)
    linked_candidate = tmp_path / "linked-candidate"
    linked_candidate.symlink_to(fixture["candidate"], target_is_directory=True)
    fixture["candidate"] = linked_candidate
    with pytest.raises(WorkflowInitializationError, match="symlink"):
        _initialize(fixture, "linked")

    fixture = _release_fixture(tmp_path / "self-owned-fixture")
    with pytest.raises(WorkflowInitializationError, match="different OS UID|root"):
        initialize_workflow(
            task=fixture["task"],
            runtime_manifest=fixture["manifest"],
            expected_runtime_manifest_sha256=fixture["manifest_sha256"],
            coordinator_public_key=fixture["public_key"],
            candidate_repo=fixture["candidate"],
            candidate_uid=os.geteuid(),
            expected_patch_sha256=fixture["patch_sha256"],
            output_dir=fixture["output_parent"] / "self-owned",
        )

    fixture = _release_fixture(tmp_path / "overwrite-fixture")
    output = fixture["output_parent"] / "initial"
    output.mkdir(mode=0o700)
    with pytest.raises(WorkflowInitializationError, match="overwrite|already exists"):
        _initialize(fixture)


def test_workflow_init_cli_prints_only_safe_digests(tmp_path: Path, capsys) -> None:
    fixture = _release_fixture(tmp_path)
    output = fixture["output_parent"] / "cli-initial"

    exit_code = release_main(
        [
            "workflow-init",
            "--task",
            str(fixture["task"]),
            "--runtime-manifest",
            str(fixture["manifest"]),
            "--expected-runtime-manifest-sha256",
            str(fixture["manifest_sha256"]),
            "--coordinator-public-key",
            str(fixture["public_key"]),
            "--candidate-repo",
            str(fixture["candidate"]),
            "--candidate-uid",
            str(_candidate_uid()),
            "--expected-patch-sha256",
            str(fixture["patch_sha256"]),
            "--output-dir",
            str(output),
        ]
    )

    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert exit_code == 0
    assert captured.err == ""
    assert set(payload) == {
        "candidate_sha256",
        "coordinator_key_id",
        "coordinator_public_key_sha256",
        "phase_request_file_sha256",
        "request_sha256",
        "runtime_manifest_sha256",
        "task_sha256",
        "workflow_id",
    }
    assert all(isinstance(value, str) and len(value) == 64 for value in payload.values())
    assert str(tmp_path) not in captured.out
