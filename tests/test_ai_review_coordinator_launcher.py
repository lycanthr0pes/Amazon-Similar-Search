from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

from tools.ai_review.coordinator_launcher import CoordinatorLauncherError
from tools.ai_review.coordinator_launcher import build_coordinator_invocation
from tools.ai_review.coordinator_launcher import execute_coordinator
from tools.ai_review.coordinator_launcher import freeze_artifact_input
from tools.ai_review.coordinator_launcher import freeze_snapshot_artifact_input
from tools.ai_review.coordinator_launcher import freeze_coordinator_assets
from tools.ai_review.coordinator_runtime import CoordinatorRuntimeError
from tools.ai_review.coordinator_runtime import verify_coordinator_runtime
from tools.ai_review.offline_runner import ContainerBackend
from tools.ai_review.offline_runner import _BoundedProcessResult
from tools.ai_review.preflight import preflight_runtime
from tools.ai_review.runtime_release import build_runtime_manifest


def _candidate_uid() -> int:
    return 65_534 if os.geteuid() != 65_534 else 65_533


def _protected_file(path: Path, raw: bytes, mode: int = 0o444) -> Path:
    path.write_bytes(raw)
    path.chmod(mode)
    return path


def _runtime_evidence(tmp_path: Path):
    runtime = tmp_path / "runtime"
    runtime.mkdir(mode=0o700)
    harness = runtime / "harness.pyz"
    with zipfile.ZipFile(harness, "w") as archive:
        archive.writestr("__main__.py", "raise SystemExit(0)\n")
    harness.chmod(0o444)
    task_payload = {
        "schema_version": "2.0",
        "task_id": "TASK-COORDINATOR",
        "base_sha": "1" * 40,
        "trusted_harness_sha256": hashlib.sha256(harness.read_bytes()).hexdigest(),
        "objective": "coordinator runtimeを検証する",
        "requirements": [{"id": "REQ-1", "text": "固定したテストを実行する"}],
        "review_prompts": {
            "reviewer_sha256": "2" * 64,
            "adversary_sha256": "3" * 64,
        },
        "candidate_commit": {
            "message": "TASK-COORDINATOR",
            "author_name": "Coordinator Test",
            "author_email": "coordinator@example.invalid",
            "timestamp": 946684800,
            "timezone": "+0000",
        },
        "acceptance_tests": [
            {
                "id": "AT-1",
                "kind": "test",
                "command": ["pytest", "tests/test_coordinator.py"],
                "expected_exit_code": 0,
                "expected_red_exit_codes": [1],
                "expected_red_fingerprint_sha256": "4" * 64,
                "test_paths": ["tests/test_coordinator.py"],
            }
        ],
        "allowed_paths": ["src/**", "tests/**"],
        "denied_paths": [".env", "cache/**"],
        "limits": {"max_changed_files": 10, "max_added_lines": 100},
        "network_policy": "deny",
    }
    task = _protected_file(
        runtime / "task.json",
        (json.dumps(task_payload, sort_keys=True) + "\n").encode(),
    )
    lock = _protected_file(runtime / "uv.lock", b"version = 1\n")
    schemas = _protected_file(runtime / "schemas.json", b'{"schema_version":"1.0"}\n')
    public_key = _protected_file(runtime / "coordinator-public.pem", b"public-key\n")
    egress_policy = _protected_file(
        runtime / "broker-egress-policy.json",
        (
            Path(__file__).resolve().parents[1] / "specs/policies/broker-egress-policy.json"
        ).read_bytes(),
    )
    pricing_policy = _protected_file(
        runtime / "openai-pricing-policy.json",
        (
            Path(__file__).resolve().parents[1] / "specs/policies/openai-pricing-policy.json"
        ).read_bytes(),
    )
    manifest = runtime / "runtime-manifest.json"
    digest = build_runtime_manifest(
        output=manifest,
        python=Path(sys.executable).resolve(strict=True),
        harness=harness,
        task=task,
        dependency_lock=lock,
        schema_bundle=schemas,
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
    return preflight_runtime(
        manifest_path=manifest,
        expected_manifest_sha256=digest,
        candidate_uid=_candidate_uid(),
    )


def _backend(
    *,
    name: str = "podman",
    rootless: bool = True,
    user_namespace: bool = True,
) -> ContainerBackend:
    executable = Path("/bin/true").resolve(strict=True)
    return ContainerBackend(
        name=name,
        executable=executable,
        rootless=rootless,
        user_namespace=user_namespace,
        seccomp_enabled=True,
        seccomp_profile="builtin",
        sha256=hashlib.sha256(executable.read_bytes()).hexdigest(),
        security_evidence_sha256="4" * 64,
    )


def _inputs(tmp_path: Path) -> tuple[Path, Path]:
    artifact_root = tmp_path / "artifacts"
    artifact_root.mkdir(mode=0o700)
    candidate = tmp_path / "candidate"
    candidate.mkdir(mode=0o555)
    source = candidate / "source.py"
    source.write_text("VALUE = 1\n", encoding="utf-8")
    source.chmod(0o444)
    return artifact_root, candidate


def test_coordinator_descriptor_is_pinned_read_only_networkless_and_socketless(
    tmp_path: Path,
) -> None:
    evidence = _runtime_evidence(tmp_path)
    artifact_root, candidate = _inputs(tmp_path)
    try:
        invocation = build_coordinator_invocation(
            evidence=evidence,
            backend=_backend(),
            image="registry.invalid/coordinator@sha256:" + "1" * 64,
            artifact_root=artifact_root,
            candidate_repo=candidate,
            candidate_uid=_candidate_uid(),
            command=(
                "policy",
                "--task",
                "@task-container",
                "--artifact-root",
                "@artifact-root-container",
                "--repo",
                "@candidate-repo-container",
                "--expected-task-sha256",
                "@task-sha256",
            ),
            container_name="ai-review-coordinator-" + "a" * 24,
        )
    finally:
        evidence.close()

    assert "--network=none" in invocation.argv
    assert "--read-only" in invocation.argv
    assert "--cap-drop=ALL" in invocation.argv
    assert "--security-opt=no-new-privileges" in invocation.argv
    assert "--userns=keep-id:uid=65532,gid=65532" in invocation.argv
    assert "/runtime/task.json" in invocation.argv
    assert "/candidate" in invocation.argv
    assert "/artifacts" in invocation.argv
    assert evidence.task.sha256 in invocation.argv
    assert all("docker.sock" not in argument for argument in invocation.argv)
    assert all("/proc/self/fd/" not in argument for argument in invocation.argv)


def test_post_snapshot_coordinator_descriptor_does_not_mount_candidate(
    tmp_path: Path,
) -> None:
    evidence = _runtime_evidence(tmp_path)
    artifact_root, _candidate = _inputs(tmp_path)
    try:
        invocation = build_coordinator_invocation(
            evidence=evidence,
            backend=_backend(),
            image="registry.invalid/coordinator@sha256:" + "1" * 64,
            artifact_root=artifact_root,
            candidate_repo=None,
            candidate_uid=_candidate_uid(),
            command=("review-packet",),
            container_name="ai-review-coordinator-" + "d" * 24,
            mount_candidate=False,
        )
    finally:
        evidence.close()

    assert all("/candidate" not in argument for argument in invocation.argv)
    assert all("docker.sock" not in argument for argument in invocation.argv)


def test_snapshot_code_uses_a_separate_readonly_mount_while_general_agents_stays_forbidden(
    tmp_path: Path,
) -> None:
    evidence = _runtime_evidence(tmp_path)
    artifact_root, _candidate = _inputs(tmp_path)
    snapshots = tmp_path / "snapshots"
    snapshots.mkdir(mode=0o700)
    tree = snapshots / "snapshots" / ("a" * 64) / "tree"
    tree.mkdir(mode=0o555, parents=True)
    _protected_file(tree / "AGENTS.md", b"untrusted repository instructions\n")
    general_copy = tmp_path / "general-copy"
    dedicated_copy = tmp_path / "dedicated-copy"
    try:
        with pytest.raises(CoordinatorLauncherError, match="protected path"):
            freeze_artifact_input(
                snapshots,
                general_copy,
                candidate_uid=_candidate_uid(),
            )
        frozen = freeze_snapshot_artifact_input(
            snapshots,
            dedicated_copy,
            candidate_uid=_candidate_uid(),
        )
        invocation = build_coordinator_invocation(
            evidence=evidence,
            backend=_backend(),
            image="registry.invalid/coordinator@sha256:" + "1" * 64,
            artifact_root=artifact_root,
            candidate_repo=None,
            candidate_uid=_candidate_uid(),
            command=("review-packet", "--snapshot-artifact-root", "/snapshots"),
            container_name="ai-review-coordinator-" + "9" * 24,
            mount_candidate=False,
            snapshot_artifact_root=snapshots,
            frozen_snapshot_artifacts=frozen,
        )
    finally:
        evidence.close()

    snapshot_mount = next(value for value in invocation.argv if "dst=/snapshots" in value)
    assert "readonly" in snapshot_mount
    assert "AGENTS.md" not in " ".join(invocation.argv)
    assert all("/candidate" not in value for value in invocation.argv)


def test_candidate_mount_cannot_be_requested_without_a_candidate_tree(tmp_path: Path) -> None:
    evidence = _runtime_evidence(tmp_path)
    artifact_root, _candidate = _inputs(tmp_path)
    try:
        with pytest.raises(CoordinatorLauncherError, match="candidate"):
            build_coordinator_invocation(
                evidence=evidence,
                backend=_backend(),
                image="registry.invalid/coordinator@sha256:" + "1" * 64,
                artifact_root=artifact_root,
                candidate_repo=None,
                candidate_uid=_candidate_uid(),
                command=("snapshot",),
                container_name="ai-review-coordinator-" + "e" * 24,
                mount_candidate=True,
            )
    finally:
        evidence.close()


def test_phase_output_is_new_exclusive_rw_mount_and_signing_key_is_sign_only(
    tmp_path: Path,
) -> None:
    evidence = _runtime_evidence(tmp_path)
    artifact_root, _candidate = _inputs(tmp_path)
    phase_output = tmp_path / "phase-output"
    phase_output.mkdir(mode=0o700)
    signing_key = _protected_file(tmp_path / "coordinator-private.pem", b"private-key\n", 0o400)
    try:
        invocation = build_coordinator_invocation(
            evidence=evidence,
            backend=_backend(),
            image="registry.invalid/coordinator@sha256:" + "1" * 64,
            artifact_root=artifact_root,
            candidate_repo=None,
            candidate_uid=_candidate_uid(),
            command=("sign", "--workflow-operation", "prepare"),
            container_name="ai-review-coordinator-" + "f" * 24,
            mount_candidate=False,
            phase_output_root=phase_output,
            signing_key=signing_key,
        )
    finally:
        evidence.close()

    output_mount = next(value for value in invocation.argv if "dst=/output" in value)
    assert "readonly" not in output_mount
    key_mount = next(value for value in invocation.argv if "dst=/signing/" in value)
    assert "readonly" in key_mount
    assert all("docker.sock" not in value for value in invocation.argv)


def test_nonce_ledger_is_private_rw_and_mounted_only_for_judge_prepare(
    tmp_path: Path,
) -> None:
    evidence = _runtime_evidence(tmp_path)
    artifact_root, _candidate = _inputs(tmp_path)
    nonce_root = tmp_path / "nonce-ledger"
    nonce_root.mkdir(mode=0o700)
    command = (
        "attested-judge",
        "--workflow-operation",
        "prepare",
        "--nonce-ledger",
        "/nonce-ledger/nonces.sqlite3",
    )
    try:
        invocation = build_coordinator_invocation(
            evidence=evidence,
            backend=_backend(),
            image="registry.invalid/coordinator@sha256:" + "1" * 64,
            artifact_root=artifact_root,
            candidate_repo=None,
            candidate_uid=_candidate_uid(),
            command=command,
            container_name="ai-review-coordinator-" + "0" * 24,
            mount_candidate=False,
            nonce_ledger_root=nonce_root,
        )
        nonce_mount = next(value for value in invocation.argv if "dst=/nonce-ledger" in value)
        assert "readonly" not in nonce_mount

        with pytest.raises(CoordinatorLauncherError, match="only for attested-judge"):
            build_coordinator_invocation(
                evidence=evidence,
                backend=_backend(),
                image="registry.invalid/coordinator@sha256:" + "1" * 64,
                artifact_root=artifact_root,
                candidate_repo=None,
                candidate_uid=_candidate_uid(),
                command=("review-packet",),
                container_name="ai-review-coordinator-" + "1" * 24,
                mount_candidate=False,
                nonce_ledger_root=nonce_root,
            )
        (nonce_root / "unexpected").write_bytes(b"unsafe\n")
        with pytest.raises(CoordinatorLauncherError, match="unknown file"):
            build_coordinator_invocation(
                evidence=evidence,
                backend=_backend(),
                image="registry.invalid/coordinator@sha256:" + "1" * 64,
                artifact_root=artifact_root,
                candidate_repo=None,
                candidate_uid=_candidate_uid(),
                command=command,
                container_name="ai-review-coordinator-" + "2" * 24,
                mount_candidate=False,
                nonce_ledger_root=nonce_root,
            )
    finally:
        evidence.close()


def test_nonce_ledger_mount_rejects_an_existing_database_with_unsafe_schema(
    tmp_path: Path,
) -> None:
    evidence = _runtime_evidence(tmp_path)
    artifact_root, _candidate = _inputs(tmp_path)
    nonce_root = tmp_path / "nonce-ledger"
    nonce_root.mkdir(mode=0o700)
    ledger = nonce_root / "nonces.sqlite3"
    connection = sqlite3.connect(ledger)
    try:
        connection.execute("CREATE TABLE used_nonces (nonce TEXT, reserved_at INTEGER NOT NULL)")
        connection.commit()
    finally:
        connection.close()
    ledger.chmod(0o600)
    command = (
        "attested-judge",
        "--workflow-operation",
        "prepare",
        "--nonce-ledger",
        "/nonce-ledger/nonces.sqlite3",
    )
    try:
        with pytest.raises(CoordinatorLauncherError, match="trusted contract"):
            build_coordinator_invocation(
                evidence=evidence,
                backend=_backend(),
                image="registry.invalid/coordinator@sha256:" + "1" * 64,
                artifact_root=artifact_root,
                candidate_repo=None,
                candidate_uid=_candidate_uid(),
                command=command,
                container_name="ai-review-coordinator-" + "3" * 24,
                mount_candidate=False,
                nonce_ledger_root=nonce_root,
            )
    finally:
        evidence.close()


def test_signing_key_and_output_mount_are_rejected_outside_their_exact_contract(
    tmp_path: Path,
) -> None:
    evidence = _runtime_evidence(tmp_path)
    artifact_root, _candidate = _inputs(tmp_path)
    signing_key = _protected_file(tmp_path / "coordinator-private.pem", b"private-key\n", 0o400)
    nonempty_output = tmp_path / "nonempty-output"
    nonempty_output.mkdir(mode=0o700)
    _protected_file(nonempty_output / "old.json", b"{}\n", 0o600)
    try:
        with pytest.raises(CoordinatorLauncherError, match="sign workflow prepare"):
            build_coordinator_invocation(
                evidence=evidence,
                backend=_backend(),
                image="registry.invalid/coordinator@sha256:" + "1" * 64,
                artifact_root=artifact_root,
                candidate_repo=None,
                candidate_uid=_candidate_uid(),
                command=("review-packet",),
                container_name="ai-review-coordinator-" + "1" * 24,
                mount_candidate=False,
                signing_key=signing_key,
            )
        with pytest.raises(CoordinatorLauncherError, match="requires the protected"):
            build_coordinator_invocation(
                evidence=evidence,
                backend=_backend(),
                image="registry.invalid/coordinator@sha256:" + "1" * 64,
                artifact_root=artifact_root,
                candidate_repo=None,
                candidate_uid=_candidate_uid(),
                command=("sign", "--workflow-operation", "prepare"),
                container_name="ai-review-coordinator-" + "4" * 24,
                mount_candidate=False,
            )
        with pytest.raises(CoordinatorLauncherError, match="sign workflow prepare"):
            build_coordinator_invocation(
                evidence=evidence,
                backend=_backend(),
                image="registry.invalid/coordinator@sha256:" + "1" * 64,
                artifact_root=artifact_root,
                candidate_repo=None,
                candidate_uid=_candidate_uid(),
                command=("sign", "--workflow-operation", "finalize"),
                container_name="ai-review-coordinator-" + "3" * 24,
                mount_candidate=False,
                signing_key=signing_key,
            )
        with pytest.raises(CoordinatorLauncherError, match="new and empty"):
            build_coordinator_invocation(
                evidence=evidence,
                backend=_backend(),
                image="registry.invalid/coordinator@sha256:" + "1" * 64,
                artifact_root=artifact_root,
                candidate_repo=None,
                candidate_uid=_candidate_uid(),
                command=("review-packet",),
                container_name="ai-review-coordinator-" + "2" * 24,
                mount_candidate=False,
                phase_output_root=nonempty_output,
            )
    finally:
        evidence.close()


def test_keep_id_output_owner_must_match_the_nonroot_launcher_user(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    evidence = _runtime_evidence(tmp_path)
    artifact_root, _candidate = _inputs(tmp_path)
    phase_output = tmp_path / "phase-output-owner"
    phase_output.mkdir(mode=0o700)
    mismatched_uid = phase_output.stat().st_uid + 1
    monkeypatch.setattr("tools.ai_review.coordinator_launcher.os.geteuid", lambda: mismatched_uid)
    try:
        with pytest.raises(CoordinatorLauncherError, match="keep-id user"):
            build_coordinator_invocation(
                evidence=evidence,
                backend=_backend(),
                image="registry.invalid/coordinator@sha256:" + "1" * 64,
                artifact_root=artifact_root,
                candidate_repo=None,
                candidate_uid=_candidate_uid(),
                command=("review-packet",),
                container_name="ai-review-coordinator-" + "3" * 24,
                mount_candidate=False,
                phase_output_root=phase_output,
            )
    finally:
        evidence.close()


@pytest.mark.parametrize(
    "backend",
    [
        _backend(user_namespace=False),
        _backend(rootless=False),
        _backend(name="docker"),
    ],
)
def test_coordinator_rejects_runtime_without_rootless_podman_keep_id(
    tmp_path: Path,
    backend: ContainerBackend,
) -> None:
    evidence = _runtime_evidence(tmp_path)
    artifact_root, candidate = _inputs(tmp_path)
    try:
        with pytest.raises(CoordinatorLauncherError, match="rootless Podman"):
            build_coordinator_invocation(
                evidence=evidence,
                backend=backend,
                image="registry.invalid/coordinator@sha256:" + "1" * 64,
                artifact_root=artifact_root,
                candidate_repo=candidate,
                candidate_uid=_candidate_uid(),
                command=("policy",),
                container_name="ai-review-coordinator-" + "b" * 24,
            )
    finally:
        evidence.close()


def test_coordinator_execution_reprobes_runtime_and_requires_cleanup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    evidence = _runtime_evidence(tmp_path)
    artifact_root, candidate = _inputs(tmp_path)
    backend = _backend()
    detections: list[int] = []
    monkeypatch.setattr("tools.ai_review.coordinator_launcher.os.geteuid", lambda: 1000)

    def detector(**_kwargs):
        detections.append(1)
        return backend

    def runner(*_args, **_kwargs):
        return _BoundedProcessResult(
            exit_code=0,
            stdout=b'{"ok":true}\n',
            stderr=b"",
            stdout_sha256=hashlib.sha256(b'{"ok":true}\n').hexdigest(),
            stderr_sha256=hashlib.sha256(b"").hexdigest(),
            duration_ms=12,
        )

    try:
        result = execute_coordinator(
            evidence=evidence,
            image="registry.invalid/coordinator@sha256:" + "1" * 64,
            artifact_root=artifact_root,
            candidate_repo=candidate,
            command=("policy",),
            container_name="ai-review-coordinator-" + "c" * 24,
            detector=detector,
            runner=runner,
            cleanup=lambda *_args: True,
        )
    finally:
        evidence.close()

    assert len(detections) == 2
    assert result.cleanup_succeeded is True
    assert result.stdout == b'{"ok":true}\n'


def test_coordinator_production_execution_rejects_root_even_with_rootless_probe(
    tmp_path: Path,
) -> None:
    evidence = _runtime_evidence(tmp_path)
    artifact_root, candidate = _inputs(tmp_path)
    try:
        with pytest.raises(CoordinatorLauncherError, match="must not run as root"):
            execute_coordinator(
                evidence=evidence,
                image="registry.invalid/coordinator@sha256:" + "1" * 64,
                artifact_root=artifact_root,
                candidate_repo=candidate,
                command=("snapshot",),
                container_name="ai-review-coordinator-" + "0" * 24,
                detector=lambda **_kwargs: _backend(),
            )
    finally:
        evidence.close()


def test_coordinator_image_rehashes_every_staged_asset_before_cli_import(tmp_path: Path) -> None:
    evidence = _runtime_evidence(tmp_path)
    staging_parent = tmp_path / "staging"
    staging_parent.mkdir(mode=0o700)
    try:
        frozen = freeze_coordinator_assets(evidence, staging_parent / "runtime")
        measured = verify_coordinator_runtime(
            runtime_root=frozen.root,
            manifest_path=frozen.paths["manifest"],
            expected_manifest_sha256=evidence.manifest_sha256,
            expected_coordinator_image_digest=evidence.coordinator_image_digest,
            expected_task_sha256=evidence.task.sha256,
            isolated=True,
        )
        assert measured.harness_sha256 == evidence.harness.sha256

        frozen.paths["task"].chmod(0o644)
        frozen.paths["task"].write_bytes(b'{"forged":true}\n')
        frozen.paths["task"].chmod(0o444)
        with pytest.raises(CoordinatorRuntimeError, match="differs"):
            verify_coordinator_runtime(
                runtime_root=frozen.root,
                manifest_path=frozen.paths["manifest"],
                expected_manifest_sha256=evidence.manifest_sha256,
                expected_coordinator_image_digest=evidence.coordinator_image_digest,
                expected_task_sha256=evidence.task.sha256,
                isolated=True,
            )
    finally:
        evidence.close()


def test_coordinator_cli_consumes_the_externally_bound_runtime_contract(tmp_path: Path) -> None:
    evidence = _runtime_evidence(tmp_path)
    staging_parent = tmp_path / "staging"
    staging_parent.mkdir(mode=0o700)
    try:
        frozen = freeze_coordinator_assets(evidence, staging_parent / "runtime")
        values = {
            "runtime_root": str(frozen.root),
            "runtime_manifest": str(frozen.paths["manifest"]),
            "expected_runtime_manifest_sha256": evidence.manifest_sha256,
            "expected_coordinator_image_digest": evidence.coordinator_image_digest,
            "expected_task_sha256": evidence.task.sha256,
            "task": str(frozen.paths["task"]),
        }
        project_root = Path(__file__).resolve().parents[1]
        script = (
            "import argparse,json,sys;from pathlib import Path;"
            f"sys.path.insert(0,{str(project_root)!r});"
            "from tools.ai_review.cli import _verify_coordinator_inputs;"
            "values=json.loads(sys.argv[1]);"
            "values.update({key:Path(values[key]) for key in "
            "('runtime_root','runtime_manifest','task')});"
            "measured=_verify_coordinator_inputs(argparse.Namespace(**values));"
            "print(measured.manifest_sha256)"
        )
        completed = subprocess.run(
            [sys.executable, "-I", "-c", script, json.dumps(values, sort_keys=True)],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
    finally:
        evidence.close()

    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.strip() == evidence.manifest_sha256
