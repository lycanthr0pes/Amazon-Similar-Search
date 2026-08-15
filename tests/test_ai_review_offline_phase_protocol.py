from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import zipfile
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from tools.ai_review.models import AcceptanceTest
from tools.ai_review.models import CandidateCommitPolicy
from tools.ai_review.models import DiffLimits
from tools.ai_review.models import Requirement
from tools.ai_review.models import ReviewPromptDigests
from tools.ai_review.models import TaskSpec
from tools.ai_review.offline_outer_executor import execute_prepared_offline_outer
from tools.ai_review.offline_phase_protocol import OfflinePhaseProtocolError
from tools.ai_review.offline_phase_protocol import canonical_prepared_offline_batch_bytes
from tools.ai_review.offline_phase_protocol import finalize_offline_batch
from tools.ai_review.offline_phase_protocol import parse_outer_offline_evidence
from tools.ai_review.offline_phase_protocol import parse_prepared_offline_batch
from tools.ai_review.offline_phase_protocol import prepare_offline_batch
from tools.ai_review.phase_execution_adapters import finalize_offline_phase_output
from tools.ai_review.phase_execution_adapters import prepare_offline_phase_action
from tools.ai_review.phase_protocol import CoordinatorPhaseOutput
from tools.ai_review.phase_protocol import PhaseRequest
from tools.ai_review.snapshot import create_readonly_snapshot
from tools.ai_review.snapshot import create_red_tdd_snapshot


def _other_uid() -> int:
    return 65_534 if os.geteuid() != 65_534 else 65_533


def _git(repo: Path, *arguments: str) -> str:
    result = subprocess.run(
        ["git", *arguments],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
        shell=False,
    )
    return result.stdout.strip()


def _snapshots(tmp_path: Path):
    work = tmp_path / "work"
    work.mkdir(mode=0o700)
    _git(work, "init", "-q")
    _git(work, "config", "user.name", "Harness")
    _git(work, "config", "user.email", "harness@example.invalid")
    (work / "src").mkdir()
    (work / "src" / "feature.py").write_text("VALUE = 1\n", encoding="utf-8")
    _git(work, "add", ".")
    _git(work, "commit", "-qm", "base")
    base_sha = _git(work, "rev-parse", "HEAD")
    (work / "src" / "feature.py").write_text("VALUE = 2\n", encoding="utf-8")
    (work / "tests").mkdir()
    (work / "tests" / "test_feature.py").write_text(
        "def test_feature(): assert True\n", encoding="utf-8"
    )
    _git(work, "add", ".")
    _git(work, "commit", "-qm", "candidate")
    candidate_sha = _git(work, "rev-parse", "HEAD")
    bare = tmp_path / "source.git"
    subprocess.run(
        ["git", "clone", "-q", "--bare", "--no-hardlinks", str(work), str(bare)],
        check=True,
        capture_output=True,
        shell=False,
    )
    artifact_root = tmp_path / "coordinator-artifacts"
    snapshot_root = artifact_root / "snapshots"
    red_root = artifact_root / "red"
    artifact_root.mkdir(mode=0o700)
    snapshot_root.mkdir(mode=0o700)
    red_root.mkdir(mode=0o700)
    base = create_readonly_snapshot(
        source_repo=bare,
        commit_sha=base_sha,
        destination_root=snapshot_root,
        candidate_uid=_other_uid(),
    )
    candidate = create_readonly_snapshot(
        source_repo=bare,
        commit_sha=candidate_sha,
        destination_root=snapshot_root,
        candidate_uid=_other_uid(),
    )
    red = create_red_tdd_snapshot(
        base_snapshot=base,
        candidate_snapshot=candidate,
        test_paths=("tests/test_feature.py",),
        destination_root=red_root,
        candidate_uid=_other_uid(),
    )
    return artifact_root, candidate, red


def _task(base_sha: str) -> TaskSpec:
    return TaskSpec(
        schema_version="2.0",
        task_id="TASK-OFFLINE",
        base_sha=base_sha,
        trusted_harness_sha256="1" * 64,
        objective="execute every acceptance phase",
        requirements=[Requirement(id="REQ-1", text="preserve the offline boundary")],
        review_prompts=ReviewPromptDigests(
            reviewer_sha256="2" * 64,
            adversary_sha256="3" * 64,
        ),
        candidate_commit=CandidateCommitPolicy(
            message="candidate",
            author_name="Harness",
            author_email="harness@example.invalid",
            timestamp=0,
            timezone="+0000",
        ),
        acceptance_tests=[
            AcceptanceTest(
                id="AT-TEST",
                kind="test",
                command=["python", "-m", "pytest", "-q"],
                expected_red_exit_codes=[1],
                expected_red_fingerprint_sha256="4" * 64,
                test_paths=["tests/test_feature.py"],
            ),
            AcceptanceTest(
                id="AT-QUALITY",
                kind="quality",
                command=["ruff", "check", "."],
            ),
        ],
        allowed_paths=["src/**", "tests/**"],
        denied_paths=[".env*"],
        limits=DiffLimits(max_changed_files=10, max_added_lines=100),
        network_policy="deny",
    )


def _prepared(tmp_path: Path):
    artifact_root, candidate, red = _snapshots(tmp_path)
    task = _task(red.source_snapshot_sha256[:40])
    batch = prepare_offline_batch(
        workflow_id="5" * 64,
        request_sha256="6" * 64,
        task=task,
        task_sha256="7" * 64,
        candidate_sha256="8" * 64,
        candidate_snapshot=candidate,
        red_snapshots={"AT-TEST": red},
        artifact_root=artifact_root,
        image=f"example.invalid/offline@sha256:{'9' * 64}",
        approved_image_digest=f"sha256:{'9' * 64}",
        candidate_uid=_other_uid(),
        max_log_bytes=4096,
    )
    return artifact_root, candidate, red, task, batch


def test_prepare_offline_batch_is_canonical_complete_and_fail_closed(tmp_path: Path) -> None:
    _artifact_root, _candidate, _red, _task_value, batch = _prepared(tmp_path)
    assert [(run.phase, run.acceptance_test_id) for run in batch.runs] == [
        ("gate", "AT-TEST"),
        ("gate", "AT-QUALITY"),
        ("red", "AT-TEST"),
        ("green", "AT-TEST"),
    ]
    raw = canonical_prepared_offline_batch_bytes(batch)
    assert parse_prepared_offline_batch(raw) == batch

    payload = json.loads(raw)
    payload["caller_descriptor"] = ["podman", "run", "--privileged"]
    with pytest.raises(OfflinePhaseProtocolError, match="unknown fields"):
        parse_prepared_offline_batch(
            (json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n").encode()
        )
    payload.pop("caller_descriptor")
    payload["runs"] = payload["runs"][:-1]
    with pytest.raises(OfflinePhaseProtocolError):
        parse_prepared_offline_batch(
            (json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n").encode()
        )


def test_outer_executes_actual_offline_api_then_coordinator_finalizes_other_mount_namespace(
    tmp_path: Path,
) -> None:
    coordinator_root, candidate, red, task, prepared = _prepared(tmp_path)
    request = PhaseRequest.create(
        workflow_id="5" * 64,
        phase="offline",
        sequence=3,
        previous_phase_sha256="a" * 64,
        task_sha256="7" * 64,
        runtime_manifest_sha256="b" * 64,
        coordinator_key_id="c" * 64,
        coordinator_public_key_sha256="d" * 64,
        candidate_sha256="8" * 64,
        candidate_snapshot_sha256=candidate.snapshot_sha256,
        review_packet_sha256=None,
        input_artifacts_sha256="e" * 64,
    )
    action, prepared_raw = prepare_offline_phase_action(
        request,
        task=task,
        candidate_snapshot=candidate,
        red_snapshots={"AT-TEST": red},
        artifact_root=coordinator_root,
        image=prepared.image,
        approved_image_digest=prepared.approved_image_digest,
        candidate_uid=_other_uid(),
        max_log_bytes=4096,
    )
    prepared = parse_prepared_offline_batch(prepared_raw)
    assert prepared.request_sha256 == request.request_sha256
    action.validate_for(request, prepared_raw)
    outer_root = tmp_path / "outer-artifacts"
    shutil.copytree(coordinator_root, outer_root)
    runtime = tmp_path / "podman"
    runtime.write_bytes(b"trusted fake podman\n")
    runtime.chmod(0o555)

    def probe(argv, **_kwargs):
        assert argv[1:3] == ("info", "--format")
        return SimpleNamespace(
            returncode=0,
            stdout=json.dumps(
                {
                    "host": {
                        "security": {
                            "rootless": True,
                            "seccompEnabled": True,
                            "seccompProfilePath": "/usr/share/containers/seccomp.json",
                        }
                    }
                }
            ),
        )

    observed: list[tuple[str, ...]] = []

    def runner(argv, **_kwargs):
        observed.append(argv)
        cidfile = next(item for item in argv if item.startswith("--cidfile="))
        Path(cidfile.split("=", 1)[1]).write_text("d" * 64 + "\n", encoding="ascii")
        stdout = b""
        stderr = b""
        return SimpleNamespace(
            exit_code=0,
            stdout=stdout,
            stderr=stderr,
            stdout_sha256=hashlib.sha256(stdout).hexdigest(),
            stderr_sha256=hashlib.sha256(stderr).hexdigest(),
            duration_ms=1,
        )

    raw = execute_prepared_offline_outer(
        prepared_raw,
        artifact_root=outer_root,
        candidate_uid=_other_uid(),
        which=lambda name: str(runtime) if name == "podman" else None,
        probe=probe,
        stream_runner=runner,
        cleanup=lambda _backend, _name, _environment: True,
    )
    assert len(observed) == 4
    assert all("--network=none" in argv for argv in observed)
    assert all(not any("docker.sock" in value for value in argv) for argv in observed)
    assert all(str(outer_root) in " ".join(argv) for argv in observed)
    verified = finalize_offline_batch(
        prepared_raw,
        raw,
        artifact_root=coordinator_root,
        candidate_uid=_other_uid(),
    )
    assert tuple((item.request.phase, item.request.acceptance_test_id) for item in verified) == (
        ("gate", "AT-TEST"),
        ("gate", "AT-QUALITY"),
        ("red", "AT-TEST"),
        ("green", "AT-TEST"),
    )
    assert all(str(outer_root) in " ".join(item.argv) for item in verified)
    phase_output = CoordinatorPhaseOutput.model_validate_json(
        finalize_offline_phase_output(
            request,
            action,
            prepared_raw,
            raw,
            artifact_root=coordinator_root,
            candidate_uid=_other_uid(),
        )
    )
    assert [artifact.name for artifact in phase_output.artifacts] == [
        "gate:AT-QUALITY",
        "gate:AT-TEST",
        "tdd-green:AT-TEST",
        "tdd-red:AT-TEST",
    ]

    outer = parse_outer_offline_evidence(raw)
    tampered = replace(
        outer.runs[0],
        request=replace(outer.runs[0].request, acceptance_test_id="AT-QUALITY"),
    )
    with pytest.raises(OfflinePhaseProtocolError):
        from tools.ai_review.offline_phase_protocol import create_outer_offline_evidence

        forged = create_outer_offline_evidence(
            prepared, (tampered, *outer.runs[1:])
        ).canonical_bytes()
        finalize_offline_batch(
            prepared_raw,
            forged,
            artifact_root=coordinator_root,
            candidate_uid=_other_uid(),
        )


def test_offline_outer_modules_import_under_isolated_no_site_python(tmp_path: Path) -> None:
    project = Path(__file__).resolve().parents[1]
    archive = tmp_path / "offline-outer.pyz"
    names = (
        "tools/__init__.py",
        "tools/ai_review/__init__.py",
        "tools/ai_review/preflight.py",
        "tools/ai_review/sensitive_paths.py",
        "tools/ai_review/snapshot.py",
        "tools/ai_review/offline_runner.py",
        "tools/ai_review/offline_phase_protocol.py",
        "tools/ai_review/offline_outer_executor.py",
    )
    with zipfile.ZipFile(archive, "w") as bundle:
        for name in names:
            bundle.write(project / name, name)
    script = """
import json
import sys
sys.path.insert(0, sys.argv[1])
import tools.ai_review.offline_outer_executor
print(json.dumps({
    'isolated': sys.flags.isolated,
    'no_site': sys.flags.no_site,
    'forbidden': sorted(name for name in sys.modules if name.split('.')[0] in {'pydantic', 'cryptography'}),
}))
"""
    result = subprocess.run(
        [sys.executable, "-I", "-S", "-c", script, str(archive)],
        check=True,
        capture_output=True,
        text=True,
        shell=False,
    )
    assert json.loads(result.stdout) == {
        "forbidden": [],
        "isolated": 1,
        "no_site": 1,
    }
