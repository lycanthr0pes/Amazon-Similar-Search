from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from tools.ai_review.broker_outer_executor import _base_environment
from tools.ai_review.broker_outer_executor import _execute_prepared_broker_outer
from tools.ai_review.broker_outer_executor import prepare_broker_outer_ledger
from tools.ai_review.broker_phase_protocol import BrokerRuntimeBinding
from tools.ai_review.broker_phase_protocol import PreparedBrokerBatch
from tools.ai_review.coordinator_workflow_ops import CoordinatorWorkflowOperationError
from tools.ai_review.coordinator_workflow_ops import finalize_workflow_transition
from tools.ai_review.coordinator_workflow_ops import prepare_workflow_transition
from tools.ai_review.coordinator_workflow_inputs import red_snapshot_finalize_inputs
from tools.ai_review.coordinator_workflow_inputs import red_snapshot_prepare_inputs
from tools.ai_review.coordinator_workflow_inputs import snapshot_finalize_inputs
from tools.ai_review.coordinator_workflow_inputs import snapshot_prepare_inputs
from tools.ai_review.egress_policy import canonical_broker_egress_policy_bytes
from tools.ai_review.models import AcceptanceTest
from tools.ai_review.models import CandidateCommitPolicy
from tools.ai_review.models import DiffLimits
from tools.ai_review.models import Requirement
from tools.ai_review.models import ReviewPromptDigests
from tools.ai_review.models import TaskSpec
from tools.ai_review.offline_outer_executor import execute_prepared_offline_outer
from tools.ai_review.offline_phase_protocol import parse_prepared_offline_batch
from tools.ai_review.outer_workflow_state import parse_finalized_transition
from tools.ai_review.outer_workflow_state import parse_prepared_transition
from tools.ai_review.phase_protocol import CoordinatorPhaseOutput
from tools.ai_review.phase_protocol import EMPTY_INITIAL_ARTIFACTS_SHA256
from tools.ai_review.phase_protocol import PhaseRequest
from tools.ai_review.policy import inspect_git_diff
from tools.ai_review.pricing_policy import APPROVED_OPENAI_PRICING_POLICY
from tools.ai_review.pricing_policy import canonical_openai_pricing_policy_bytes
from tests.test_ai_review_broker_egress_provisioner import FakeRuntime
from tests.test_ai_review_broker_egress_provisioner import broker_envelope
from tests.test_ai_review_broker_egress_provisioner import podman_probe
from tests.test_ai_review_broker_phase_protocol import _canonical
from tests.test_ai_review_offline_phase_protocol import _other_uid
from tests.test_ai_review_offline_phase_protocol import _prepared as offline_fixture
from tests.test_ai_review_review_packet import ADVERSARY_PROMPT
from tests.test_ai_review_review_packet import REVIEWER_PROMPT
from tests.test_ai_review_review_packet import make_boundary_evidence
from tests.test_ai_review_review_packet import make_codex_paths
from tests.test_ai_review_review_packet import make_packet


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _git(repo: Path, *arguments: str, env: dict[str, str] | None = None) -> str:
    result = subprocess.run(
        ["git", *arguments],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
        shell=False,
        env={**os.environ, **(env or {})},
    )
    return result.stdout.strip()


def _freeze_tree(root: Path) -> None:
    for directory, directories, filenames in os.walk(root, topdown=False):
        directory_path = Path(directory)
        for name in filenames:
            path = directory_path / name
            path.chmod(0o555 if path.stat().st_mode & 0o111 else 0o444)
        for name in directories:
            (directory_path / name).chmod(0o555)
        directory_path.chmod(0o555)


def _snapshot_workflow_fixture(tmp_path: Path):
    candidate = tmp_path / "candidate"
    candidate.mkdir(mode=0o700)
    _git(candidate, "init", "-q")
    _git(candidate, "config", "user.name", "AI Harness")
    _git(candidate, "config", "user.email", "harness@example.invalid")
    (candidate / "src").mkdir()
    (candidate / "tests").mkdir()
    (candidate / "src" / "feature.py").write_text("VALUE = 1\n", encoding="utf-8")
    (candidate / "tests" / "test_feature.py").write_text(
        "def test_value(): assert 1 == 1\n", encoding="utf-8"
    )
    _git(candidate, "add", ".")
    commit_env = {
        "GIT_AUTHOR_DATE": "2000-01-01T00:00:00+00:00",
        "GIT_COMMITTER_DATE": "2000-01-01T00:00:00+00:00",
    }
    _git(candidate, "commit", "-qm", "base", env=commit_env)
    base_sha = _git(candidate, "rev-parse", "HEAD")
    (candidate / "src" / "feature.py").write_text("VALUE = 2\n", encoding="utf-8")
    (candidate / "tests" / "test_feature.py").write_text(
        "def test_value(): assert 2 == 2\n", encoding="utf-8"
    )
    _git(candidate, "add", ".")
    _git(candidate, "commit", "-qm", "candidate", env=commit_env)
    task = TaskSpec(
        schema_version="2.0",
        task_id="TASK-WORKFLOW-SNAPSHOT",
        base_sha=base_sha,
        trusted_harness_sha256="1" * 64,
        objective="construct and remeasure immutable workflow snapshots",
        requirements=[Requirement(id="REQ-1", text="bind exact snapshot content")],
        review_prompts=ReviewPromptDigests(
            reviewer_sha256="2" * 64,
            adversary_sha256="3" * 64,
        ),
        candidate_commit=CandidateCommitPolicy(
            message="candidate",
            author_name="AI Harness",
            author_email="harness@example.invalid",
            timestamp=946_684_800,
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
            )
        ],
        allowed_paths=["src/**", "tests/**"],
        denied_paths=[".env*", "cache/**"],
        limits=DiffLimits(max_changed_files=10, max_added_lines=100),
        network_policy="deny",
    )
    task_sha256 = "5" * 64
    policy = inspect_git_diff(candidate, task, task_sha256=task_sha256)
    assert policy.passed and policy.patch_sha256 is not None
    _freeze_tree(candidate)
    request = PhaseRequest.create(
        workflow_id="6" * 64,
        phase="snapshot",
        sequence=1,
        previous_phase_sha256=None,
        task_sha256=task_sha256,
        runtime_manifest_sha256="7" * 64,
        coordinator_key_id="8" * 64,
        coordinator_public_key_sha256="9" * 64,
        candidate_sha256=policy.patch_sha256,
        candidate_snapshot_sha256=None,
        review_packet_sha256=None,
        input_artifacts_sha256=EMPTY_INITIAL_ARTIFACTS_SHA256,
    )
    return candidate, task, policy, request


def test_snapshot_and_red_dispatch_create_physical_stores_then_remeasure_finalize(
    tmp_path: Path,
) -> None:
    candidate, task, policy, snapshot_request = _snapshot_workflow_fixture(tmp_path)
    snapshot_output = tmp_path / "snapshot-output"
    snapshot_output.mkdir(mode=0o700)
    prepared_snapshot_raw = prepare_workflow_transition(
        snapshot_request,
        inputs=snapshot_prepare_inputs(
            snapshot_request,
            task=task,
            candidate_repo=candidate,
            output_root=snapshot_output,
            candidate_uid=_other_uid(),
        ),
    )
    prepared_snapshot = parse_prepared_transition(
        prepared_snapshot_raw,
        request=snapshot_request.model_dump(mode="json"),
    )
    snapshot_directories = tuple((snapshot_output / "snapshots").iterdir())
    assert len(snapshot_directories) == 2
    assert all(
        (path / "tree").is_dir() and (path / "manifest.json").is_file()
        for path in snapshot_directories
    )
    assert not any(path.name.startswith(".source-") for path in snapshot_output.rglob("*"))

    snapshot_store = tmp_path / "snapshot-store"
    snapshot_store.mkdir(mode=0o700)
    (snapshot_output / "snapshots").rename(snapshot_store / "snapshots")
    _freeze_tree(snapshot_store / "snapshots")
    finalized_snapshot_raw = finalize_workflow_transition(
        snapshot_request,
        prepared_transition=prepared_snapshot_raw,
        execution_evidence=prepared_snapshot.payload,
        inputs=snapshot_finalize_inputs(
            snapshot_request,
            snapshot_artifact_root=snapshot_store,
            candidate_uid=_other_uid(),
        ),
    )
    finalized_snapshot = parse_finalized_transition(
        finalized_snapshot_raw,
        request=snapshot_request.model_dump(mode="json"),
        external_raw=None,
    )
    snapshot_output_model = CoordinatorPhaseOutput.model_validate_json(
        finalized_snapshot.coordinator_output
    )
    assert [artifact.name for artifact in snapshot_output_model.artifacts] == [
        "base-snapshot",
        "candidate-snapshot",
        "policy",
    ]
    assert json.loads(snapshot_output_model.artifacts[-1].content()) == policy.model_dump(
        mode="json"
    )
    assert finalized_snapshot.result["external_execution_sha256"] is None
    assert finalized_snapshot.next_request is not None

    committed = tmp_path / "snapshot-committed"
    committed.mkdir(mode=0o700)
    (committed / "coordinator-output.json").write_bytes(finalized_snapshot.coordinator_output)
    _freeze_tree(committed)
    red_request = PhaseRequest.model_validate_json(finalized_snapshot.next_request)
    red_output = tmp_path / "red-output"
    red_output.mkdir(mode=0o700)
    prepared_red_raw = prepare_workflow_transition(
        red_request,
        inputs=red_snapshot_prepare_inputs(
            red_request,
            task=task,
            artifact_root=committed,
            snapshot_artifact_root=snapshot_store,
            output_root=red_output,
            candidate_uid=_other_uid(),
        ),
    )
    prepared_red = parse_prepared_transition(
        prepared_red_raw,
        request=red_request.model_dump(mode="json"),
    )
    physical_red = tuple((red_output / "red-snapshots").iterdir())
    assert len(physical_red) == 1
    assert (physical_red[0] / "tree" / "tests" / "test_feature.py").is_file()
    (red_output / "red-snapshots").rename(snapshot_store / "red-snapshots")
    _freeze_tree(snapshot_store)
    finalized_red_raw = finalize_workflow_transition(
        red_request,
        prepared_transition=prepared_red_raw,
        execution_evidence=prepared_red.payload,
        inputs=red_snapshot_finalize_inputs(
            red_request,
            task=task,
            artifact_root=committed,
            snapshot_artifact_root=snapshot_store,
            candidate_uid=_other_uid(),
        ),
    )
    finalized_red = parse_finalized_transition(
        finalized_red_raw,
        request=red_request.model_dump(mode="json"),
        external_raw=None,
    )
    red_output_model = CoordinatorPhaseOutput.model_validate_json(finalized_red.coordinator_output)
    assert [artifact.name for artifact in red_output_model.artifacts] == ["red-snapshot:AT-TEST"]
    assert red_output_model.artifacts[0].content().decode("ascii") == physical_red[0].name
    assert finalized_red.result["external_execution_sha256"] is None
    assert finalized_red.next_request is not None
    assert b'"phase":"offline"' in finalized_red.next_request


def test_snapshot_finalize_rejects_candidate_mount_field_and_tampered_physical_content(
    tmp_path: Path,
) -> None:
    candidate, task, _policy, request = _snapshot_workflow_fixture(tmp_path)
    output = tmp_path / "snapshot-output"
    output.mkdir(mode=0o700)
    prepared_raw = prepare_workflow_transition(
        request,
        inputs=snapshot_prepare_inputs(
            request,
            task=task,
            candidate_repo=candidate,
            output_root=output,
            candidate_uid=_other_uid(),
        ),
    )
    prepared = parse_prepared_transition(
        prepared_raw,
        request=request.model_dump(mode="json"),
    )
    store = tmp_path / "snapshot-store"
    store.mkdir(mode=0o700)
    (output / "snapshots").rename(store / "snapshots")
    finalize_inputs = snapshot_finalize_inputs(
        request,
        snapshot_artifact_root=store,
        candidate_uid=_other_uid(),
    )
    with pytest.raises(CoordinatorWorkflowOperationError, match="unknown fields"):
        finalize_workflow_transition(
            request,
            prepared_transition=prepared_raw,
            execution_evidence=prepared.payload,
            inputs={**finalize_inputs, "candidate_repo": candidate},
        )
    candidate_digest = json.loads(prepared.payload)["candidate_snapshot"]["snapshot_sha256"]
    target = store / "snapshots" / candidate_digest / "tree" / "src" / "feature.py"
    target.chmod(0o600)
    target.write_text("VALUE = 999\n", encoding="utf-8")
    target.chmod(0o444)
    with pytest.raises(CoordinatorWorkflowOperationError, match="snapshot"):
        finalize_workflow_transition(
            request,
            prepared_transition=prepared_raw,
            execution_evidence=prepared.payload,
            inputs=finalize_inputs,
        )


def _offline_request(candidate_sha256: str) -> PhaseRequest:
    return PhaseRequest.create(
        workflow_id="5" * 64,
        phase="offline",
        sequence=3,
        previous_phase_sha256="a" * 64,
        task_sha256="7" * 64,
        runtime_manifest_sha256="b" * 64,
        coordinator_key_id="c" * 64,
        coordinator_public_key_sha256="d" * 64,
        candidate_sha256="8" * 64,
        candidate_snapshot_sha256=candidate_sha256,
        review_packet_sha256=None,
        input_artifacts_sha256="e" * 64,
    )


def test_offline_dispatch_derives_descriptor_and_finalizes_actual_outer_evidence(
    tmp_path: Path,
) -> None:
    artifact_root, candidate, red, task, fixture = offline_fixture(tmp_path)
    request = _offline_request(candidate.snapshot_sha256)
    prepare_inputs = {
        "approved_image_digest": fixture.approved_image_digest,
        "artifact_root": artifact_root,
        "candidate_snapshot": candidate,
        "candidate_uid": _other_uid(),
        "image": fixture.image,
        "red_snapshots": {"AT-TEST": red},
        "task": task,
    }
    prepared_transition = prepare_workflow_transition(request, inputs=prepare_inputs)
    prepared = parse_prepared_transition(
        prepared_transition,
        request=request.model_dump(mode="json"),
    )
    batch = parse_prepared_offline_batch(prepared.payload)
    assert [(run.phase, run.acceptance_test_id) for run in batch.runs] == [
        ("gate", "AT-TEST"),
        ("gate", "AT-QUALITY"),
        ("red", "AT-TEST"),
        ("green", "AT-TEST"),
    ]

    outer_root = tmp_path / "outer-artifacts"
    shutil.copytree(artifact_root, outer_root)
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

    def runner(argv, **_kwargs):
        cidfile = next(item for item in argv if item.startswith("--cidfile="))
        Path(cidfile.split("=", 1)[1]).write_text("d" * 64 + "\n", encoding="ascii")
        return SimpleNamespace(
            exit_code=0,
            stdout=b"",
            stderr=b"",
            stdout_sha256=_sha256(b""),
            stderr_sha256=_sha256(b""),
            duration_ms=1,
        )

    outer_raw = execute_prepared_offline_outer(
        prepared.payload,
        artifact_root=outer_root,
        candidate_uid=_other_uid(),
        which=lambda name: str(runtime) if name == "podman" else None,
        probe=probe,
        stream_runner=runner,
        cleanup=lambda _backend, _name, _environment: True,
    )
    finalized_raw = finalize_workflow_transition(
        request,
        prepared_transition=prepared_transition,
        execution_evidence=outer_raw,
        inputs={"artifact_root": artifact_root, "candidate_uid": _other_uid()},
    )
    finalized = parse_finalized_transition(
        finalized_raw,
        request=request.model_dump(mode="json"),
        external_raw=outer_raw,
    )
    output = CoordinatorPhaseOutput.model_validate_json(finalized.coordinator_output)
    assert [artifact.name for artifact in output.artifacts] == [
        "gate:AT-QUALITY",
        "gate:AT-TEST",
        "tdd-green:AT-TEST",
        "tdd-red:AT-TEST",
    ]
    assert finalized.result["external_execution_sha256"] == _sha256(outer_raw)
    assert finalized.next_request is not None
    assert b'"phase":"review-packet"' in finalized.next_request


def _broker_runtime(runtime_path: Path) -> BrokerRuntimeBinding:
    security = {
        "name": "podman",
        "rootless": True,
        "seccomp_profile": "/usr/share/containers/seccomp.json",
        "user_namespace": True,
    }
    return BrokerRuntimeBinding(
        name="podman",
        executable_sha256=_sha256(runtime_path.read_bytes()),
        environment_sha256=_sha256(_canonical(_base_environment("podman"))),
        rootless=True,
        user_namespace=True,
        seccomp_profile="/usr/share/containers/seccomp.json",
        security_evidence_sha256=_sha256(_canonical(security) + b"\n"),
    )


def test_broker_dispatch_builds_fixed_role_descriptors_and_finalizes_frozen_ledger(
    tmp_path: Path,
) -> None:
    packet = make_packet()
    coordinator, schema, _output = make_codex_paths(tmp_path)
    runtime_path = tmp_path / "podman"
    runtime_path.write_bytes(b"trusted broker runtime\n")
    runtime_path.chmod(0o555)
    runtime = _broker_runtime(runtime_path)
    allowlist = canonical_broker_egress_policy_bytes()
    pricing = canonical_openai_pricing_policy_bytes()
    broker_digest = "sha256:" + "6" * 64
    gateway_digest = "sha256:" + "7" * 64
    ledger_path = tmp_path / "ledger" / "broker.sqlite3"
    ledger_path.parent.mkdir(mode=0o700)
    ledger_identity = prepare_broker_outer_ledger(
        ledger_path,
        candidate_uid=_other_uid(),
    )
    request = PhaseRequest.create(
        workflow_id="1" * 64,
        phase="broker",
        sequence=5,
        previous_phase_sha256="2" * 64,
        task_sha256=packet.task_sha256,
        runtime_manifest_sha256="3" * 64,
        coordinator_key_id="4" * 64,
        coordinator_public_key_sha256="5" * 64,
        candidate_sha256="8" * 64,
        candidate_snapshot_sha256="9" * 64,
        review_packet_sha256=packet.packet_sha256,
        input_artifacts_sha256="a" * 64,
    )
    prepare_inputs = {
        "adversary_prompt": ADVERSARY_PROMPT,
        "allowlist_policy": allowlist,
        "approved_image_digest": broker_digest,
        "boundary_evidence": make_boundary_evidence(packet.packet_sha256),
        "broker_allowlist_policy_sha256": _sha256(allowlist),
        "broker_gateway_image_digest": gateway_digest,
        "broker_ledger_identity_sha256": ledger_identity,
        "broker_packet_cost_limit_microusd": 4_540_000,
        "broker_packet_reservation_limit": 544_000,
        "broker_pricing_policy_sha256": APPROVED_OPENAI_PRICING_POLICY.sha256,
        "candidate_uid": _other_uid(),
        "gateway_image": f"registry.invalid/review-gateway@{gateway_digest}",
        "image": f"registry.invalid/review-broker@{broker_digest}",
        "output_schema": schema,
        "packet": packet,
        "pricing_policy": pricing,
        "reviewer_prompt": REVIEWER_PROMPT,
        "runtime": runtime,
        "task": packet.task,
        "trusted_cwd": coordinator,
    }
    prepared_transition = prepare_workflow_transition(request, inputs=prepare_inputs)
    prepared = parse_prepared_transition(
        prepared_transition,
        request=request.model_dump(mode="json"),
    )
    batch = PreparedBrokerBatch.parse(prepared.payload)
    assert tuple(run.role for run in batch.runs) == ("reviewer", "adversary")
    assert all(run.descriptor_argv[0:2] == ("podman", "run") for run in batch.runs)
    assert all(not any("/candidate" in item for item in run.descriptor_argv) for run in batch.runs)
    assert b"OPENAI_API_KEY=" not in prepared.payload
    with pytest.raises(CoordinatorWorkflowOperationError, match="changed the verified TaskSpec"):
        prepare_workflow_transition(
            request,
            inputs={
                **prepare_inputs,
                "task": packet.task.model_copy(update={"objective": "substituted task"}),
            },
        )

    fake = FakeRuntime()

    def stream_runner(argv, *, stdin_bytes, **_kwargs):
        return FakeRuntime._result(
            tuple(argv),
            0,
            stdout=broker_envelope(_sha256(stdin_bytes[:-1])),
        )

    outer_raw = _execute_prepared_broker_outer(
        prepared.payload,
        credentials={"reviewer": "secret-reviewer", "adversary": "secret-adversary"},
        ledger_path=ledger_path,
        runtime_executable=runtime_path,
        require_two=True,
        runner=fake,
        stream_runner=stream_runner,
        probe=podman_probe,
        broker_cleanup=lambda *_args: True,
    )
    finalized_raw = finalize_workflow_transition(
        request,
        prepared_transition=prepared_transition,
        execution_evidence=outer_raw,
        inputs={"allowlist_policy": allowlist, "pricing_policy": pricing},
    )
    finalized = parse_finalized_transition(
        finalized_raw,
        request=request.model_dump(mode="json"),
        external_raw=outer_raw,
    )
    output = CoordinatorPhaseOutput.model_validate_json(finalized.coordinator_output)
    assert [artifact.name for artifact in output.artifacts] == ["adversary", "reviewer"]
    assert finalized.result["external_execution_sha256"] == _sha256(outer_raw)
    assert b"secret-reviewer" not in finalized_raw
    assert finalized.next_request is not None
    assert b'"phase":"sign"' in finalized.next_request


def test_dispatch_rejects_unknown_fields_caller_descriptors_and_incomplete_sign_inputs(
    tmp_path: Path,
) -> None:
    artifact_root, candidate, red, task, fixture = offline_fixture(tmp_path)
    request = _offline_request(candidate.snapshot_sha256)
    inputs = {
        "approved_image_digest": fixture.approved_image_digest,
        "artifact_root": artifact_root,
        "candidate_snapshot": candidate,
        "candidate_uid": _other_uid(),
        "image": fixture.image,
        "red_snapshots": {"AT-TEST": red},
        "task": task,
    }
    with pytest.raises(CoordinatorWorkflowOperationError, match="unknown fields"):
        prepare_workflow_transition(request, inputs={**inputs, "unexpected": True})
    with pytest.raises(CoordinatorWorkflowOperationError, match="caller-supplied"):
        prepare_workflow_transition(
            request,
            inputs={**inputs, "descriptor": ["podman", "run", "--privileged"]},
        )
    with pytest.raises(CoordinatorWorkflowOperationError, match="caller-supplied"):
        prepare_workflow_transition(request, inputs={**inputs, "invocations": ()})
    sign = PhaseRequest.create(
        workflow_id="1" * 64,
        phase="sign",
        sequence=6,
        previous_phase_sha256="2" * 64,
        task_sha256="3" * 64,
        runtime_manifest_sha256="4" * 64,
        coordinator_key_id="5" * 64,
        coordinator_public_key_sha256="6" * 64,
        candidate_sha256="7" * 64,
        candidate_snapshot_sha256="8" * 64,
        review_packet_sha256="9" * 64,
        input_artifacts_sha256="a" * 64,
    )
    with pytest.raises(CoordinatorWorkflowOperationError, match="missing or unknown fields"):
        prepare_workflow_transition(sign, inputs={})


def test_finalize_recovers_action_only_from_prepared_envelope(tmp_path: Path) -> None:
    artifact_root, candidate, red, task, fixture = offline_fixture(tmp_path)
    request = _offline_request(candidate.snapshot_sha256)
    prepared = prepare_workflow_transition(
        request,
        inputs={
            "approved_image_digest": fixture.approved_image_digest,
            "artifact_root": artifact_root,
            "candidate_snapshot": candidate,
            "candidate_uid": _other_uid(),
            "image": fixture.image,
            "red_snapshots": {"AT-TEST": red},
            "task": task,
        },
    )
    with pytest.raises(CoordinatorWorkflowOperationError, match="caller-supplied"):
        finalize_workflow_transition(
            request,
            prepared_transition=prepared,
            execution_evidence=b"{}\n",
            inputs={
                "artifact_root": artifact_root,
                "candidate_uid": _other_uid(),
                "action": {"external_kind": "none"},
            },
        )
