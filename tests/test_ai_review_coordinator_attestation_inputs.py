from __future__ import annotations

import hashlib
import json
import shutil
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from tools.ai_review.attestation import AttestationStatement
from tools.ai_review.attestation import InMemoryNonceLedger
from tools.ai_review.attestation import public_key_id
from tools.ai_review.attestation import sign_attestation
from tools.ai_review.attested_judge import TrustedAttestationContext
from tools.ai_review.attested_judge import build_frozen_bundle_expectations
from tools.ai_review.attested_judge import derive_offline_artifacts
from tools.ai_review.attested_judge import judge_frozen_attestation_bundle
from tools.ai_review.broker_outer_executor import _base_environment
from tools.ai_review.broker_outer_executor import _execute_prepared_broker_outer
from tools.ai_review.broker_outer_executor import prepare_broker_outer_ledger
from tools.ai_review.broker_phase_protocol import BrokerRuntimeBinding
from tools.ai_review.broker_phase_protocol import canonical_prepared_broker_batch_bytes
from tools.ai_review.broker_phase_protocol import prepare_provisioned_broker_execution
from tools.ai_review.codex_adapter import BrokerBoundaryEvidence
from tools.ai_review.codex_adapter import CodexAdapter
from tools.ai_review.coordinator_attestation_inputs import reconstruct_attestation_inputs
from tools.ai_review.coordinator_attestation_inputs import CoordinatorAttestationInputError
from tools.ai_review.coordinator_phase_protocol import prepare_transition_bytes
from tools.ai_review.coordinator_runtime import CoordinatorRuntimeEvidence
from tools.ai_review.coordinator_workflow_ops import finalize_workflow_transition
from tools.ai_review.coordinator_workflow_ops import prepare_workflow_transition
from tools.ai_review.egress_policy import canonical_broker_egress_policy_bytes
from tools.ai_review.offline_outer_executor import execute_prepared_offline_outer
from tools.ai_review.offline_phase_protocol import canonical_prepared_offline_batch_bytes
from tools.ai_review.offline_phase_protocol import offline_evidence_from_dict
from tools.ai_review.offline_phase_protocol import prepare_offline_batch
from tools.ai_review.outer_workflow_state import parse_finalized_transition
from tools.ai_review.outer_workflow_state import parse_prepared_transition
from tools.ai_review.models import Verdict
from tools.ai_review.phase_execution_adapters import finalize_broker_phase_output
from tools.ai_review.phase_execution_adapters import finalize_offline_phase_output
from tools.ai_review.phase_protocol import PHASE_ORDER
from tools.ai_review.phase_protocol import CoordinatorPhaseOutput
from tools.ai_review.phase_protocol import EMPTY_INITIAL_ARTIFACTS_SHA256
from tools.ai_review.phase_protocol import PhaseAction
from tools.ai_review.phase_protocol import PhaseOutputArtifact
from tools.ai_review.phase_protocol import PhaseRequest
from tools.ai_review.phase_protocol import PhaseResult
from tools.ai_review.phase_protocol import canonical_json_bytes
from tools.ai_review.pricing_policy import APPROVED_OPENAI_PRICING_POLICY
from tools.ai_review.pricing_policy import canonical_openai_pricing_policy_bytes
from tools.ai_review.review_packet import build_review_packet_from_snapshots
from tools.ai_review.review_packet import canonical_packet_bytes
from tools.ai_review.snapshot import measure_red_tdd_snapshot
from tools.ai_review.snapshot import verify_readonly_snapshot
from tests import test_ai_review_attested_judge as strict_fixtures
from tests.test_ai_review_broker_egress_provisioner import FakeRuntime
from tests.test_ai_review_broker_egress_provisioner import podman_probe


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _next_request(result: PhaseResult, output: CoordinatorPhaseOutput) -> PhaseRequest:
    request = result.request
    return PhaseRequest.create(
        workflow_id=request.workflow_id,
        phase=PHASE_ORDER[request.sequence],
        sequence=request.sequence + 1,
        previous_phase_sha256=result.phase_sha256,
        task_sha256=request.task_sha256,
        runtime_manifest_sha256=request.runtime_manifest_sha256,
        coordinator_key_id=request.coordinator_key_id,
        coordinator_public_key_sha256=request.coordinator_public_key_sha256,
        candidate_sha256=request.candidate_sha256,
        candidate_snapshot_sha256=output.candidate_snapshot_sha256,
        review_packet_sha256=output.review_packet_sha256,
        input_artifacts_sha256=output.output_artifacts_sha256,
    )


def _result(
    request: PhaseRequest,
    output: CoordinatorPhaseOutput,
    *,
    external: bytes | None = None,
) -> PhaseResult:
    raw = canonical_json_bytes(output)
    return PhaseResult.create(
        request=request,
        output_artifacts_sha256=output.output_artifacts_sha256,
        artifacts=output.phase_artifacts(),
        candidate_snapshot_sha256=output.candidate_snapshot_sha256,
        review_packet_sha256=output.review_packet_sha256,
        external_execution_sha256=_sha(external) if external is not None else None,
        coordinator_output_sha256=_sha(raw),
    )


def _commit(
    root: Path,
    result: PhaseResult,
    output: CoordinatorPhaseOutput,
    *,
    prepared: bytes | None = None,
    transition: bytes | None = None,
    external: bytes | None = None,
    runtime_binding: bytes | None = None,
) -> None:
    directory = root / f"{result.request.sequence:02d}-{result.request.phase}"
    directory.mkdir()
    (directory / "phase-result.json").write_bytes(canonical_json_bytes(result))
    (directory / "coordinator-output.json").write_bytes(canonical_json_bytes(output))
    if prepared is not None:
        assert transition is not None and external is not None
        (directory / "prepared-payload.json").write_bytes(prepared)
        (directory / "prepared-transition.json").write_bytes(transition)
        (directory / "external-evidence.json").write_bytes(external)
    if runtime_binding is not None:
        (directory / "broker-runtime-binding.json").write_bytes(runtime_binding)


def _build_fixture(tmp_path: Path, *, private_key: Ed25519PrivateKey | None = None):
    source_root = tmp_path / "source"
    source_root.mkdir(mode=0o700)
    source = strict_fixtures.make_strict_bundle(source_root)
    task = strict_fixtures.make_task()
    # Production binds the exact (possibly pretty-printed) mounted TaskSpec bytes,
    # not a coordinator reserialization of the parsed model.
    task_sha256 = _sha(b"pretty mounted TaskSpec fixture bytes\n")
    strict_fixtures.TASK_SHA = task_sha256
    policy = strict_fixtures.make_policy(task)
    candidate_uid = source.candidate_uid

    snapshots = tmp_path / "snapshot-artifacts"
    (snapshots / "snapshots").mkdir(parents=True)
    (snapshots / "red-snapshots").mkdir()
    shutil.copytree(
        source.base_snapshot.root,
        snapshots / "snapshots" / source.base_snapshot.snapshot_sha256,
    )
    shutil.copytree(
        source.candidate_snapshot.root,
        snapshots / "snapshots" / source.candidate_snapshot.snapshot_sha256,
    )
    shutil.copytree(
        source.red_snapshots[0].snapshot.root,
        snapshots / "red-snapshots" / source.red_snapshots[0].snapshot.snapshot_sha256,
    )
    base = verify_readonly_snapshot(
        snapshots / "snapshots" / source.base_snapshot.snapshot_sha256,
        candidate_uid=candidate_uid,
    )
    candidate = verify_readonly_snapshot(
        snapshots / "snapshots" / source.candidate_snapshot.snapshot_sha256,
        candidate_uid=candidate_uid,
    )
    acceptance = next(item for item in task.acceptance_tests if item.kind == "test")
    red = measure_red_tdd_snapshot(
        red_root=snapshots / "red-snapshots" / source.red_snapshots[0].snapshot.snapshot_sha256,
        base_snapshot=base,
        candidate_snapshot=candidate,
        test_paths=tuple(acceptance.test_paths),
        candidate_uid=candidate_uid,
    )

    allowlist = canonical_broker_egress_policy_bytes()
    pricing = canonical_openai_pricing_policy_bytes()
    runtime = tmp_path / "runtime"
    runtime.mkdir(mode=0o700)
    (runtime / "broker-egress-policy.json").write_bytes(allowlist)
    (runtime / "openai-pricing-policy.json").write_bytes(pricing)
    private_key = private_key or Ed25519PrivateKey.generate()
    public_raw = private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    (runtime / "coordinator-public-key.pem").write_bytes(public_raw)
    coordinator = CoordinatorRuntimeEvidence(
        manifest_sha256=strict_fixtures.RUNTIME_SHA,
        coordinator_image_digest=strict_fixtures.COORDINATOR_IMAGE_DIGEST,
        harness_sha256="1" * 64,
        task_sha256=task_sha256,
        dependency_lock_sha256="2" * 64,
        schema_bundle_sha256="3" * 64,
        coordinator_public_key_sha256=_sha(public_raw),
        offline_runner_image_digest=strict_fixtures.OFFLINE_IMAGE_DIGEST,
        broker_image_digest=strict_fixtures.BROKER_IMAGE_DIGEST,
        broker_gateway_image_digest=strict_fixtures.BROKER_GATEWAY_IMAGE_DIGEST,
        broker_allowlist_policy_sha256=_sha(allowlist),
        broker_packet_reservation_limit=544_000,
        broker_pricing_policy_sha256=APPROVED_OPENAI_PRICING_POLICY.sha256,
        broker_packet_cost_limit_microusd=4_540_000,
    )
    workflow_id = "5" * 64
    request = PhaseRequest.create(
        workflow_id=workflow_id,
        phase="snapshot",
        sequence=1,
        previous_phase_sha256=None,
        task_sha256=task_sha256,
        runtime_manifest_sha256=coordinator.manifest_sha256,
        coordinator_key_id=public_key_id(private_key.public_key()),
        coordinator_public_key_sha256=coordinator.coordinator_public_key_sha256,
        candidate_sha256=policy.patch_sha256,
        candidate_snapshot_sha256=None,
        review_packet_sha256=None,
        input_artifacts_sha256=EMPTY_INITIAL_ARTIFACTS_SHA256,
    )
    artifact_root = tmp_path / "artifacts"
    artifact_root.mkdir(mode=0o700)
    snapshot_output = CoordinatorPhaseOutput.create(
        request=request,
        artifacts=(
            PhaseOutputArtifact.create("base-snapshot", base.snapshot_sha256.encode()),
            PhaseOutputArtifact.create("candidate-snapshot", candidate.snapshot_sha256.encode()),
            PhaseOutputArtifact.create("policy", canonical_json_bytes(policy)),
        ),
    )
    snapshot_result = _result(request, snapshot_output)
    _commit(artifact_root, snapshot_result, snapshot_output)
    request = _next_request(snapshot_result, snapshot_output)

    red_output = CoordinatorPhaseOutput.create(
        request=request,
        artifacts=(
            PhaseOutputArtifact.create(
                "red-snapshot:" + acceptance.id,
                red.snapshot.snapshot_sha256.encode(),
            ),
        ),
    )
    red_result = _result(request, red_output)
    _commit(artifact_root, red_result, red_output)
    request = _next_request(red_result, red_output)

    offline_prepared = prepare_offline_batch(
        workflow_id=workflow_id,
        request_sha256=request.request_sha256,
        task=task,
        task_sha256=task_sha256,
        candidate_sha256=policy.patch_sha256,
        candidate_snapshot=candidate,
        red_snapshots={acceptance.id: red},
        artifact_root=snapshots,
        image=source.offline_runner_image,
        approved_image_digest=coordinator.offline_runner_image_digest,
        candidate_uid=candidate_uid,
    )
    offline_prepared_raw = canonical_prepared_offline_batch_bytes(offline_prepared)
    planned = iter(offline_prepared.runs)

    def offline_runner(argv, **_kwargs):
        run = next(planned)
        cidfile = next(item for item in argv if item.startswith("--cidfile="))
        Path(cidfile.split("=", 1)[1]).write_text("d" * 64 + "\n", encoding="ascii")
        if run.phase == "red":
            exit_code, stdout = 1, b"expected RED failure\n"
        elif run.phase == "green":
            exit_code, stdout = 0, b"GREEN passed\n"
        else:
            expected = next(
                item for item in task.acceptance_tests if item.id == run.acceptance_test_id
            )
            exit_code, stdout = (
                expected.expected_exit_code,
                f"gate {run.acceptance_test_id}\n".encode(),
            )
        return SimpleNamespace(
            exit_code=exit_code,
            stdout=stdout,
            stderr=b"",
            stdout_sha256=_sha(stdout),
            stderr_sha256=_sha(b""),
            duration_ms=1,
        )

    offline_outer_raw = execute_prepared_offline_outer(
        offline_prepared_raw,
        artifact_root=snapshots,
        candidate_uid=candidate_uid,
        which=lambda name: str(source.broker_runtime_binary) if name == "podman" else None,
        probe=source.broker_runtime_probe,
        stream_runner=offline_runner,
        cleanup=lambda *_args: True,
    )
    offline_action = PhaseAction.create(
        request=request,
        external_kind="offline",
        payload_sha256=_sha(offline_prepared_raw),
    )
    offline_transition = prepare_transition_bytes(request, offline_action, offline_prepared_raw)
    offline_output = CoordinatorPhaseOutput.model_validate_json(
        finalize_offline_phase_output(
            request,
            offline_action,
            offline_prepared_raw,
            offline_outer_raw,
            artifact_root=snapshots,
            candidate_uid=candidate_uid,
        )
    )
    offline_result = _result(request, offline_output, external=offline_outer_raw)
    _commit(
        artifact_root,
        offline_result,
        offline_output,
        prepared=offline_prepared_raw,
        transition=offline_transition,
        external=offline_outer_raw,
    )
    request = _next_request(offline_result, offline_output)

    preliminary = TrustedAttestationContext(
        runtime_manifest_sha256=coordinator.manifest_sha256,
        coordinator_image_digest=coordinator.coordinator_image_digest,
        offline_runner_image_digest=coordinator.offline_runner_image_digest,
        broker_image_digest=coordinator.broker_image_digest,
        broker_gateway_image_digest=coordinator.broker_gateway_image_digest,
        broker_egress_boundary_sha256="8" * 64,
        broker_allowlist_policy_sha256=coordinator.broker_allowlist_policy_sha256,
        broker_ledger_identity_sha256="9" * 64,
        broker_packet_reservation_limit=coordinator.broker_packet_reservation_limit,
        broker_pricing_policy_sha256=coordinator.broker_pricing_policy_sha256,
        broker_packet_cost_limit_microusd=coordinator.broker_packet_cost_limit_microusd,
        base_snapshot_sha256=base.snapshot_sha256,
        base_snapshot_manifest_sha256=base.manifest_sha256,
        base_commit_tree_sha=base.commit_tree_sha,
        candidate_snapshot_sha256=candidate.snapshot_sha256,
        candidate_snapshot_manifest_sha256=candidate.manifest_sha256,
        candidate_commit_tree_sha=candidate.commit_tree_sha,
        review_packet_sha256="a" * 64,
        review_output_schema_sha256="b" * 64,
    )
    gates, tdds, _bindings = derive_offline_artifacts(
        task=task,
        policy=policy,
        task_sha256=task_sha256,
        raw_runs=tuple(
            # The coordinator output holds the exact full evidence just finalized above.
            offline_evidence_from_dict(json.loads(item.content()))
            for item in offline_output.artifacts
        ),
        base_snapshot=base,
        candidate_snapshot=candidate,
        red_snapshots=(red,),
        offline_runner_image=source.offline_runner_image,
        context=preliminary,
        candidate_uid=candidate_uid,
    )
    packet = build_review_packet_from_snapshots(
        task=task,
        task_sha256=task_sha256,
        policy=policy,
        base_snapshot_root=base.root,
        candidate_snapshot_root=candidate.root,
        context_paths=(),
        candidate_uid=candidate_uid,
        gates=gates,
        tdd_evidence=tdds,
    )
    packet_output = CoordinatorPhaseOutput.create(
        request=request,
        artifacts=(PhaseOutputArtifact.create("review-packet", canonical_packet_bytes(packet)),),
    )
    packet_result = _result(request, packet_output)
    _commit(artifact_root, packet_result, packet_output)
    request = _next_request(packet_result, packet_output)

    requests = strict_fixtures.make_broker_requests(packet)
    reviews = strict_fixtures.make_reviews(task, packet, requests)
    security = {
        "name": "podman",
        "rootless": True,
        "seccomp_profile": "/usr/share/containers/seccomp.json",
        "user_namespace": True,
    }
    runtime_binding = BrokerRuntimeBinding(
        name="podman",
        executable_sha256=_sha(source.broker_runtime_binary.read_bytes()),
        environment_sha256=_sha(
            json.dumps(
                _base_environment("podman"),
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode()
        ),
        rootless=True,
        user_namespace=True,
        seccomp_profile=security["seccomp_profile"],
        security_evidence_sha256=_sha(canonical_json_bytes(security)),
    )
    runtime_binding_raw = canonical_json_bytes(vars(runtime_binding))
    boundary = BrokerBoundaryEvidence(
        packet_sha256=packet.packet_sha256,
        external_preflight_sha256=_sha(runtime_binding_raw),
        snapshot_manifest_sha256=candidate.manifest_sha256,
        isolation_attestation_sha256=runtime_binding.security_evidence_sha256,
        candidate_filesystem_unmounted=True,
        read_only_snapshot_verified=True,
        network_isolation_verified=True,
        coordinator_attestation_verified=True,
    )
    adapter = CodexAdapter()
    broker_image = f"example.invalid/review-broker@{coordinator.broker_image_digest}"
    invocations = tuple(
        adapter.build_isolated_broker_invocation(
            request=item,
            packet=packet,
            boundary_evidence=boundary,
            container_runtime="podman",
            image=broker_image,
            approved_image_digest=coordinator.broker_image_digest,
            allow_external_ai=True,
            allow_isolated_broker=True,
        )
        for item in requests
    )
    ledger = tmp_path / "outer-ledger" / "broker.sqlite3"
    ledger.parent.mkdir(mode=0o700)
    ledger_identity = prepare_broker_outer_ledger(ledger, candidate_uid=candidate_uid)
    broker_prepared = prepare_provisioned_broker_execution(
        workflow_id=workflow_id,
        phase_request_sha256=request.request_sha256,
        task_sha256=task_sha256,
        runtime_manifest_sha256=coordinator.manifest_sha256,
        candidate_snapshot_sha256=candidate.snapshot_sha256,
        review_packet_sha256=packet.packet_sha256,
        invocations=invocations,
        runtime=runtime_binding,
        gateway_image=(f"example.invalid/review-gateway@{coordinator.broker_gateway_image_digest}"),
        broker_gateway_image_digest=coordinator.broker_gateway_image_digest,
        allowlist_policy=allowlist,
        broker_allowlist_policy_sha256=coordinator.broker_allowlist_policy_sha256,
        pricing_policy=pricing,
        broker_pricing_policy_sha256=coordinator.broker_pricing_policy_sha256,
        broker_ledger_identity_sha256=ledger_identity,
        broker_packet_reservation_limit=coordinator.broker_packet_reservation_limit,
        broker_packet_cost_limit_microusd=coordinator.broker_packet_cost_limit_microusd,
        candidate_uid=candidate_uid,
    )
    broker_prepared_raw = canonical_prepared_broker_batch_bytes(broker_prepared)
    request_by_sha = {item.request_sha256: item for item in requests}
    review_by_role = {item.role: item for item in reviews}
    role_by_sha = {item.request_sha256: item.role for item in broker_prepared.runs}

    def broker_runner(_argv, *, stdin_bytes, **_kwargs):
        request_sha = _sha(stdin_bytes[:-1])
        role = role_by_sha[request_sha]
        envelope = strict_fixtures.broker_envelope(
            role,
            request_by_sha[request_sha],
            review_by_role[role],
        )
        return FakeRuntime._result(tuple(_argv), 0, stdout=envelope)

    broker_outer_raw = _execute_prepared_broker_outer(
        broker_prepared_raw,
        credentials={"reviewer": "secret-one", "adversary": "secret-two"},
        ledger_path=ledger,
        runtime_executable=source.broker_runtime_binary,
        require_two=True,
        runner=FakeRuntime(),
        stream_runner=broker_runner,
        probe=podman_probe,
        broker_cleanup=lambda *_args: True,
    )
    broker_action = PhaseAction.create(
        request=request,
        external_kind="broker",
        payload_sha256=_sha(broker_prepared_raw),
    )
    broker_transition = prepare_transition_bytes(request, broker_action, broker_prepared_raw)
    broker_output = CoordinatorPhaseOutput.model_validate_json(
        finalize_broker_phase_output(
            request,
            broker_action,
            broker_prepared_raw,
            broker_outer_raw,
            allowlist_policy=allowlist,
            pricing_policy=pricing,
        )
    )
    broker_result = _result(request, broker_output, external=broker_outer_raw)
    _commit(
        artifact_root,
        broker_result,
        broker_output,
        prepared=broker_prepared_raw,
        transition=broker_transition,
        external=broker_outer_raw,
        runtime_binding=runtime_binding_raw,
    )
    ledger.unlink()
    return (
        _next_request(broker_result, broker_output),
        artifact_root,
        snapshots,
        runtime,
        coordinator,
        candidate_uid,
    )


def test_reconstructs_same_frozen_bundle_for_sign_and_judge_without_live_ledger(
    tmp_path: Path,
) -> None:
    sign, artifacts, snapshots, runtime, coordinator, candidate_uid = _build_fixture(tmp_path)
    signed = reconstruct_attestation_inputs(
        sign,
        artifact_root=artifacts,
        snapshot_artifact_root=snapshots,
        runtime_root=runtime,
        coordinator=coordinator,
        candidate_uid=candidate_uid,
    )
    assert tuple(item.role for item in signed.broker_requests) == ("reviewer", "adversary")
    assert tuple(item.role for item in signed.reviews) == ("reviewer", "adversary")
    assert signed.broker_prepared_raw
    assert signed.broker_outer_raw
    assert tuple(item.role for item in signed.task_policy_bindings) == ("task", "policy")

    sign_artifacts = [
        PhaseOutputArtifact.create("adversary", b"signed-adversary"),
        *(
            PhaseOutputArtifact.create("gate:" + item.acceptance_test_id, b"signed-gate")
            for item in signed.gates
        ),
        PhaseOutputArtifact.create("policy", b"signed-policy"),
        PhaseOutputArtifact.create("reviewer", b"signed-reviewer"),
        PhaseOutputArtifact.create("task", b"signed-task"),
        *(
            artifact
            for item in signed.tdd_evidence
            for artifact in (
                PhaseOutputArtifact.create("tdd-green:" + item.acceptance_test_id, b"signed-green"),
                PhaseOutputArtifact.create("tdd-red:" + item.acceptance_test_id, b"signed-red"),
            )
        ),
    ]
    sign_output = CoordinatorPhaseOutput.create(
        request=sign,
        artifacts=tuple(sorted(sign_artifacts, key=lambda item: item.name)),
    )
    sign_result = _result(sign, sign_output)
    _commit(artifacts, sign_result, sign_output)
    judge = _next_request(sign_result, sign_output)
    judged = reconstruct_attestation_inputs(
        judge,
        artifact_root=artifacts,
        snapshot_artifact_root=snapshots,
        runtime_root=runtime,
        coordinator=coordinator,
        candidate_uid=candidate_uid,
    )
    assert judged == signed
    assert judged.bundle_sha256 == signed.bundle_sha256
    assert not (tmp_path / "outer-ledger" / "broker.sqlite3").exists()


def _sign_frozen(bundle, private_key: Ed25519PrivateKey):
    expectations = build_frozen_bundle_expectations(bundle)
    return tuple(
        sign_attestation(
            AttestationStatement(
                **expectation.model_dump(),
                nonce=_sha(f"frozen:{role}".encode()),
                issued_at=strict_fixtures.NOW,
            ),
            private_key,
        )
        for role, expectation in sorted(expectations.items())
    )


def test_frozen_judge_passes_after_host_ledger_deletion_and_rejects_replay(
    tmp_path: Path,
) -> None:
    private_key = Ed25519PrivateKey.generate()
    sign, artifacts, snapshots, runtime, coordinator, candidate_uid = _build_fixture(
        tmp_path,
        private_key=private_key,
    )
    bundle = reconstruct_attestation_inputs(
        sign,
        artifact_root=artifacts,
        snapshot_artifact_root=snapshots,
        runtime_root=runtime,
        coordinator=coordinator,
        candidate_uid=candidate_uid,
    )
    attestations = _sign_frozen(bundle, private_key)
    ledger = InMemoryNonceLedger()
    keys = {public_key_id(private_key.public_key()): private_key.public_key()}

    verdict = judge_frozen_attestation_bundle(
        bundle,
        attestations,
        trusted_public_keys=keys,
        nonce_ledger=ledger,
        now=strict_fixtures.NOW,
    )
    replay = judge_frozen_attestation_bundle(
        bundle,
        attestations,
        trusted_public_keys=keys,
        nonce_ledger=ledger,
        now=strict_fixtures.NOW,
    )

    assert verdict.status == "pass"
    assert replay.status == "fail"
    assert any("replay" in reason for reason in replay.reasons)
    assert not (tmp_path / "outer-ledger" / "broker.sqlite3").exists()


def test_frozen_judge_rejects_prepared_batch_substitution(tmp_path: Path) -> None:
    private_key = Ed25519PrivateKey.generate()
    sign, artifacts, snapshots, runtime, coordinator, candidate_uid = _build_fixture(
        tmp_path,
        private_key=private_key,
    )
    bundle = reconstruct_attestation_inputs(
        sign,
        artifact_root=artifacts,
        snapshot_artifact_root=snapshots,
        runtime_root=runtime,
        coordinator=coordinator,
        candidate_uid=candidate_uid,
    )

    with pytest.raises(ValueError, match="finalization failed"):
        build_frozen_bundle_expectations(
            replace(bundle, broker_prepared_raw=bundle.broker_prepared_raw + b" ")
        )


def test_actual_sign_and_judge_handlers_use_one_frozen_bundle_without_host_ledger(
    tmp_path: Path,
) -> None:
    private_key = Ed25519PrivateKey.generate()
    sign, artifacts, snapshots, runtime, coordinator, candidate_uid = _build_fixture(
        tmp_path,
        private_key=private_key,
    )
    key_dir = tmp_path / "signing"
    key_dir.mkdir(mode=0o700)
    key_path = key_dir / "coordinator-private-key.pem"
    key_path.write_bytes(
        private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    key_path.chmod(0o400)
    common = {
        "artifact_root": artifacts,
        "candidate_uid": candidate_uid,
        "coordinator": coordinator,
        "runtime_root": runtime,
        "snapshot_artifact_root": snapshots,
    }
    frozen = reconstruct_attestation_inputs(
        sign,
        artifact_root=artifacts,
        snapshot_artifact_root=snapshots,
        runtime_root=runtime,
        coordinator=coordinator,
        candidate_uid=candidate_uid,
    )
    expected_roles = set(build_frozen_bundle_expectations(frozen))
    sign_prepared_raw = prepare_workflow_transition(
        sign,
        inputs={**common, "nonce_ledger": None, "signing_key": key_path},
    )
    sign_prepared = parse_prepared_transition(
        sign_prepared_raw,
        request=sign.model_dump(mode="json"),
    )
    sign_output = CoordinatorPhaseOutput.model_validate_json(sign_prepared.payload)
    sign_finalized_raw = finalize_workflow_transition(
        sign,
        prepared_transition=sign_prepared_raw,
        execution_evidence=sign_prepared.payload,
        inputs={},
    )
    sign_finalized = parse_finalized_transition(
        sign_finalized_raw,
        request=sign.model_dump(mode="json"),
        external_raw=None,
    )
    sign_result = PhaseResult.model_validate_json(canonical_json_bytes(sign_finalized.result))
    _commit(artifacts, sign_result, sign_output)
    judge = _next_request(sign_result, sign_output)
    nonce_dir = tmp_path / "nonces"
    nonce_dir.mkdir(mode=0o700)
    judge_prepared_raw = prepare_workflow_transition(
        judge,
        inputs={
            **common,
            "artifact_root": artifacts,
            "nonce_ledger": nonce_dir / "nonces.sqlite3",
            "signing_key": None,
        },
    )
    judge_prepared = parse_prepared_transition(
        judge_prepared_raw,
        request=judge.model_dump(mode="json"),
    )
    judge_output = CoordinatorPhaseOutput.model_validate_json(judge_prepared.payload)
    verdict = Verdict.model_validate_json(judge_output.artifacts[0].content())
    judge_finalized_raw = finalize_workflow_transition(
        judge,
        prepared_transition=judge_prepared_raw,
        execution_evidence=judge_prepared.payload,
        inputs={},
    )
    judge_finalized = parse_finalized_transition(
        judge_finalized_raw,
        request=judge.model_dump(mode="json"),
        external_raw=None,
    )

    assert verdict.status == "pass"
    assert judge_finalized.next_request is None
    assert {item.name for item in sign_output.artifacts} == expected_roles
    assert not (tmp_path / "outer-ledger" / "broker.sqlite3").exists()


def test_rejects_broker_outer_evidence_not_bound_by_phase_result(tmp_path: Path) -> None:
    sign, artifacts, snapshots, runtime, coordinator, candidate_uid = _build_fixture(tmp_path)
    outer = artifacts / "05-broker" / "external-evidence.json"
    outer.write_bytes(outer.read_bytes() + b" ")

    with pytest.raises(CoordinatorAttestationInputError, match="PhaseResult-bound"):
        reconstruct_attestation_inputs(
            sign,
            artifact_root=artifacts,
            snapshot_artifact_root=snapshots,
            runtime_root=runtime,
            coordinator=coordinator,
            candidate_uid=candidate_uid,
        )
