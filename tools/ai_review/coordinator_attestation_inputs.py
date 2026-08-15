"""Reconstruct signing and judging inputs from committed workflow evidence.

This module runs only in the pinned coordinator.  It accepts no caller-built
descriptor, review, gate, TDD result, broker request, invocation, or execution
object.  Every such value is recovered from the immutable phase chain and the
dedicated content-addressed snapshot store.

The broker ledger is deliberately absent from this API.  Broker executions are
finalized from the outer phase's frozen final-ledger evidence, without probing a
runtime executable, opening a runtime socket, or reading a live ledger path.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from tools.ai_review.attestation import canonical_sha256
from tools.ai_review.attestation import SignedAttestation
from tools.ai_review.attested_judge import AttestedJudgeError
from tools.ai_review.attested_judge import TrustedAttestationContext
from tools.ai_review.attested_judge import TrustedBrokerArtifacts
from tools.ai_review.attested_judge import TrustedRunBinding
from tools.ai_review.attested_judge import TrustedRunRequest
from tools.ai_review.attested_judge import broker_egress_boundary_set_sha256
from tools.ai_review.attested_judge import derive_offline_artifacts
from tools.ai_review.attested_judge import run_request_sha256
from tools.ai_review.broker_egress_provisioner import ProvisionedBrokerExecutionEvidence
from tools.ai_review.broker_phase_protocol import BrokerPhaseProtocolError
from tools.ai_review.broker_phase_protocol import PreparedBrokerBatch
from tools.ai_review.broker_phase_protocol import finalize_provisioned_broker_execution
from tools.ai_review.broker_result import BrokerResultError
from tools.ai_review.broker_result import parse_broker_review
from tools.ai_review.codex_adapter import BrokerBoundaryEvidence
from tools.ai_review.codex_adapter import BrokerInferenceEvidence
from tools.ai_review.codex_adapter import IsolatedBrokerInvocation
from tools.ai_review.codex_adapter import TOKEN_WARNING_THRESHOLD
from tools.ai_review.codex_adapter import ToolFreeResponsesRequest
from tools.ai_review.codex_adapter import broker_boundary_evidence_sha256
from tools.ai_review.codex_adapter import validated_tool_free_request_bytes
from tools.ai_review.coordinator_runtime import CoordinatorRuntimeEvidence
from tools.ai_review.models import GateResult
from tools.ai_review.models import PolicyReport
from tools.ai_review.models import ReviewReport
from tools.ai_review.models import TaskSpec
from tools.ai_review.models import TddEvidence
from tools.ai_review.offline_phase_protocol import OfflinePhaseProtocolError
from tools.ai_review.offline_phase_protocol import canonical_offline_run_evidence_bytes
from tools.ai_review.offline_phase_protocol import finalize_offline_batch
from tools.ai_review.offline_phase_protocol import parse_prepared_offline_batch
from tools.ai_review.offline_runner import OfflineRunEvidence
from tools.ai_review.outer_workflow_state import OuterWorkflowStateError
from tools.ai_review.outer_workflow_state import parse_prepared_transition
from tools.ai_review.phase_protocol import PHASE_ORDER
from tools.ai_review.phase_protocol import CoordinatorPhaseOutput
from tools.ai_review.phase_protocol import PhaseChain
from tools.ai_review.phase_protocol import PhaseProtocolError
from tools.ai_review.phase_protocol import PhaseRequest
from tools.ai_review.phase_protocol import PhaseResult
from tools.ai_review.phase_protocol import canonical_json_bytes
from tools.ai_review.preflight import PreflightError
from tools.ai_review.preflight import assert_candidate_cannot_mutate_tree
from tools.ai_review.preflight import read_protected_file
from tools.ai_review.review_packet import ReviewPacket
from tools.ai_review.review_packet import canonical_packet_bytes
from tools.ai_review.snapshot import RedTddSnapshotEvidence
from tools.ai_review.snapshot import SnapshotError
from tools.ai_review.snapshot import SnapshotEvidence
from tools.ai_review.snapshot import measure_red_tdd_snapshot
from tools.ai_review.snapshot import verify_readonly_snapshot


_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_IMAGE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/:+-]*@(sha256:[0-9a-f]{64})$")
_BINDING_RUNNER_DOMAIN = b"amazon-explorer-coordinator-artifact-runner-v1\0"
_BINDING_SESSION_DOMAIN = b"amazon-explorer-coordinator-artifact-session-v1\0"
_BINDING_LOG_DOMAIN = b"amazon-explorer-coordinator-artifact-log-v1\0"
_BINDING_RESPONSE_DOMAIN = b"amazon-explorer-coordinator-artifact-response-v1\0"
_BUNDLE_DOMAIN = b"amazon-explorer-coordinator-attestation-inputs-v1\0"


class CoordinatorAttestationInputError(PhaseProtocolError):
    """Raised when immutable workflow evidence cannot form one exact bundle."""


@dataclass(frozen=True)
class CoordinatorAttestationInputs:
    """Fully measured common input for a future sign or attested-judge phase."""

    task: TaskSpec
    task_sha256: str
    policy: PolicyReport
    review_packet: ReviewPacket
    base_snapshot: SnapshotEvidence
    candidate_snapshot: SnapshotEvidence
    red_snapshots: tuple[RedTddSnapshotEvidence, ...]
    raw_offline_runs: tuple[OfflineRunEvidence, ...]
    offline_runner_image: str
    gates: tuple[GateResult, ...]
    tdd_evidence: tuple[TddEvidence, ...]
    offline_run_bindings: tuple[TrustedRunBinding, ...]
    task_policy_bindings: tuple[TrustedRunBinding, TrustedRunBinding]
    broker_batch: PreparedBrokerBatch
    broker_prepared_raw: bytes
    broker_outer_raw: bytes
    broker_allowlist_policy: bytes
    broker_pricing_policy: bytes
    broker_requests: tuple[ToolFreeResponsesRequest, ToolFreeResponsesRequest]
    broker_invocations: tuple[IsolatedBrokerInvocation, IsolatedBrokerInvocation]
    provisioned_broker_executions: tuple[
        ProvisionedBrokerExecutionEvidence,
        ProvisionedBrokerExecutionEvidence,
    ]
    reviews: tuple[ReviewReport, ReviewReport]
    broker_inference: tuple[BrokerInferenceEvidence, BrokerInferenceEvidence]
    broker_artifacts: tuple[TrustedBrokerArtifacts, TrustedBrokerArtifacts]
    broker_boundary_evidence: BrokerBoundaryEvidence
    context: TrustedAttestationContext
    bundle_sha256: str


@dataclass(frozen=True)
class _CommittedPhase:
    directory: Path
    result: PhaseResult
    output: CoordinatorPhaseOutput
    output_raw: bytes


def reconstruct_signed_attestations(
    request: PhaseRequest,
    *,
    artifact_root: Path,
    candidate_uid: int,
) -> tuple[SignedAttestation, ...]:
    """Read the PhaseResult-bound sign artifacts for the judge phase only."""

    if type(request) is not PhaseRequest or request.phase != "attested-judge":
        raise CoordinatorAttestationInputError(
            "signed attestations require the attested-judge request"
        )
    phases = _committed_history(request, artifact_root, candidate_uid=candidate_uid)
    sign = phases.get("sign")
    if sign is None:
        raise CoordinatorAttestationInputError("committed sign phase is missing")
    attestations: list[SignedAttestation] = []
    for artifact in sign.output.artifacts:
        raw = artifact.content()
        try:
            envelope = SignedAttestation.model_validate_json(raw)
        except ValueError as exc:
            raise CoordinatorAttestationInputError(
                "committed signed attestation is invalid"
            ) from exc
        if canonical_json_bytes(envelope) != raw or envelope.statement.role != artifact.name:
            raise CoordinatorAttestationInputError(
                "signed artifact changed its canonical role binding"
            )
        if envelope.key_id != request.coordinator_key_id:
            raise CoordinatorAttestationInputError(
                "signed artifact does not use the workflow coordinator key"
            )
        attestations.append(envelope)
    if not attestations:
        raise CoordinatorAttestationInputError("committed sign phase has no attestations")
    return tuple(attestations)


def _read(
    path: Path,
    *,
    candidate_uid: int,
    label: str,
    maximum: int = 6_000_000,
) -> bytes:
    try:
        _evidence, raw = read_protected_file(
            path,
            candidate_uid=candidate_uid,
            label=label,
            max_bytes=maximum,
        )
    except PreflightError as exc:
        raise CoordinatorAttestationInputError(str(exc)) from exc
    if not raw:
        raise CoordinatorAttestationInputError(f"{label} is empty")
    return raw


def _strict_json(raw: bytes, *, label: str, newline: bool) -> object:
    def pairs(values: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in values:
            if key in result:
                raise CoordinatorAttestationInputError(f"{label} contains a duplicate field")
            result[key] = value
        return result

    try:
        value = json.loads(raw.decode("utf-8", errors="strict"), object_pairs_hook=pairs)
        encoded = json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except CoordinatorAttestationInputError:
        raise
    except (UnicodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
        raise CoordinatorAttestationInputError(f"{label} is not strict JSON") from exc
    expected = encoded + (b"\n" if newline else b"")
    if raw != expected:
        raise CoordinatorAttestationInputError(f"{label} is not canonical JSON")
    return value


def _protected_directory(path: Path, *, candidate_uid: int, label: str) -> Path:
    if type(path) is not type(Path()):
        raise CoordinatorAttestationInputError(f"{label} must be a concrete Path")
    try:
        return assert_candidate_cannot_mutate_tree(path, candidate_uid=candidate_uid).root
    except PreflightError as exc:
        raise CoordinatorAttestationInputError(str(exc)) from exc


def _committed_history(
    request: PhaseRequest,
    artifact_root: Path,
    *,
    candidate_uid: int,
) -> dict[str, _CommittedPhase]:
    if type(request) is not PhaseRequest or request.phase not in {"sign", "attested-judge"}:
        raise CoordinatorAttestationInputError(
            "attestation inputs require the sign or attested-judge request"
        )
    root = _protected_directory(
        artifact_root,
        candidate_uid=candidate_uid,
        label="committed workflow artifact root",
    )
    phases: dict[str, _CommittedPhase] = {}
    results: list[PhaseResult] = []
    for result_path in sorted(root.rglob("phase-result.json")):
        directory = result_path.parent
        result_raw = _read(
            result_path,
            candidate_uid=candidate_uid,
            label="committed phase result",
            maximum=2_000_000,
        )
        output_raw = _read(
            directory / "coordinator-output.json",
            candidate_uid=candidate_uid,
            label="committed coordinator output",
        )
        try:
            result = PhaseResult.model_validate_json(result_raw)
            output = CoordinatorPhaseOutput.model_validate_json(output_raw)
            if (
                canonical_json_bytes(result) != result_raw
                or canonical_json_bytes(output) != output_raw
            ):
                raise ValueError("noncanonical committed evidence")
            output.validate_for(result.request)
        except (TypeError, ValueError) as exc:
            raise CoordinatorAttestationInputError(
                "committed phase result or coordinator output is invalid"
            ) from exc
        if (
            result.request.workflow_id != request.workflow_id
            or result.request.phase in phases
            or not hmac.compare_digest(
                result.coordinator_output_sha256,
                hashlib.sha256(output_raw).hexdigest(),
            )
            or result.output_artifacts_sha256 != output.output_artifacts_sha256
            or result.artifacts != output.phase_artifacts()
            or result.candidate_snapshot_sha256 != output.candidate_snapshot_sha256
            or result.review_packet_sha256 != output.review_packet_sha256
        ):
            raise CoordinatorAttestationInputError(
                "PhaseResult does not bind exactly one canonical coordinator output"
            )
        phases[result.request.phase] = _CommittedPhase(
            directory=directory,
            result=result,
            output=output,
            output_raw=output_raw,
        )
        results.append(result)
    ordered = tuple(sorted(results, key=lambda item: item.request.sequence))
    expected_names = PHASE_ORDER[: request.sequence - 1]
    if (
        len(ordered) != request.sequence - 1
        or tuple(item.request.phase for item in ordered) != expected_names
        or tuple(item.request.sequence for item in ordered) != tuple(range(1, request.sequence))
    ):
        raise CoordinatorAttestationInputError(
            "committed workflow history is incomplete, duplicated, or reordered"
        )
    try:
        PhaseChain(ordered).validate_request(request)
    except PhaseProtocolError as exc:
        raise CoordinatorAttestationInputError("committed workflow phase chain is invalid") from exc
    return phases


def _artifact(phase: _CommittedPhase, name: str) -> bytes:
    matches = tuple(item for item in phase.output.artifacts if item.name == name)
    if len(matches) != 1:
        raise CoordinatorAttestationInputError(f"missing or duplicate committed artifact: {name}")
    try:
        return matches[0].content()
    except ValueError as exc:
        raise CoordinatorAttestationInputError(f"committed artifact is invalid: {name}") from exc


def _snapshot_digest(phase: _CommittedPhase, name: str) -> str:
    try:
        value = _artifact(phase, name).decode("ascii", errors="strict")
    except UnicodeError as exc:
        raise CoordinatorAttestationInputError(f"{name} digest is not ASCII") from exc
    if _SHA256_RE.fullmatch(value) is None:
        raise CoordinatorAttestationInputError(f"{name} digest is invalid")
    return value


def _snapshot_store(
    snapshot_root: Path,
    phases: dict[str, _CommittedPhase],
    *,
    task: TaskSpec,
    candidate_uid: int,
) -> tuple[SnapshotEvidence, SnapshotEvidence, tuple[RedTddSnapshotEvidence, ...]]:
    root = _protected_directory(
        snapshot_root,
        candidate_uid=candidate_uid,
        label="dedicated snapshot artifact root",
    )
    snapshot_phase = phases["snapshot"]
    base_digest = _snapshot_digest(snapshot_phase, "base-snapshot")
    candidate_digest = _snapshot_digest(snapshot_phase, "candidate-snapshot")
    snapshot_directory = root / "snapshots"
    expected_snapshots = {base_digest, candidate_digest}
    try:
        snapshot_entries = tuple(snapshot_directory.iterdir())
    except OSError as exc:
        raise CoordinatorAttestationInputError("snapshot store is unavailable") from exc
    if {item.name for item in snapshot_entries} != expected_snapshots or any(
        not item.is_dir() or item.is_symlink() for item in snapshot_entries
    ):
        raise CoordinatorAttestationInputError(
            "physical base/candidate snapshot set differs from committed artifacts"
        )
    try:
        base = verify_readonly_snapshot(
            snapshot_directory / base_digest,
            candidate_uid=candidate_uid,
        )
        candidate = verify_readonly_snapshot(
            snapshot_directory / candidate_digest,
            candidate_uid=candidate_uid,
        )
    except SnapshotError as exc:
        raise CoordinatorAttestationInputError(
            "base/candidate snapshot verification failed"
        ) from exc
    if base.snapshot_sha256 != base_digest or candidate.snapshot_sha256 != candidate_digest:
        raise CoordinatorAttestationInputError("remeasured snapshot digest changed")

    red_phase = phases["red-snapshot"]
    expected_red_names = {
        "red-snapshot:" + acceptance.id
        for acceptance in task.acceptance_tests
        if acceptance.kind == "test"
    }
    if {item.name for item in red_phase.output.artifacts} != expected_red_names:
        raise CoordinatorAttestationInputError(
            "committed RED artifacts do not exactly cover TaskSpec tests"
        )
    expected_red_digests = {
        _snapshot_digest(red_phase, "red-snapshot:" + acceptance.id)
        for acceptance in task.acceptance_tests
        if acceptance.kind == "test"
    }
    red_directory = root / "red-snapshots"
    try:
        red_entries = tuple(red_directory.iterdir())
    except OSError as exc:
        raise CoordinatorAttestationInputError("RED snapshot store is unavailable") from exc
    if (
        not expected_red_digests
        or {item.name for item in red_entries} != expected_red_digests
        or any(not item.is_dir() or item.is_symlink() for item in red_entries)
    ):
        raise CoordinatorAttestationInputError(
            "physical RED snapshot set differs from committed artifacts"
        )
    red: list[RedTddSnapshotEvidence] = []
    for acceptance in task.acceptance_tests:
        if acceptance.kind != "test":
            continue
        if not acceptance.test_paths:
            raise CoordinatorAttestationInputError(
                "attested workflow requires exact TaskSpec v2 test paths"
            )
        digest = _snapshot_digest(red_phase, "red-snapshot:" + acceptance.id)
        try:
            measured = measure_red_tdd_snapshot(
                red_root=red_directory / digest,
                base_snapshot=base,
                candidate_snapshot=candidate,
                test_paths=tuple(acceptance.test_paths),
                candidate_uid=candidate_uid,
            )
        except SnapshotError as exc:
            raise CoordinatorAttestationInputError("RED snapshot remeasurement failed") from exc
        if measured.snapshot.snapshot_sha256 != digest:
            raise CoordinatorAttestationInputError("RED semantic digest changed")
        red.append(measured)
    return base, candidate, tuple(red)


def _phase_file(
    phase: _CommittedPhase,
    filename: str,
    *,
    candidate_uid: int,
) -> bytes:
    raw = _read(
        phase.directory / filename,
        candidate_uid=candidate_uid,
        label=f"{phase.result.request.phase} {filename}",
    )
    if filename == "external-evidence.json" and not hmac.compare_digest(
        hashlib.sha256(raw).hexdigest(),
        phase.result.external_execution_sha256 or "",
    ):
        raise CoordinatorAttestationInputError(
            f"{phase.result.request.phase} external evidence is not PhaseResult-bound"
        )
    return raw


def _prepared_payload(
    phase: _CommittedPhase,
    *,
    candidate_uid: int,
) -> bytes:
    payload = _phase_file(
        phase,
        "prepared-payload.json",
        candidate_uid=candidate_uid,
    )
    transition = _phase_file(
        phase,
        "prepared-transition.json",
        candidate_uid=candidate_uid,
    )
    try:
        parsed = parse_prepared_transition(
            transition,
            request=phase.result.request.model_dump(mode="json"),
        )
    except OuterWorkflowStateError as exc:
        raise CoordinatorAttestationInputError("committed prepared transition is invalid") from exc
    if parsed.payload != payload:
        raise CoordinatorAttestationInputError(
            "committed prepared payload differs from its coordinator action"
        )
    return payload


def _offline_runs(
    phase: _CommittedPhase,
    *,
    snapshot_root: Path,
    candidate_uid: int,
    coordinator: CoordinatorRuntimeEvidence,
) -> tuple[tuple[OfflineRunEvidence, ...], str]:
    prepared_raw = _prepared_payload(phase, candidate_uid=candidate_uid)
    external_raw = _phase_file(
        phase,
        "external-evidence.json",
        candidate_uid=candidate_uid,
    )
    try:
        prepared = parse_prepared_offline_batch(prepared_raw)
        runs = finalize_offline_batch(
            prepared_raw,
            external_raw,
            artifact_root=snapshot_root,
            candidate_uid=candidate_uid,
        )
    except OfflinePhaseProtocolError as exc:
        raise CoordinatorAttestationInputError("offline evidence finalization failed") from exc
    request = phase.result.request
    if (
        prepared.workflow_id != request.workflow_id
        or prepared.request_sha256 != request.request_sha256
        or prepared.task_sha256 != request.task_sha256
        or prepared.candidate_sha256 != request.candidate_sha256
        or prepared.candidate_snapshot_sha256 != request.candidate_snapshot_sha256
        or prepared.approved_image_digest != coordinator.offline_runner_image_digest
        or _IMAGE_RE.fullmatch(prepared.image) is None
    ):
        raise CoordinatorAttestationInputError("offline prepared batch changed workflow anchors")
    by_name = {item.name: item.content() for item in phase.output.artifacts}
    expected: dict[str, bytes] = {}
    for run in runs:
        prefix = "gate" if run.request.phase == "gate" else "tdd-" + run.request.phase
        expected[prefix + ":" + run.request.acceptance_test_id] = (
            canonical_offline_run_evidence_bytes(run)
        )
    if by_name != expected:
        raise CoordinatorAttestationInputError(
            "committed offline full evidence differs from finalized outer evidence"
        )
    return tuple(runs), prepared.image


def _tool_free_request(
    run: Any,
    *,
    packet: ReviewPacket,
) -> ToolFreeResponsesRequest:
    if not run.stdin.endswith(b"\n"):
        raise CoordinatorAttestationInputError("prepared broker request lacks canonical newline")
    request_raw = run.stdin[:-1]
    payload = _strict_json(request_raw, label=f"{run.role} broker request", newline=False)
    if type(payload) is not dict:
        raise CoordinatorAttestationInputError("broker request must be a JSON object")
    try:
        reasoning = payload["reasoning"]
        request = ToolFreeResponsesRequest(
            payload=payload,
            request_sha256=run.request_sha256,
            packet_sha256=run.packet_sha256,
            role=run.role,
            attempt=run.attempt,
            model=payload["model"],
            reasoning_effort=reasoning["effort"],
            estimated_input_tokens=len(request_raw),
            warning_250k=len(request_raw) >= TOKEN_WARNING_THRESHOLD,
        )
        measured = validated_tool_free_request_bytes(request, expected_packet=packet)
    except (KeyError, TypeError, ValueError) as exc:
        raise CoordinatorAttestationInputError("prepared broker request is invalid") from exc
    if measured != request_raw:
        raise CoordinatorAttestationInputError("prepared broker request changed canonical bytes")
    return request


def _broker_summary(
    provisioned: ProvisionedBrokerExecutionEvidence,
    *,
    final_ledger: Any,
    prepared_sha256: str,
    outer_sha256: str,
) -> bytes:
    execution = provisioned.execution
    return canonical_json_bytes(
        {
            "broker_egress_boundary_sha256": execution.broker_egress_boundary_sha256,
            "broker_egress_lifecycle_sha256": provisioned.broker_egress_lifecycle_sha256,
            "broker_ledger_identity_sha256": execution.broker_ledger_identity_sha256,
            "broker_packet_cost_limit_microusd": execution.broker_packet_cost_limit_microusd,
            "broker_packet_reservation_limit": execution.broker_packet_reservation_limit,
            "broker_pricing_policy_sha256": execution.broker_pricing_policy_sha256,
            "cumulative_reserved_cost_microusd": final_ledger.cumulative_reserved_cost_microusd,
            "cumulative_reserved_tokens": final_ledger.cumulative_reserved_tokens,
            "evidence_sha256": provisioned.evidence_sha256,
            "execution_evidence_sha256": provisioned.execution_evidence_sha256,
            "final_ledger_evidence_sha256": final_ledger.evidence_sha256,
            "final_ledger_records_sha256": final_ledger.records_sha256,
            "outer_evidence_sha256": outer_sha256,
            "packet_sha256": execution.packet_sha256,
            "prepared_batch_sha256": prepared_sha256,
            "request_sha256": execution.request_sha256,
            "response_sha256": execution.response_sha256,
            "role": execution.role,
            "schema_version": "1.0",
            "stdout_sha256": execution.stdout_sha256,
        }
    )


def _runtime_policy(
    runtime_root: Path,
    filename: str,
    expected_sha256: str,
    *,
    candidate_uid: int,
) -> bytes:
    root = _protected_directory(
        runtime_root,
        candidate_uid=candidate_uid,
        label="coordinator runtime root",
    )
    try:
        _evidence, raw = read_protected_file(
            root / filename,
            candidate_uid=candidate_uid,
            label=filename,
            expected_sha256=expected_sha256,
            max_bytes=64 * 1024,
        )
    except PreflightError as exc:
        raise CoordinatorAttestationInputError(str(exc)) from exc
    return raw


def _broker_inputs(
    phase: _CommittedPhase,
    *,
    packet: ReviewPacket,
    candidate: SnapshotEvidence,
    runtime_root: Path,
    coordinator: CoordinatorRuntimeEvidence,
    candidate_uid: int,
) -> tuple[
    PreparedBrokerBatch,
    tuple[ToolFreeResponsesRequest, ToolFreeResponsesRequest],
    tuple[IsolatedBrokerInvocation, IsolatedBrokerInvocation],
    tuple[ProvisionedBrokerExecutionEvidence, ProvisionedBrokerExecutionEvidence],
    tuple[ReviewReport, ReviewReport],
    tuple[BrokerInferenceEvidence, BrokerInferenceEvidence],
    tuple[TrustedBrokerArtifacts, TrustedBrokerArtifacts],
    BrokerBoundaryEvidence,
    bytes,
    bytes,
    bytes,
    bytes,
]:
    prepared_raw = _prepared_payload(phase, candidate_uid=candidate_uid)
    outer_raw = _phase_file(
        phase,
        "external-evidence.json",
        candidate_uid=candidate_uid,
    )
    runtime_binding_raw = _phase_file(
        phase,
        "broker-runtime-binding.json",
        candidate_uid=candidate_uid,
    )
    allowlist = _runtime_policy(
        runtime_root,
        "broker-egress-policy.json",
        coordinator.broker_allowlist_policy_sha256,
        candidate_uid=candidate_uid,
    )
    pricing = _runtime_policy(
        runtime_root,
        "openai-pricing-policy.json",
        coordinator.broker_pricing_policy_sha256,
        candidate_uid=candidate_uid,
    )
    try:
        batch = PreparedBrokerBatch.parse(prepared_raw)
        provisioned = finalize_provisioned_broker_execution(
            batch,
            outer_raw,
            allowlist_policy=allowlist,
            pricing_policy=pricing,
        )
    except BrokerPhaseProtocolError as exc:
        raise CoordinatorAttestationInputError(
            "frozen broker evidence finalization failed"
        ) from exc
    request = phase.result.request
    if (
        batch.workflow_id != request.workflow_id
        or batch.phase_request_sha256 != request.request_sha256
        or batch.task_sha256 != request.task_sha256
        or batch.runtime_manifest_sha256 != request.runtime_manifest_sha256
        or batch.candidate_snapshot_sha256 != request.candidate_snapshot_sha256
        or batch.review_packet_sha256 != request.review_packet_sha256
        or batch.candidate_uid != candidate_uid
        or batch.runtime_manifest_sha256 != coordinator.manifest_sha256
        or batch.runs[0].approved_image_digest != coordinator.broker_image_digest
        or batch.runs[1].approved_image_digest != coordinator.broker_image_digest
        or batch.broker_gateway_image_digest != coordinator.broker_gateway_image_digest
        or batch.broker_allowlist_policy_sha256 != coordinator.broker_allowlist_policy_sha256
        or batch.broker_pricing_policy_sha256 != coordinator.broker_pricing_policy_sha256
        or batch.broker_packet_reservation_limit != coordinator.broker_packet_reservation_limit
        or batch.broker_packet_cost_limit_microusd != coordinator.broker_packet_cost_limit_microusd
        or canonical_json_bytes(vars(batch.runtime)) != runtime_binding_raw
    ):
        raise CoordinatorAttestationInputError("prepared broker batch changed workflow anchors")
    boundary = BrokerBoundaryEvidence(
        packet_sha256=packet.packet_sha256,
        external_preflight_sha256=hashlib.sha256(runtime_binding_raw).hexdigest(),
        snapshot_manifest_sha256=candidate.manifest_sha256,
        isolation_attestation_sha256=batch.runtime.security_evidence_sha256,
        candidate_filesystem_unmounted=True,
        read_only_snapshot_verified=True,
        network_isolation_verified=True,
        coordinator_attestation_verified=True,
    )
    try:
        boundary.validate_for(packet)
        boundary_sha256 = broker_boundary_evidence_sha256(boundary)
    except ValueError as exc:
        raise CoordinatorAttestationInputError("broker boundary evidence is invalid") from exc
    if any(run.boundary_evidence_sha256 != boundary_sha256 for run in batch.runs):
        raise CoordinatorAttestationInputError(
            "prepared broker runs do not bind the reconstructed boundary evidence"
        )

    requests = tuple(_tool_free_request(run, packet=packet) for run in batch.runs)
    invocations = tuple(run.invocation() for run in batch.runs)
    parsed = []
    artifacts = []
    for run, approved, evidence in zip(batch.runs, requests, provisioned, strict=True):
        if evidence.execution.stdin != run.stdin or evidence.execution.request_sha256 != (
            approved.request_sha256
        ):
            raise CoordinatorAttestationInputError(
                "frozen broker execution changed its prepared request"
            )
        try:
            review = parse_broker_review(
                evidence.execution.canonical_envelope,
                expected_request_sha256=approved.request_sha256,
                expected_packet_sha256=packet.packet_sha256,
                role=run.role,
                attempt=run.attempt,
            )
        except BrokerResultError as exc:
            raise CoordinatorAttestationInputError("frozen broker review is invalid") from exc
        parsed.append(review)
        artifacts.append(
            TrustedBrokerArtifacts(
                role=run.role,
                canonical_request=run.stdin[:-1],
                canonical_envelope=evidence.execution.canonical_envelope,
            )
        )
    prepared_sha256 = hashlib.sha256(prepared_raw).hexdigest()
    outer_sha256 = hashlib.sha256(outer_raw).hexdigest()
    final_ledger = provisioned[-1].execution.ledger
    expected_summaries = {
        evidence.execution.role: _broker_summary(
            evidence,
            final_ledger=final_ledger,
            prepared_sha256=prepared_sha256,
            outer_sha256=outer_sha256,
        )
        for evidence in provisioned
    }
    actual_summaries = {item.name: item.content() for item in phase.output.artifacts}
    if actual_summaries != expected_summaries:
        raise CoordinatorAttestationInputError(
            "broker PhaseResult summaries do not bind prepared and frozen outer evidence"
        )
    typed_requests = (requests[0], requests[1])
    typed_invocations = (invocations[0], invocations[1])
    typed_reviews = (parsed[0].review, parsed[1].review)
    typed_inference = (parsed[0].inference, parsed[1].inference)
    typed_artifacts = (artifacts[0], artifacts[1])
    return (
        batch,
        typed_requests,
        typed_invocations,
        provisioned,
        typed_reviews,
        typed_inference,
        typed_artifacts,
        boundary,
        prepared_raw,
        outer_raw,
        allowlist,
        pricing,
    )


def _binding_digest(domain: bytes, payload: dict[str, object]) -> str:
    return hashlib.sha256(domain + canonical_json_bytes(payload)).hexdigest()


def _task_policy_bindings(
    *,
    task: TaskSpec,
    task_sha256: str,
    policy: PolicyReport,
    base: SnapshotEvidence,
    candidate: SnapshotEvidence,
    snapshot_phase: _CommittedPhase,
    runtime_manifest_sha256: str,
) -> tuple[TrustedRunBinding, TrustedRunBinding]:
    artifact_values = (
        (
            "task",
            canonical_sha256(task),
            TrustedRunRequest(
                kind="task",
                task_sha256=task_sha256,
                source_sha=task.base_sha,
                source_snapshot_sha256=base.snapshot_sha256,
                snapshot_sha256=base.snapshot_sha256,
                input_sha256=task_sha256,
            ),
        ),
        (
            "policy",
            canonical_sha256(policy),
            TrustedRunRequest(
                kind="policy",
                task_sha256=task_sha256,
                source_sha=policy.head_sha,
                source_snapshot_sha256=candidate.snapshot_sha256,
                candidate_sha256=policy.patch_sha256,
                snapshot_sha256=candidate.snapshot_sha256,
                input_sha256=candidate.snapshot_sha256,
            ),
        ),
    )
    bindings: list[TrustedRunBinding] = []
    for role, artifact_sha256, run_request in artifact_values:
        anchors = {
            "artifact_sha256": artifact_sha256,
            "artifact_type": role,
            "base_snapshot_manifest_sha256": base.manifest_sha256,
            "candidate_snapshot_manifest_sha256": candidate.manifest_sha256,
            "phase_output_sha256": snapshot_phase.output.output_sha256,
            "phase_request_sha256": snapshot_phase.result.request.request_sha256,
            "phase_result_sha256": snapshot_phase.result.phase_sha256,
            "runtime_manifest_sha256": runtime_manifest_sha256,
        }
        bindings.append(
            TrustedRunBinding(
                role=role,
                artifact_type=role,
                session_id="coordinator-" + _binding_digest(_BINDING_SESSION_DOMAIN, anchors),
                runner_sha256=_binding_digest(_BINDING_RUNNER_DOMAIN, anchors),
                argv=(
                    "trusted-coordinator-phase",
                    "snapshot",
                    "--request-sha256",
                    snapshot_phase.result.request.request_sha256,
                    "--output-sha256",
                    snapshot_phase.output.output_sha256,
                ),
                log_sha256=_binding_digest(_BINDING_LOG_DOMAIN, anchors),
                request=run_request,
                request_sha256=run_request_sha256(run_request),
                response_sha256=_binding_digest(_BINDING_RESPONSE_DOMAIN, anchors),
            )
        )
    return bindings[0], bindings[1]


def _bundle_sha256(
    *,
    phases: dict[str, _CommittedPhase],
    task_sha256: str,
    policy: PolicyReport,
    packet: ReviewPacket,
    raw_runs: tuple[OfflineRunEvidence, ...],
    batch: PreparedBrokerBatch,
    provisioned: tuple[
        ProvisionedBrokerExecutionEvidence,
        ProvisionedBrokerExecutionEvidence,
    ],
    context: TrustedAttestationContext,
    bindings: tuple[TrustedRunBinding, TrustedRunBinding],
) -> str:
    payload = {
        "broker_batch_sha256": batch.batch_sha256,
        "broker_evidence_sha256": [item.evidence_sha256 for item in provisioned],
        "context": context.model_dump(mode="json"),
        "offline_response_sha256": [item.response_sha256 for item in raw_runs],
        "phase_sha256": {
            name: phases[name].result.phase_sha256
            for name in ("snapshot", "red-snapshot", "offline", "review-packet", "broker")
        },
        "policy_sha256": canonical_sha256(policy),
        "review_packet_sha256": packet.packet_sha256,
        "schema_version": "1.0",
        "task_policy_bindings": [item.model_dump(mode="json") for item in bindings],
        # This is the digest of the exact mounted TaskSpec bytes.  The packet's
        # parsed model is intentionally not reserialized as a substitute.
        "task_sha256": task_sha256,
    }
    return hashlib.sha256(_BUNDLE_DOMAIN + canonical_json_bytes(payload)).hexdigest()


def reconstruct_attestation_inputs(
    request: PhaseRequest,
    *,
    artifact_root: Path,
    snapshot_artifact_root: Path,
    runtime_root: Path,
    coordinator: CoordinatorRuntimeEvidence,
    candidate_uid: int,
) -> CoordinatorAttestationInputs:
    """Return one deterministic frozen bundle without live broker dependencies."""

    if type(candidate_uid) is not int or not 1 <= candidate_uid <= 2**31 - 1:
        raise CoordinatorAttestationInputError("candidate uid is invalid")
    if type(coordinator) is not CoordinatorRuntimeEvidence:
        raise CoordinatorAttestationInputError("coordinator runtime evidence type is invalid")
    phases = _committed_history(request, artifact_root, candidate_uid=candidate_uid)
    required = {"snapshot", "red-snapshot", "offline", "review-packet", "broker"}
    if not required <= phases.keys():
        raise CoordinatorAttestationInputError("attestation input phases are incomplete")
    if (
        request.runtime_manifest_sha256 != coordinator.manifest_sha256
        or request.task_sha256 != coordinator.task_sha256
        or request.coordinator_public_key_sha256 != coordinator.coordinator_public_key_sha256
    ):
        raise CoordinatorAttestationInputError(
            "attestation request differs from pinned coordinator evidence"
        )

    policy_raw = _artifact(phases["snapshot"], "policy")
    packet_raw = _artifact(phases["review-packet"], "review-packet")
    try:
        policy = PolicyReport.model_validate_json(policy_raw)
        packet = ReviewPacket.model_validate_json(packet_raw)
    except ValueError as exc:
        raise CoordinatorAttestationInputError(
            "policy or review packet artifact is invalid"
        ) from exc
    if canonical_json_bytes(policy) != policy_raw or canonical_packet_bytes(packet) != packet_raw:
        raise CoordinatorAttestationInputError("policy or review packet is noncanonical")
    task = packet.task
    if (
        task.schema_version != "2.0"
        or packet.task_sha256 != request.task_sha256
        or packet.policy != policy
        or policy.task_sha256 != request.task_sha256
        or policy.patch_sha256 != request.candidate_sha256
        or packet.packet_sha256 != request.review_packet_sha256
    ):
        raise CoordinatorAttestationInputError(
            "task, policy, packet, or current request anchor changed"
        )
    base, candidate, red = _snapshot_store(
        snapshot_artifact_root,
        phases,
        task=task,
        candidate_uid=candidate_uid,
    )
    if (
        base.commit_sha != task.base_sha
        or candidate.commit_sha != policy.head_sha
        or candidate.snapshot_sha256 != request.candidate_snapshot_sha256
        or packet.trusted_diff_binding.snapshot_manifest_sha256 != candidate.manifest_sha256
    ):
        raise CoordinatorAttestationInputError("snapshot anchors changed task, policy, or packet")
    raw_runs, offline_image = _offline_runs(
        phases["offline"],
        snapshot_root=snapshot_artifact_root,
        candidate_uid=candidate_uid,
        coordinator=coordinator,
    )
    (
        batch,
        broker_requests,
        broker_invocations,
        provisioned,
        reviews,
        inference,
        broker_artifacts,
        boundary,
        broker_prepared_raw,
        broker_outer_raw,
        broker_allowlist_policy,
        broker_pricing_policy,
    ) = _broker_inputs(
        phases["broker"],
        packet=packet,
        candidate=candidate,
        runtime_root=runtime_root,
        coordinator=coordinator,
        candidate_uid=candidate_uid,
    )
    schemas = [item.payload["text"]["format"]["schema"] for item in broker_requests]
    if schemas[0] != schemas[1]:
        raise CoordinatorAttestationInputError("broker roles changed the output schema")
    context = TrustedAttestationContext(
        runtime_manifest_sha256=coordinator.manifest_sha256,
        coordinator_image_digest=coordinator.coordinator_image_digest,
        offline_runner_image_digest=coordinator.offline_runner_image_digest,
        broker_image_digest=coordinator.broker_image_digest,
        broker_gateway_image_digest=coordinator.broker_gateway_image_digest,
        broker_egress_boundary_sha256=broker_egress_boundary_set_sha256(provisioned),
        broker_allowlist_policy_sha256=batch.broker_allowlist_policy_sha256,
        broker_ledger_identity_sha256=batch.broker_ledger_identity_sha256,
        broker_packet_reservation_limit=batch.broker_packet_reservation_limit,
        broker_pricing_policy_sha256=batch.broker_pricing_policy_sha256,
        broker_packet_cost_limit_microusd=batch.broker_packet_cost_limit_microusd,
        base_snapshot_sha256=base.snapshot_sha256,
        base_snapshot_manifest_sha256=base.manifest_sha256,
        base_commit_tree_sha=base.commit_tree_sha,
        candidate_snapshot_sha256=candidate.snapshot_sha256,
        candidate_snapshot_manifest_sha256=candidate.manifest_sha256,
        candidate_commit_tree_sha=candidate.commit_tree_sha,
        review_packet_sha256=packet.packet_sha256,
        review_output_schema_sha256=canonical_sha256(schemas[0]),
    )
    try:
        gates, tdds, offline_bindings = derive_offline_artifacts(
            task=task,
            policy=policy,
            task_sha256=request.task_sha256,
            raw_runs=raw_runs,
            base_snapshot=base,
            candidate_snapshot=candidate,
            red_snapshots=red,
            offline_runner_image=offline_image,
            context=context,
            candidate_uid=candidate_uid,
        )
    except AttestedJudgeError as exc:
        raise CoordinatorAttestationInputError("offline attestation derivation failed") from exc
    ordered_gates = tuple(sorted(gates, key=lambda item: item.acceptance_test_id))
    ordered_tdds = tuple(sorted(tdds, key=lambda item: item.acceptance_test_id))
    if ordered_gates != packet.gates or ordered_tdds != packet.tdd_evidence:
        raise CoordinatorAttestationInputError(
            "review packet gate or TDD evidence differs from raw offline executions"
        )
    task_policy_bindings = _task_policy_bindings(
        task=task,
        task_sha256=request.task_sha256,
        policy=policy,
        base=base,
        candidate=candidate,
        snapshot_phase=phases["snapshot"],
        runtime_manifest_sha256=coordinator.manifest_sha256,
    )
    bundle_sha256 = _bundle_sha256(
        phases=phases,
        task_sha256=request.task_sha256,
        policy=policy,
        packet=packet,
        raw_runs=raw_runs,
        batch=batch,
        provisioned=provisioned,
        context=context,
        bindings=task_policy_bindings,
    )
    return CoordinatorAttestationInputs(
        task=task,
        task_sha256=request.task_sha256,
        policy=policy,
        review_packet=packet,
        base_snapshot=base,
        candidate_snapshot=candidate,
        red_snapshots=red,
        raw_offline_runs=raw_runs,
        offline_runner_image=offline_image,
        gates=ordered_gates,
        tdd_evidence=ordered_tdds,
        offline_run_bindings=tuple(offline_bindings),
        task_policy_bindings=task_policy_bindings,
        broker_batch=batch,
        broker_prepared_raw=broker_prepared_raw,
        broker_outer_raw=broker_outer_raw,
        broker_allowlist_policy=broker_allowlist_policy,
        broker_pricing_policy=broker_pricing_policy,
        broker_requests=broker_requests,
        broker_invocations=broker_invocations,
        provisioned_broker_executions=provisioned,
        reviews=reviews,
        broker_inference=inference,
        broker_artifacts=broker_artifacts,
        broker_boundary_evidence=boundary,
        context=context,
        bundle_sha256=bundle_sha256,
    )
