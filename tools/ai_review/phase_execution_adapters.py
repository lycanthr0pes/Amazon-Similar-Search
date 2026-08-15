"""Typed coordinator adapters for phase-specific outer execution protocols."""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from tools.ai_review.broker_phase_protocol import BrokerRuntimeBinding
from tools.ai_review.broker_phase_protocol import canonical_prepared_broker_batch_bytes
from tools.ai_review.broker_phase_protocol import finalize_provisioned_broker_execution
from tools.ai_review.broker_phase_protocol import prepare_provisioned_broker_execution
from tools.ai_review.codex_adapter import IsolatedBrokerInvocation
from tools.ai_review.offline_phase_protocol import canonical_offline_run_evidence_bytes
from tools.ai_review.offline_phase_protocol import canonical_prepared_offline_batch_bytes
from tools.ai_review.offline_phase_protocol import finalize_offline_batch
from tools.ai_review.offline_phase_protocol import prepare_offline_batch
from tools.ai_review.phase_protocol import CoordinatorPhaseOutput
from tools.ai_review.phase_protocol import PhaseAction
from tools.ai_review.phase_protocol import PhaseOutputArtifact
from tools.ai_review.phase_protocol import PhaseProtocolError
from tools.ai_review.phase_protocol import PhaseRequest
from tools.ai_review.phase_protocol import canonical_json_bytes
from tools.ai_review.snapshot import RedTddSnapshotEvidence
from tools.ai_review.snapshot import SnapshotEvidence


def prepare_broker_phase_action(
    request: PhaseRequest,
    *,
    invocations: Sequence[IsolatedBrokerInvocation],
    runtime: BrokerRuntimeBinding,
    gateway_image: str,
    broker_gateway_image_digest: str,
    allowlist_policy: bytes,
    broker_allowlist_policy_sha256: str,
    pricing_policy: bytes,
    broker_pricing_policy_sha256: str,
    broker_ledger_identity_sha256: str,
    broker_packet_reservation_limit: int,
    broker_packet_cost_limit_microusd: int,
    candidate_uid: int,
    timeout_seconds: int = 240,
) -> tuple[PhaseAction, bytes]:
    """Prepare the exact reviewer/adversary provisioned broker batch."""

    if (
        request.phase != "broker"
        or request.candidate_snapshot_sha256 is None
        or request.review_packet_sha256 is None
    ):
        raise PhaseProtocolError("broker phase request lacks snapshot or packet bindings")
    prepared = prepare_provisioned_broker_execution(
        workflow_id=request.workflow_id,
        phase_request_sha256=request.request_sha256,
        task_sha256=request.task_sha256,
        runtime_manifest_sha256=request.runtime_manifest_sha256,
        candidate_snapshot_sha256=request.candidate_snapshot_sha256,
        review_packet_sha256=request.review_packet_sha256,
        invocations=invocations,
        runtime=runtime,
        gateway_image=gateway_image,
        broker_gateway_image_digest=broker_gateway_image_digest,
        allowlist_policy=allowlist_policy,
        broker_allowlist_policy_sha256=broker_allowlist_policy_sha256,
        pricing_policy=pricing_policy,
        broker_pricing_policy_sha256=broker_pricing_policy_sha256,
        broker_ledger_identity_sha256=broker_ledger_identity_sha256,
        broker_packet_reservation_limit=broker_packet_reservation_limit,
        broker_packet_cost_limit_microusd=broker_packet_cost_limit_microusd,
        candidate_uid=candidate_uid,
        timeout_seconds=timeout_seconds,
    )
    payload = canonical_prepared_broker_batch_bytes(prepared)
    return (
        PhaseAction.create(
            request=request,
            external_kind="broker",
            payload_sha256=hashlib.sha256(payload).hexdigest(),
        ),
        payload,
    )


def _broker_artifact_bytes(
    value: Any,
    *,
    final_ledger: Any,
    prepared_sha256: str,
    outer_sha256: str,
) -> bytes:
    execution = value.execution
    return canonical_json_bytes(
        {
            "broker_egress_boundary_sha256": execution.broker_egress_boundary_sha256,
            "broker_egress_lifecycle_sha256": value.broker_egress_lifecycle_sha256,
            "broker_ledger_identity_sha256": execution.broker_ledger_identity_sha256,
            "broker_packet_cost_limit_microusd": execution.broker_packet_cost_limit_microusd,
            "broker_packet_reservation_limit": execution.broker_packet_reservation_limit,
            "broker_pricing_policy_sha256": execution.broker_pricing_policy_sha256,
            "cumulative_reserved_cost_microusd": (final_ledger.cumulative_reserved_cost_microusd),
            "cumulative_reserved_tokens": final_ledger.cumulative_reserved_tokens,
            "evidence_sha256": value.evidence_sha256,
            "execution_evidence_sha256": value.execution_evidence_sha256,
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


def finalize_broker_phase_output(
    request: PhaseRequest,
    action: PhaseAction,
    prepared_raw: bytes,
    outer_raw: bytes,
    *,
    allowlist_policy: bytes,
    pricing_policy: bytes,
) -> bytes:
    """Finalize provisioned lifecycle evidence into reviewer/adversary artifacts."""

    action.validate_for(request, prepared_raw)
    executions = finalize_provisioned_broker_execution(
        prepared_raw,
        outer_raw,
        allowlist_policy=allowlist_policy,
        pricing_policy=pricing_policy,
    )
    if tuple(value.execution.role for value in executions) != ("reviewer", "adversary"):
        raise PhaseProtocolError("broker finalize returned an incomplete role set")
    prepared_sha256 = hashlib.sha256(prepared_raw).hexdigest()
    outer_sha256 = hashlib.sha256(outer_raw).hexdigest()
    final_ledger = executions[-1].execution.ledger
    output = CoordinatorPhaseOutput.create(
        request=request,
        artifacts=tuple(
            sorted(
                (
                    PhaseOutputArtifact.create(
                        value.execution.role,
                        _broker_artifact_bytes(
                            value,
                            final_ledger=final_ledger,
                            prepared_sha256=prepared_sha256,
                            outer_sha256=outer_sha256,
                        ),
                    )
                    for value in executions
                ),
                key=lambda artifact: artifact.name,
            )
        ),
    )
    return canonical_json_bytes(output)


def prepare_offline_phase_action(
    request: PhaseRequest,
    *,
    task: Any,
    candidate_snapshot: SnapshotEvidence,
    red_snapshots: Mapping[str, RedTddSnapshotEvidence],
    artifact_root: Path,
    image: str,
    approved_image_digest: str,
    candidate_uid: int,
    timeout_seconds: int = 900,
    max_log_bytes: int = 1_000_000,
) -> tuple[PhaseAction, bytes]:
    """Prepare the only offline payload accepted by the root-owned outer dispatcher."""

    if request.phase != "offline" or request.candidate_snapshot_sha256 != (
        candidate_snapshot.snapshot_sha256
    ):
        raise PhaseProtocolError("offline phase request does not bind its candidate snapshot")
    prepared = prepare_offline_batch(
        workflow_id=request.workflow_id,
        request_sha256=request.request_sha256,
        task=task,
        task_sha256=request.task_sha256,
        candidate_sha256=request.candidate_sha256,
        candidate_snapshot=candidate_snapshot,
        red_snapshots=red_snapshots,
        artifact_root=artifact_root,
        image=image,
        approved_image_digest=approved_image_digest,
        candidate_uid=candidate_uid,
        timeout_seconds=timeout_seconds,
        max_log_bytes=max_log_bytes,
    )
    payload = canonical_prepared_offline_batch_bytes(prepared)
    return (
        PhaseAction.create(
            request=request,
            external_kind="offline",
            payload_sha256=hashlib.sha256(payload).hexdigest(),
        ),
        payload,
    )


def finalize_offline_phase_output(
    request: PhaseRequest,
    action: PhaseAction,
    prepared_raw: bytes,
    outer_raw: bytes,
    *,
    artifact_root: Path,
    candidate_uid: int,
) -> bytes:
    """Finalize a complete raw batch into canonical named phase artifacts."""

    action.validate_for(request, prepared_raw)
    runs = finalize_offline_batch(
        prepared_raw,
        outer_raw,
        artifact_root=artifact_root,
        candidate_uid=candidate_uid,
    )
    artifacts: list[PhaseOutputArtifact] = []
    for run in runs:
        prefix = "gate" if run.request.phase == "gate" else "tdd-" + run.request.phase
        artifacts.append(
            PhaseOutputArtifact.create(
                prefix + ":" + run.request.acceptance_test_id,
                canonical_offline_run_evidence_bytes(run),
            )
        )
    output = CoordinatorPhaseOutput.create(
        request=request,
        artifacts=tuple(sorted(artifacts, key=lambda artifact: artifact.name)),
    )
    return canonical_json_bytes(output)
