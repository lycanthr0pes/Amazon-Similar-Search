"""Coordinator-only construction of the production review packet phase.

The packet is rebuilt from immutable snapshot trees and the full raw offline
evidence committed by the preceding phase.  No diff, gate result, TDD result,
context text, packet, or phase output can be supplied by the outer caller.
"""

from __future__ import annotations

import hashlib
import hmac
import re
from collections.abc import Mapping
from collections.abc import Sequence

from tools.ai_review.attested_judge import TrustedAttestationContext
from tools.ai_review.attested_judge import derive_offline_artifacts
from tools.ai_review.coordinator_runtime import CoordinatorRuntimeEvidence
from tools.ai_review.models import PolicyReport
from tools.ai_review.models import TaskSpec
from tools.ai_review.offline_runner import OfflineRunEvidence
from tools.ai_review.phase_protocol import CoordinatorPhaseOutput
from tools.ai_review.phase_protocol import PhaseOutputArtifact
from tools.ai_review.phase_protocol import PhaseProtocolError
from tools.ai_review.phase_protocol import PhaseRequest
from tools.ai_review.review_packet import ReviewPacket
from tools.ai_review.review_packet import build_review_packet_from_snapshots
from tools.ai_review.review_packet import canonical_packet_bytes
from tools.ai_review.snapshot import RedTddSnapshotEvidence
from tools.ai_review.snapshot import SnapshotEvidence


_PINNED_IMAGE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/:+-]*@(sha256:[0-9a-f]{64})$")
_PENDING_DOMAIN = b"amazon-explorer-review-packet-pending-context-v1\0"


class CoordinatorReviewPacketError(PhaseProtocolError):
    """Raised when immutable workflow evidence cannot produce one packet."""


def _pending(request: PhaseRequest, label: str) -> str:
    digest = hashlib.sha256(_PENDING_DOMAIN)
    digest.update(request.request_sha256.encode("ascii"))
    digest.update(b"\0")
    digest.update(label.encode("ascii"))
    return digest.hexdigest()


def _validate_inputs(
    request: PhaseRequest,
    *,
    task: TaskSpec,
    policy: PolicyReport,
    base_snapshot: SnapshotEvidence,
    candidate_snapshot: SnapshotEvidence,
    red_snapshots: Mapping[str, RedTddSnapshotEvidence],
    raw_offline_runs: Sequence[OfflineRunEvidence],
    offline_runner_image: str,
    coordinator: CoordinatorRuntimeEvidence,
    candidate_uid: int,
) -> None:
    if type(request) is not PhaseRequest or request.phase != "review-packet":
        raise CoordinatorReviewPacketError("review packet requested for the wrong phase")
    if type(task) is not TaskSpec or task.schema_version != "2.0":
        raise CoordinatorReviewPacketError("review packet requires strict TaskSpec v2")
    if type(policy) is not PolicyReport or not policy.passed or policy.patch_sha256 is None:
        raise CoordinatorReviewPacketError("review packet requires a passing strict policy")
    if (
        type(base_snapshot) is not SnapshotEvidence
        or type(candidate_snapshot) is not SnapshotEvidence
    ):
        raise CoordinatorReviewPacketError("review packet snapshot types are invalid")
    if type(red_snapshots) is not dict or any(
        type(key) is not str or type(value) is not RedTddSnapshotEvidence
        for key, value in red_snapshots.items()
    ):
        raise CoordinatorReviewPacketError("review packet RED snapshot mapping is invalid")
    if type(raw_offline_runs) not in {tuple, list} or any(
        type(value) is not OfflineRunEvidence for value in raw_offline_runs
    ):
        raise CoordinatorReviewPacketError("review packet raw offline evidence is invalid")
    if type(coordinator) is not CoordinatorRuntimeEvidence:
        raise CoordinatorReviewPacketError("review packet coordinator evidence is invalid")
    if type(candidate_uid) is not int or not 1 <= candidate_uid <= 2**31 - 1:
        raise CoordinatorReviewPacketError("review packet candidate UID is invalid")
    image_match = _PINNED_IMAGE_RE.fullmatch(offline_runner_image)
    if image_match is None or not hmac.compare_digest(
        image_match.group(1), coordinator.offline_runner_image_digest
    ):
        raise CoordinatorReviewPacketError("review packet offline image is not manifest pinned")
    if (
        request.task_sha256 != coordinator.task_sha256
        or request.runtime_manifest_sha256 != coordinator.manifest_sha256
        or policy.task_sha256 != request.task_sha256
        or policy.patch_sha256 != request.candidate_sha256
        or base_snapshot.commit_sha != task.base_sha
        or candidate_snapshot.commit_sha != policy.head_sha
        or candidate_snapshot.snapshot_sha256 != request.candidate_snapshot_sha256
    ):
        raise CoordinatorReviewPacketError("review packet inputs changed a workflow anchor")
    expected_tests = {
        acceptance.id for acceptance in task.acceptance_tests if acceptance.kind == "test"
    }
    if not expected_tests or set(red_snapshots) != expected_tests:
        raise CoordinatorReviewPacketError("review packet RED snapshots are incomplete")


def _offline_context(
    request: PhaseRequest,
    *,
    base_snapshot: SnapshotEvidence,
    candidate_snapshot: SnapshotEvidence,
    coordinator: CoordinatorRuntimeEvidence,
) -> TrustedAttestationContext:
    """Build a typed context whose pre-broker fields are deterministic sentinels.

    ``derive_offline_artifacts`` consumes only the runtime, image, and snapshot
    fields at this point.  The final sign/judge context is reconstructed after
    the packet and both provisioned broker executions exist; pending values are
    never persisted as an attestation context.
    """

    return TrustedAttestationContext(
        runtime_manifest_sha256=coordinator.manifest_sha256,
        coordinator_image_digest=coordinator.coordinator_image_digest,
        offline_runner_image_digest=coordinator.offline_runner_image_digest,
        broker_image_digest=coordinator.broker_image_digest,
        broker_gateway_image_digest=coordinator.broker_gateway_image_digest,
        broker_egress_boundary_sha256=_pending(request, "broker-egress-boundary"),
        broker_allowlist_policy_sha256=coordinator.broker_allowlist_policy_sha256,
        broker_ledger_identity_sha256=_pending(request, "broker-ledger-identity"),
        broker_packet_reservation_limit=coordinator.broker_packet_reservation_limit,
        broker_pricing_policy_sha256=coordinator.broker_pricing_policy_sha256,
        broker_packet_cost_limit_microusd=coordinator.broker_packet_cost_limit_microusd,
        base_snapshot_sha256=base_snapshot.snapshot_sha256,
        base_snapshot_manifest_sha256=base_snapshot.manifest_sha256,
        base_commit_tree_sha=base_snapshot.commit_tree_sha,
        candidate_snapshot_sha256=candidate_snapshot.snapshot_sha256,
        candidate_snapshot_manifest_sha256=candidate_snapshot.manifest_sha256,
        candidate_commit_tree_sha=candidate_snapshot.commit_tree_sha,
        review_packet_sha256=_pending(request, "review-packet"),
        review_output_schema_sha256=_pending(request, "review-output-schema"),
    )


def build_review_packet_phase_output(
    request: PhaseRequest,
    *,
    task: TaskSpec,
    policy: PolicyReport,
    base_snapshot: SnapshotEvidence,
    candidate_snapshot: SnapshotEvidence,
    red_snapshots: Mapping[str, RedTddSnapshotEvidence],
    raw_offline_runs: Sequence[OfflineRunEvidence],
    offline_runner_image: str,
    coordinator: CoordinatorRuntimeEvidence,
    candidate_uid: int,
) -> tuple[CoordinatorPhaseOutput, ReviewPacket]:
    """Remeasure every offline artifact and produce the one canonical packet."""

    _validate_inputs(
        request,
        task=task,
        policy=policy,
        base_snapshot=base_snapshot,
        candidate_snapshot=candidate_snapshot,
        red_snapshots=red_snapshots,
        raw_offline_runs=raw_offline_runs,
        offline_runner_image=offline_runner_image,
        coordinator=coordinator,
        candidate_uid=candidate_uid,
    )
    context = _offline_context(
        request,
        base_snapshot=base_snapshot,
        candidate_snapshot=candidate_snapshot,
        coordinator=coordinator,
    )
    try:
        gates, tdd_evidence, _bindings = derive_offline_artifacts(
            task=task,
            policy=policy,
            task_sha256=request.task_sha256,
            raw_runs=tuple(raw_offline_runs),
            base_snapshot=base_snapshot,
            candidate_snapshot=candidate_snapshot,
            red_snapshots=tuple(red_snapshots[key] for key in sorted(red_snapshots)),
            offline_runner_image=offline_runner_image,
            context=context,
            candidate_uid=candidate_uid,
        )
        packet = build_review_packet_from_snapshots(
            task=task,
            task_sha256=request.task_sha256,
            policy=policy,
            base_snapshot_root=base_snapshot.root,
            candidate_snapshot_root=candidate_snapshot.root,
            context_paths=(),
            candidate_uid=candidate_uid,
            gates=gates,
            tdd_evidence=tdd_evidence,
        )
        packet_raw = canonical_packet_bytes(packet)
        output = CoordinatorPhaseOutput.create(
            request=request,
            artifacts=(PhaseOutputArtifact.create("review-packet", packet_raw),),
        )
    except (TypeError, ValueError) as exc:
        raise CoordinatorReviewPacketError(
            "immutable workflow evidence did not produce a valid review packet"
        ) from exc
    if output.review_packet_sha256 != packet.packet_sha256:
        raise CoordinatorReviewPacketError("review packet semantic digest is inconsistent")
    return output, packet
