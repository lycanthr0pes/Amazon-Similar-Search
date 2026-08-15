from __future__ import annotations

from pathlib import Path

import pytest

from test_ai_review_attested_judge import TASK_SHA
from test_ai_review_attested_judge import make_strict_bundle
from tools.ai_review.coordinator_review_packet_phase import CoordinatorReviewPacketError
from tools.ai_review.coordinator_review_packet_phase import build_review_packet_phase_output
from tools.ai_review.coordinator_runtime import CoordinatorRuntimeEvidence
from tools.ai_review.coordinator_workflow_ops import finalize_workflow_transition
from tools.ai_review.coordinator_workflow_ops import prepare_workflow_transition
from tools.ai_review.outer_workflow_state import parse_finalized_transition
from tools.ai_review.outer_workflow_state import parse_prepared_transition
from tools.ai_review.phase_protocol import CoordinatorPhaseOutput
from tools.ai_review.phase_protocol import PhaseRequest
from tools.ai_review.review_packet import canonical_packet_bytes


def _request(strict) -> PhaseRequest:
    bundle = strict.bundle
    return PhaseRequest.create(
        workflow_id="1" * 64,
        phase="review-packet",
        sequence=4,
        previous_phase_sha256="2" * 64,
        task_sha256=TASK_SHA,
        runtime_manifest_sha256=bundle.context.runtime_manifest_sha256,
        coordinator_key_id="3" * 64,
        coordinator_public_key_sha256="4" * 64,
        candidate_sha256=bundle.policy.patch_sha256,
        candidate_snapshot_sha256=strict.candidate_snapshot.snapshot_sha256,
        review_packet_sha256=None,
        input_artifacts_sha256="5" * 64,
    )


def _coordinator(strict) -> CoordinatorRuntimeEvidence:
    context = strict.bundle.context
    return CoordinatorRuntimeEvidence(
        manifest_sha256=context.runtime_manifest_sha256,
        coordinator_image_digest=context.coordinator_image_digest,
        harness_sha256="6" * 64,
        task_sha256=TASK_SHA,
        dependency_lock_sha256="7" * 64,
        schema_bundle_sha256="8" * 64,
        coordinator_public_key_sha256="9" * 64,
        offline_runner_image_digest=context.offline_runner_image_digest,
        broker_image_digest=context.broker_image_digest,
        broker_gateway_image_digest=context.broker_gateway_image_digest,
        broker_allowlist_policy_sha256=context.broker_allowlist_policy_sha256,
        broker_packet_reservation_limit=context.broker_packet_reservation_limit,
        broker_pricing_policy_sha256=context.broker_pricing_policy_sha256,
        broker_packet_cost_limit_microusd=context.broker_packet_cost_limit_microusd,
    )


def _arguments(strict) -> dict[str, object]:
    bundle = strict.bundle
    return {
        "task": bundle.task,
        "policy": bundle.policy,
        "base_snapshot": strict.base_snapshot,
        "candidate_snapshot": strict.candidate_snapshot,
        "red_snapshots": {
            item.acceptance_test_id: snapshot
            for item, snapshot in zip(bundle.tdds, strict.red_snapshots, strict=True)
        },
        "raw_offline_runs": strict.raw_offline_runs,
        "offline_runner_image": strict.offline_runner_image,
        "coordinator": _coordinator(strict),
        "candidate_uid": strict.candidate_uid,
    }


def test_review_packet_phase_rebuilds_actual_packet_from_raw_offline_evidence(
    tmp_path: Path,
) -> None:
    strict = make_strict_bundle(tmp_path)
    output, packet = build_review_packet_phase_output(
        _request(strict),
        **_arguments(strict),
    )

    assert canonical_packet_bytes(packet) == canonical_packet_bytes(strict.bundle.review_packet)
    assert output.review_packet_sha256 == packet.packet_sha256
    assert output.artifacts[0].content() == canonical_packet_bytes(packet)


def test_review_packet_phase_rejects_incomplete_offline_evidence(tmp_path: Path) -> None:
    strict = make_strict_bundle(tmp_path)
    arguments = _arguments(strict)
    arguments["raw_offline_runs"] = strict.raw_offline_runs[:-1]

    with pytest.raises(CoordinatorReviewPacketError, match="did not produce"):
        build_review_packet_phase_output(_request(strict), **arguments)


def test_review_packet_ops_emit_and_finalize_one_actual_canonical_packet(tmp_path: Path) -> None:
    strict = make_strict_bundle(tmp_path)
    request = _request(strict)
    prepared_raw = prepare_workflow_transition(request, inputs=_arguments(strict))
    prepared = parse_prepared_transition(
        prepared_raw,
        request=request.model_dump(mode="json"),
    )
    output = CoordinatorPhaseOutput.model_validate_json(prepared.payload)
    assert output.artifacts[0].content() == canonical_packet_bytes(strict.bundle.review_packet)

    finalized_raw = finalize_workflow_transition(
        request,
        prepared_transition=prepared_raw,
        execution_evidence=prepared.payload,
        inputs={},
    )
    finalized = parse_finalized_transition(
        finalized_raw,
        request=request.model_dump(mode="json"),
        external_raw=None,
    )
    assert finalized.result["review_packet_sha256"] == strict.bundle.review_packet.packet_sha256
    assert finalized.next_request is not None
