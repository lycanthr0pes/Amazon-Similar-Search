"""Pinned-coordinator construction of outer workflow transition envelopes.

Only this coordinator-side module is allowed to construct a prepared action or
the next digest-chained request.  The root-owned outer process parses the
resulting bytes with its independent stdlib validator before dispatching any
descriptor or advancing the workflow.
"""

from __future__ import annotations

import hashlib

from tools.ai_review.outer_workflow_state import encode_finalized_transition
from tools.ai_review.outer_workflow_state import encode_prepared_transition
from tools.ai_review.phase_protocol import EXTERNAL_PHASES
from tools.ai_review.phase_protocol import PHASE_ORDER
from tools.ai_review.phase_protocol import CoordinatorPhaseOutput
from tools.ai_review.phase_protocol import PhaseAction
from tools.ai_review.phase_protocol import PhaseProtocolError
from tools.ai_review.phase_protocol import PhaseRequest
from tools.ai_review.phase_protocol import PhaseResult
from tools.ai_review.phase_protocol import canonical_json_bytes


def prepare_transition_bytes(
    request: PhaseRequest,
    action: PhaseAction,
    payload: bytes,
) -> bytes:
    """Serialize a coordinator-created action after revalidating its payload binding."""

    if not isinstance(request, PhaseRequest) or not isinstance(action, PhaseAction):
        raise PhaseProtocolError("coordinator prepare transition has invalid typed inputs")
    action.validate_for(request, payload)
    return encode_prepared_transition(action.model_dump(mode="json"), payload)


def finalize_transition_bytes(
    request: PhaseRequest,
    action: PhaseAction,
    prepared_payload: bytes,
    execution_evidence: bytes,
    coordinator_output: CoordinatorPhaseOutput,
) -> bytes:
    """Build the measured result and the only valid next phase request.

    External phases bind the raw outer evidence digest.  Coordinator-only
    phases require the finalize input to be the exact prepared payload, which
    prevents a caller from smuggling a second unbound evidence object into the
    transition.
    """

    if not isinstance(request, PhaseRequest) or not isinstance(action, PhaseAction):
        raise PhaseProtocolError("coordinator finalize transition has invalid typed inputs")
    if not isinstance(coordinator_output, CoordinatorPhaseOutput):
        raise PhaseProtocolError("coordinator finalize output is not typed evidence")
    action.validate_for(request, prepared_payload)
    coordinator_output.validate_for(request)
    expected_external = request.phase in EXTERNAL_PHASES
    if not isinstance(execution_evidence, bytes) or not execution_evidence:
        raise PhaseProtocolError("coordinator finalize evidence is empty")
    if not expected_external and execution_evidence != prepared_payload:
        raise PhaseProtocolError(
            "coordinator-only phase evidence differs from its prepared payload"
        )
    output_raw = canonical_json_bytes(coordinator_output)
    result = PhaseResult.create(
        request=request,
        output_artifacts_sha256=coordinator_output.output_artifacts_sha256,
        artifacts=coordinator_output.phase_artifacts(),
        candidate_snapshot_sha256=coordinator_output.candidate_snapshot_sha256,
        review_packet_sha256=coordinator_output.review_packet_sha256,
        external_execution_sha256=(
            hashlib.sha256(execution_evidence).hexdigest() if expected_external else None
        ),
        coordinator_output_sha256=hashlib.sha256(output_raw).hexdigest(),
    )
    next_request_raw: bytes | None = None
    if request.sequence < len(PHASE_ORDER):
        next_request = PhaseRequest.create(
            workflow_id=request.workflow_id,
            phase=PHASE_ORDER[request.sequence],
            sequence=request.sequence + 1,
            previous_phase_sha256=result.phase_sha256,
            task_sha256=request.task_sha256,
            runtime_manifest_sha256=request.runtime_manifest_sha256,
            coordinator_key_id=request.coordinator_key_id,
            coordinator_public_key_sha256=request.coordinator_public_key_sha256,
            candidate_sha256=request.candidate_sha256,
            candidate_snapshot_sha256=coordinator_output.candidate_snapshot_sha256,
            review_packet_sha256=coordinator_output.review_packet_sha256,
            input_artifacts_sha256=result.output_artifacts_sha256,
        )
        next_request_raw = canonical_json_bytes(next_request)
    return encode_finalized_transition(
        result.model_dump(mode="json"),
        output_raw,
        next_request_raw,
    )
