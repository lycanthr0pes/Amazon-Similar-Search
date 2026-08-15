from __future__ import annotations

import hashlib

import pytest

from tools.ai_review.coordinator_phase_protocol import finalize_transition_bytes
from tools.ai_review.coordinator_phase_protocol import prepare_transition_bytes
from tools.ai_review.outer_workflow_state import parse_finalized_transition
from tools.ai_review.outer_workflow_state import parse_prepared_transition
from tools.ai_review.phase_protocol import CoordinatorPhaseOutput
from tools.ai_review.phase_protocol import PhaseAction
from tools.ai_review.phase_protocol import PhaseProtocolError
from tools.ai_review.phase_protocol import canonical_json_bytes
from tests.test_ai_review_phase_protocol import artifact_payloads_for
from tests.test_ai_review_phase_protocol import request_for


def test_coordinator_prepare_and_finalize_construct_the_only_next_request() -> None:
    request = request_for("snapshot")
    payload = b'{"compound":"snapshot"}\n'
    action = PhaseAction.create(
        request=request,
        external_kind="none",
        payload_sha256=hashlib.sha256(payload).hexdigest(),
    )
    prepared_raw = prepare_transition_bytes(request, action, payload)
    prepared = parse_prepared_transition(
        prepared_raw,
        request=request.model_dump(mode="json"),
    )
    output = CoordinatorPhaseOutput.create(
        request=request,
        artifacts=artifact_payloads_for("snapshot"),
    )
    finalized = parse_finalized_transition(
        finalize_transition_bytes(request, action, payload, payload, output),
        request=request.model_dump(mode="json"),
        external_raw=None,
    )

    assert prepared.payload == payload
    assert finalized.result["artifacts"] == [
        value.model_dump(mode="json") for value in output.phase_artifacts()
    ]
    assert finalized.next_request is not None
    assert b'"phase":"red-snapshot"' in finalized.next_request
    assert (
        b'"input_artifacts_sha256":"' + output.output_artifacts_sha256.encode() + b'"'
        in finalized.next_request
    )


def test_coordinator_only_finalize_rejects_a_second_payload() -> None:
    request = request_for("snapshot")
    payload = b'{"compound":"snapshot"}\n'
    action = PhaseAction.create(
        request=request,
        external_kind="none",
        payload_sha256=hashlib.sha256(payload).hexdigest(),
    )
    output = CoordinatorPhaseOutput.create(
        request=request,
        artifacts=artifact_payloads_for("snapshot"),
    )
    with pytest.raises(PhaseProtocolError, match="differs"):
        finalize_transition_bytes(request, action, payload, b"caller replacement", output)


def test_external_finalize_binds_raw_outer_evidence() -> None:
    request = request_for("snapshot").model_copy(
        update={
            "phase": "offline",
            "sequence": 3,
            "previous_phase_sha256": "d" * 64,
            "candidate_snapshot_sha256": "4" * 64,
        }
    )
    request = type(request).create(**request.model_dump(mode="json", exclude={"request_sha256"}))
    payload = b'{"offline":"prepared"}\n'
    external = b'{"offline":"raw evidence"}\n'
    action = PhaseAction.create(
        request=request,
        external_kind="offline",
        payload_sha256=hashlib.sha256(payload).hexdigest(),
    )
    output = CoordinatorPhaseOutput.create(
        request=request,
        artifacts=artifact_payloads_for("offline"),
    )
    finalized = parse_finalized_transition(
        finalize_transition_bytes(request, action, payload, external, output),
        request=request.model_dump(mode="json"),
        external_raw=external,
    )
    assert finalized.result["external_execution_sha256"] == hashlib.sha256(external).hexdigest()
    assert canonical_json_bytes(output) == finalized.coordinator_output
