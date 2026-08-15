from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from tools.ai_review.outer_workflow_state import OuterWorkflowStateError
from tools.ai_review.outer_workflow_state import encode_finalized_transition
from tools.ai_review.outer_workflow_state import encode_prepared_transition
from tools.ai_review.outer_workflow_state import parse_prepared_transition
from tools.ai_review.outer_workflow_state import run_fixed_workflow
from tools.ai_review.phase_protocol import EXTERNAL_PHASES
from tools.ai_review.phase_protocol import EMPTY_INITIAL_ARTIFACTS_SHA256
from tools.ai_review.phase_protocol import PHASE_ORDER
from tools.ai_review.phase_protocol import CoordinatorPhaseOutput
from tools.ai_review.phase_protocol import PhaseAction
from tools.ai_review.phase_protocol import PhaseRequest
from tools.ai_review.phase_protocol import PhaseResult
from tools.ai_review.phase_protocol import canonical_json_bytes
from tests.test_ai_review_phase_protocol import artifact_payloads_for


def _initial_request() -> PhaseRequest:
    return PhaseRequest.create(
        workflow_id="1" * 64,
        phase="snapshot",
        sequence=1,
        previous_phase_sha256=None,
        task_sha256="2" * 64,
        runtime_manifest_sha256="3" * 64,
        coordinator_key_id="4" * 64,
        coordinator_public_key_sha256="5" * 64,
        candidate_sha256="6" * 64,
        candidate_snapshot_sha256=None,
        review_packet_sha256=None,
        input_artifacts_sha256=EMPTY_INITIAL_ARTIFACTS_SHA256,
    )


def test_stdlib_state_machine_runs_exact_seven_phase_digest_chain() -> None:
    prepared_by_phase: dict[str, tuple[PhaseRequest, PhaseAction, bytes]] = {}
    outer_calls: list[str] = []
    committed: list[tuple[str, str]] = []

    def coordinator_prepare(phase: str, request_raw: bytes) -> bytes:
        request = PhaseRequest.model_validate_json(request_raw)
        assert request.phase == phase
        payload = canonical_json_bytes(
            {"descriptor": phase, "request_sha256": request.request_sha256}
        )
        kind = "offline" if phase == "offline" else "broker" if phase == "broker" else "none"
        action = PhaseAction.create(
            request=request,
            external_kind=kind,
            payload_sha256=hashlib.sha256(payload).hexdigest(),
        )
        prepared_by_phase[phase] = (request, action, payload)
        return encode_prepared_transition(action.model_dump(mode="json"), payload)

    def external(kind: str, payload: bytes) -> bytes:
        outer_calls.append(kind)
        return canonical_json_bytes(
            {"kind": kind, "prepared_sha256": hashlib.sha256(payload).hexdigest()}
        )

    def coordinator_finalize(phase: str, prepared_raw: bytes, evidence: bytes) -> bytes:
        del prepared_raw
        request, _action, payload = prepared_by_phase[phase]
        if phase not in EXTERNAL_PHASES:
            assert evidence == payload
        output = CoordinatorPhaseOutput.create(
            request=request,
            artifacts=artifact_payloads_for(phase),
        )
        output_raw = canonical_json_bytes(output)
        result = PhaseResult.create(
            request=request,
            output_artifacts_sha256=output.output_artifacts_sha256,
            artifacts=output.phase_artifacts(),
            candidate_snapshot_sha256=output.candidate_snapshot_sha256,
            review_packet_sha256=output.review_packet_sha256,
            external_execution_sha256=(
                hashlib.sha256(evidence).hexdigest() if phase in EXTERNAL_PHASES else None
            ),
            coordinator_output_sha256=hashlib.sha256(output_raw).hexdigest(),
        )
        next_raw = None
        if request.sequence < len(PHASE_ORDER):
            next_phase = PHASE_ORDER[request.sequence]
            next_request = PhaseRequest.create(
                workflow_id=request.workflow_id,
                phase=next_phase,
                sequence=request.sequence + 1,
                previous_phase_sha256=result.phase_sha256,
                task_sha256=request.task_sha256,
                runtime_manifest_sha256=request.runtime_manifest_sha256,
                coordinator_key_id=request.coordinator_key_id,
                coordinator_public_key_sha256=request.coordinator_public_key_sha256,
                candidate_sha256=request.candidate_sha256,
                candidate_snapshot_sha256=output.candidate_snapshot_sha256,
                review_packet_sha256=output.review_packet_sha256,
                input_artifacts_sha256=result.output_artifacts_sha256,
            )
            next_raw = canonical_json_bytes(next_request)
        return encode_finalized_transition(result.model_dump(mode="json"), output_raw, next_raw)

    completed = run_fixed_workflow(
        canonical_json_bytes(_initial_request()),
        coordinator_prepare=coordinator_prepare,
        coordinator_finalize=coordinator_finalize,
        offline_execute=lambda payload: external("offline", payload),
        broker_execute=lambda payload: external("broker", payload),
        transition_committed=lambda phase, _request, _prepared, _external, _finalized, value: (
            committed.append((phase, value.result["phase_sha256"]))
        ),
    )

    assert [item.result["request"]["phase"] for item in completed.transitions] == list(PHASE_ORDER)
    assert outer_calls == ["offline", "broker"]
    assert [phase for phase, _digest in committed] == list(PHASE_ORDER)
    assert completed.transitions[-1].next_request is None


def test_state_machine_rejects_self_valid_next_request_not_bound_to_output() -> None:
    initial = _initial_request()
    action_payload = b'{"snapshot":"prepared"}\n'
    action = PhaseAction.create(
        request=initial,
        external_kind="none",
        payload_sha256=hashlib.sha256(action_payload).hexdigest(),
    )

    def prepare(_phase: str, _request: bytes) -> bytes:
        return encode_prepared_transition(action.model_dump(mode="json"), action_payload)

    def finalize(_phase: str, _prepared: bytes, _evidence: bytes) -> bytes:
        output = CoordinatorPhaseOutput.create(
            request=initial,
            artifacts=artifact_payloads_for("snapshot"),
        )
        output_raw = canonical_json_bytes(output)
        result = PhaseResult.create(
            request=initial,
            output_artifacts_sha256=output.output_artifacts_sha256,
            artifacts=output.phase_artifacts(),
            candidate_snapshot_sha256=output.candidate_snapshot_sha256,
            review_packet_sha256=None,
            external_execution_sha256=None,
            coordinator_output_sha256=hashlib.sha256(output_raw).hexdigest(),
        )
        forged_next = PhaseRequest.create(
            workflow_id=initial.workflow_id,
            phase="red-snapshot",
            sequence=2,
            previous_phase_sha256=result.phase_sha256,
            task_sha256=initial.task_sha256,
            runtime_manifest_sha256=initial.runtime_manifest_sha256,
            coordinator_key_id=initial.coordinator_key_id,
            coordinator_public_key_sha256=initial.coordinator_public_key_sha256,
            candidate_sha256=initial.candidate_sha256,
            candidate_snapshot_sha256=output.candidate_snapshot_sha256,
            review_packet_sha256=None,
            input_artifacts_sha256="f" * 64,
        )
        return encode_finalized_transition(
            result.model_dump(mode="json"),
            output_raw,
            canonical_json_bytes(forged_next),
        )

    with pytest.raises(OuterWorkflowStateError, match="not chained"):
        run_fixed_workflow(
            canonical_json_bytes(initial),
            coordinator_prepare=prepare,
            coordinator_finalize=finalize,
            offline_execute=lambda _payload: pytest.fail("offline must not run"),
            broker_execute=lambda _payload: pytest.fail("broker must not run"),
        )


def test_outer_workflow_state_imports_with_isolated_no_site_python(tmp_path: Path) -> None:
    module = Path(__file__).parents[1] / "tools" / "ai_review" / "outer_workflow_state.py"
    script = (
        "import importlib.util,sys;"
        "spec=importlib.util.spec_from_file_location('outer_state',sys.argv[1]);"
        "value=importlib.util.module_from_spec(spec);sys.modules[spec.name]=value;"
        "spec.loader.exec_module(value);"
        "assert sys.flags.isolated and sys.flags.no_site;"
        "assert 'pydantic' not in sys.modules and 'cryptography' not in sys.modules"
    )
    result = subprocess.run(
        [sys.executable, "-I", "-S", "-c", script, str(module)],
        cwd=tmp_path,
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
        env={"PATH": os.defpath, "LC_ALL": "C"},
    )
    assert result.returncode == 0, result.stderr


def test_prepared_transition_rejects_unknown_field() -> None:
    request = _initial_request()
    payload = b'{"snapshot":"prepared"}\n'
    action = PhaseAction.create(
        request=request,
        external_kind="none",
        payload_sha256=hashlib.sha256(payload).hexdigest(),
    )
    encoded = json.loads(encode_prepared_transition(action.model_dump(mode="json"), payload))
    encoded["descriptor"] = ["podman", "run", "--privileged"]
    forged = (json.dumps(encoded, sort_keys=True, separators=(",", ":")) + "\n").encode()
    with pytest.raises(OuterWorkflowStateError, match="unknown"):
        parse_prepared_transition(
            forged,
            request=json.loads(canonical_json_bytes(request)),
        )


def test_prepared_transition_accepts_maximum_broker_descriptor_envelope() -> None:
    request = PhaseRequest.create(
        **{
            **_initial_request().model_dump(mode="json", exclude={"request_sha256"}),
            "phase": "broker",
            "sequence": 5,
            "previous_phase_sha256": "8" * 64,
            "candidate_snapshot_sha256": "9" * 64,
            "review_packet_sha256": "a" * 64,
        }
    )
    payload = b"x" * 2_000_000
    action = PhaseAction.create(
        request=request,
        external_kind="broker",
        payload_sha256=hashlib.sha256(payload).hexdigest(),
    )
    prepared = parse_prepared_transition(
        encode_prepared_transition(action.model_dump(mode="json"), payload),
        request=request.model_dump(mode="json"),
    )
    assert prepared.payload == payload


def test_prepared_transition_rejects_boolean_sequence() -> None:
    request = _initial_request()
    payload = b'{"snapshot":"prepared"}\n'
    action = PhaseAction.create(
        request=request,
        external_kind="none",
        payload_sha256=hashlib.sha256(payload).hexdigest(),
    )
    encoded = json.loads(encode_prepared_transition(action.model_dump(mode="json"), payload))
    encoded["action"]["sequence"] = True
    unsigned = {key: value for key, value in encoded["action"].items() if key != "action_sha256"}
    encoded["action"]["action_sha256"] = hashlib.sha256(
        b"amazon-explorer-phase-action-v1\0" + canonical_json_bytes(unsigned)
    ).hexdigest()
    body = {key: encoded[key] for key in ("action", "payload_base64", "schema_version")}
    encoded["prepared_sha256"] = hashlib.sha256(
        b"amazon-explorer-outer-prepared-transition-v1\0" + canonical_json_bytes(body)
    ).hexdigest()
    forged = canonical_json_bytes(encoded)
    with pytest.raises(OuterWorkflowStateError, match="strict bounded integer"):
        parse_prepared_transition(forged, request=request.model_dump(mode="json"))
