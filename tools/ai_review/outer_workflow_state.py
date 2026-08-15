"""Stdlib-only fixed seven-phase state machine for the external launcher.

The outer process treats coordinator output as untrusted bytes: every request,
action, semantic artifact, result, and next request is canonically revalidated.
Only the descriptor embedded in the coordinator prepare envelope reaches the
offline or provisioned-broker executor.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any


PHASE_ORDER = (
    "snapshot",
    "red-snapshot",
    "offline",
    "review-packet",
    "broker",
    "sign",
    "attested-judge",
)
_EXTERNAL = {"offline": "offline", "broker": "broker"}
_SHA_RE = re.compile(r"^[0-9a-f]{64}$")
_ARTIFACT_RE = re.compile(r"^[a-z][a-z0-9-]*(?::[A-Z][A-Z0-9_-]{0,63})?$")
_REQUEST_DOMAIN = b"amazon-explorer-phase-request-v1\0"
_ACTION_DOMAIN = b"amazon-explorer-phase-action-v1\0"
_OUTPUT_DOMAIN = b"amazon-explorer-coordinator-phase-output-v1\0"
_RESULT_DOMAIN = b"amazon-explorer-phase-result-v1\0"
_PREPARED_DOMAIN = b"amazon-explorer-outer-prepared-transition-v1\0"
_FINALIZED_DOMAIN = b"amazon-explorer-outer-finalized-transition-v1\0"
# A prepared broker batch may contain 2,000,000 bytes before the transition
# envelope base64-encodes it.  Keep the envelope limit explicit instead of
# accidentally making a valid coordinator descriptor unreachable.
_MAX_PREPARED_BYTES = 3_000_000
_MAX_EXTERNAL_BYTES = 6_000_000
_MAX_FINALIZED_BYTES = 10_000_000


class OuterWorkflowStateError(RuntimeError):
    """Raised before a malformed or replayed workflow transition can continue."""


def _canonical(value: object) -> bytes:
    try:
        return (
            json.dumps(
                value,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            )
            + "\n"
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise OuterWorkflowStateError("workflow value is not canonical JSON") from exc


def _domain(domain: bytes, value: object) -> str:
    return hashlib.sha256(domain + _canonical(value)).hexdigest()


def _strict_json(raw: bytes, *, label: str, maximum: int) -> dict[str, Any]:
    if not isinstance(raw, bytes) or not raw or len(raw) > maximum:
        raise OuterWorkflowStateError(f"{label} is empty or exceeds its byte limit")

    def pairs(values: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in values:
            if key in result:
                raise OuterWorkflowStateError(f"{label} contains a duplicate field")
            result[key] = value
        return result

    def constant(_value: str) -> object:
        raise OuterWorkflowStateError(f"{label} contains a non-finite number")

    try:
        value = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=pairs,
            parse_constant=constant,
        )
    except OuterWorkflowStateError:
        raise
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise OuterWorkflowStateError(f"{label} is invalid JSON") from exc
    if not isinstance(value, dict) or _canonical(value) != raw:
        raise OuterWorkflowStateError(f"{label} is not canonical JSON")
    return value


def _exact(value: object, fields: set[str], *, label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise OuterWorkflowStateError(f"{label} has missing or unknown fields")
    return value


def _sha(value: object, *, label: str) -> str:
    if not isinstance(value, str) or _SHA_RE.fullmatch(value) is None:
        raise OuterWorkflowStateError(f"{label} is not a lowercase SHA-256")
    return value


def _integer(value: object, *, label: str, minimum: int, maximum: int) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise OuterWorkflowStateError(f"{label} is not a strict bounded integer")
    return value


def _decode_base64(value: object, *, label: str, maximum: int) -> bytes:
    if not isinstance(value, str) or len(value) > maximum * 2:
        raise OuterWorkflowStateError(f"{label} encoding is invalid")
    try:
        raw = base64.b64decode(value, validate=True)
    except (ValueError, UnicodeError) as exc:
        raise OuterWorkflowStateError(f"{label} encoding is invalid") from exc
    if not raw or len(raw) > maximum or base64.b64encode(raw).decode("ascii") != value:
        raise OuterWorkflowStateError(f"{label} is empty, oversized, or non-canonical")
    return raw


_REQUEST_FIELDS = {
    "schema_version",
    "workflow_id",
    "phase",
    "sequence",
    "previous_phase_sha256",
    "task_sha256",
    "runtime_manifest_sha256",
    "coordinator_key_id",
    "coordinator_public_key_sha256",
    "candidate_sha256",
    "candidate_snapshot_sha256",
    "review_packet_sha256",
    "input_artifacts_sha256",
    "request_sha256",
}


def validate_phase_request_bytes(raw: bytes) -> dict[str, Any]:
    request = _exact(
        _strict_json(raw, label="phase request", maximum=128_000),
        _REQUEST_FIELDS,
        label="phase request",
    )
    phase = request["phase"]
    sequence = request["sequence"]
    if (
        request["schema_version"] != "1.0"
        or phase not in PHASE_ORDER
        or _integer(sequence, label="phase sequence", minimum=1, maximum=7)
        != PHASE_ORDER.index(phase) + 1
    ):
        raise OuterWorkflowStateError("phase request order is invalid")
    required = (
        "workflow_id",
        "task_sha256",
        "runtime_manifest_sha256",
        "coordinator_key_id",
        "coordinator_public_key_sha256",
        "candidate_sha256",
        "input_artifacts_sha256",
        "request_sha256",
    )
    for name in required:
        _sha(request[name], label=name)
    for name in (
        "previous_phase_sha256",
        "candidate_snapshot_sha256",
        "review_packet_sha256",
    ):
        if request[name] is not None:
            _sha(request[name], label=name)
    if (request["previous_phase_sha256"] is None) != (sequence == 1):
        raise OuterWorkflowStateError("phase request prior binding is invalid")
    if (request["candidate_snapshot_sha256"] is None) != (sequence == 1):
        raise OuterWorkflowStateError("phase request snapshot binding is invalid")
    needs_packet = sequence >= PHASE_ORDER.index("broker") + 1
    if (request["review_packet_sha256"] is not None) != needs_packet:
        raise OuterWorkflowStateError("phase request packet binding is invalid")
    unsigned = {key: value for key, value in request.items() if key != "request_sha256"}
    if not hmac.compare_digest(request["request_sha256"], _domain(_REQUEST_DOMAIN, unsigned)):
        raise OuterWorkflowStateError("phase request digest is invalid")
    return request


def _validate_action(
    value: object,
    *,
    request: dict[str, Any],
    payload: bytes,
) -> dict[str, Any]:
    action = _exact(
        value,
        {
            "schema_version",
            "workflow_id",
            "phase",
            "sequence",
            "request_sha256",
            "external_kind",
            "payload_sha256",
            "action_sha256",
        },
        label="phase action",
    )
    expected_kind = _EXTERNAL.get(request["phase"], "none")
    if (
        action["schema_version"] != "1.0"
        or action["workflow_id"] != request["workflow_id"]
        or action["phase"] != request["phase"]
        or _integer(action["sequence"], label="action sequence", minimum=1, maximum=7)
        != request["sequence"]
        or action["request_sha256"] != request["request_sha256"]
        or action["external_kind"] != expected_kind
        or action["payload_sha256"] != hashlib.sha256(payload).hexdigest()
    ):
        raise OuterWorkflowStateError("phase action does not match its request and payload")
    _sha(action["action_sha256"], label="action SHA-256")
    unsigned = {key: value for key, value in action.items() if key != "action_sha256"}
    if not hmac.compare_digest(action["action_sha256"], _domain(_ACTION_DOMAIN, unsigned)):
        raise OuterWorkflowStateError("phase action digest is invalid")
    return action


@dataclass(frozen=True)
class PreparedTransition:
    action: dict[str, Any]
    payload: bytes
    prepared_sha256: str


def encode_prepared_transition(action: dict[str, Any], payload: bytes) -> bytes:
    body = {
        "action": action,
        "payload_base64": base64.b64encode(payload).decode("ascii"),
        "schema_version": "1.0",
    }
    return _canonical({**body, "prepared_sha256": _domain(_PREPARED_DOMAIN, body)})


def parse_prepared_transition(
    raw: bytes,
    *,
    request: dict[str, Any],
) -> PreparedTransition:
    value = _exact(
        _strict_json(raw, label="prepared transition", maximum=_MAX_PREPARED_BYTES),
        {"action", "payload_base64", "prepared_sha256", "schema_version"},
        label="prepared transition",
    )
    if value["schema_version"] != "1.0":
        raise OuterWorkflowStateError("prepared transition version is invalid")
    payload = _decode_base64(value["payload_base64"], label="prepared payload", maximum=2_000_000)
    action = _validate_action(value["action"], request=request, payload=payload)
    body = {key: value[key] for key in ("action", "payload_base64", "schema_version")}
    prepared_sha256 = _sha(value["prepared_sha256"], label="prepared transition SHA-256")
    if not hmac.compare_digest(prepared_sha256, _domain(_PREPARED_DOMAIN, body)):
        raise OuterWorkflowStateError("prepared transition digest is invalid")
    return PreparedTransition(action=action, payload=payload, prepared_sha256=prepared_sha256)


def _artifact_semantic(name: str, raw: bytes) -> str:
    if name in {"base-snapshot", "candidate-snapshot"} or name.startswith("red-snapshot:"):
        try:
            value = raw.decode("ascii", errors="strict")
        except UnicodeError as exc:
            raise OuterWorkflowStateError("snapshot artifact is not an exact digest") from exc
        return _sha(value, label="snapshot artifact")
    if name == "review-packet":
        packet = _strict_json(raw, label="review packet", maximum=6_000_000)
        digest = _sha(packet.get("packet_sha256"), label="review packet SHA-256")
        body = {key: value for key, value in packet.items() if key != "packet_sha256"}
        compact = json.dumps(
            body,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
        if not hmac.compare_digest(digest, hashlib.sha256(compact).hexdigest()):
            raise OuterWorkflowStateError("review packet semantic digest is invalid")
        return digest
    return hashlib.sha256(raw).hexdigest()


def _validate_completeness(phase: str, names: set[str]) -> None:
    def suffix(prefix: str) -> set[str]:
        return {name.removeprefix(prefix + ":") for name in names if name.startswith(prefix + ":")}

    if phase == "snapshot" and names != {"base-snapshot", "candidate-snapshot", "policy"}:
        raise OuterWorkflowStateError("snapshot artifact set is incomplete")
    if phase == "red-snapshot" and (
        not names or any(not name.startswith("red-snapshot:") for name in names)
    ):
        raise OuterWorkflowStateError("RED artifact set is incomplete")
    if phase == "offline":
        gates, red, green = suffix("gate"), suffix("tdd-red"), suffix("tdd-green")
        expected = {
            *(f"gate:{item}" for item in gates),
            *(f"tdd-red:{item}" for item in red),
            *(f"tdd-green:{item}" for item in green),
        }
        if not gates or not red or red != green or not red <= gates or names != expected:
            raise OuterWorkflowStateError("offline artifact set is incomplete")
    if phase == "review-packet" and names != {"review-packet"}:
        raise OuterWorkflowStateError("review packet artifact set is incomplete")
    if phase == "broker" and names != {"reviewer", "adversary"}:
        raise OuterWorkflowStateError("broker artifact set is incomplete")
    if phase == "sign":
        gates, red, green = suffix("gate"), suffix("tdd-red"), suffix("tdd-green")
        expected = {
            "task",
            "policy",
            "reviewer",
            "adversary",
            *(f"gate:{item}" for item in gates),
            *(f"tdd-red:{item}" for item in red),
            *(f"tdd-green:{item}" for item in green),
        }
        if not gates or not red or red != green or not red <= gates or names != expected:
            raise OuterWorkflowStateError("sign artifact set is incomplete")
    if phase == "attested-judge" and names != {"verdict"}:
        raise OuterWorkflowStateError("judge artifact set is incomplete")


def _validate_coordinator_output(
    raw: bytes,
    *,
    request: dict[str, Any],
) -> tuple[dict[str, Any], tuple[dict[str, str], ...]]:
    output = _exact(
        _strict_json(raw, label="coordinator output", maximum=8_000_000),
        {
            "schema_version",
            "workflow_id",
            "phase",
            "sequence",
            "request_sha256",
            "artifacts",
            "candidate_snapshot_sha256",
            "review_packet_sha256",
            "output_artifacts_sha256",
            "output_sha256",
        },
        label="coordinator output",
    )
    if (
        output["schema_version"] != "1.0"
        or output["workflow_id"] != request["workflow_id"]
        or output["phase"] != request["phase"]
        or _integer(output["sequence"], label="coordinator output sequence", minimum=1, maximum=7)
        != request["sequence"]
        or output["request_sha256"] != request["request_sha256"]
        or not isinstance(output["artifacts"], list)
        or not 1 <= len(output["artifacts"]) <= 512
    ):
        raise OuterWorkflowStateError("coordinator output does not match the phase request")
    semantic: list[dict[str, str]] = []
    names: list[str] = []
    for value in output["artifacts"]:
        artifact = _exact(value, {"content_base64", "name"}, label="coordinator output artifact")
        name = artifact["name"]
        if not isinstance(name, str) or _ARTIFACT_RE.fullmatch(name) is None:
            raise OuterWorkflowStateError("coordinator artifact name is invalid")
        content = _decode_base64(
            artifact["content_base64"], label="coordinator artifact", maximum=6_000_000
        )
        names.append(name)
        semantic.append({"name": name, "sha256": _artifact_semantic(name, content)})
    if names != sorted(names) or len(names) != len(set(names)):
        raise OuterWorkflowStateError("coordinator artifacts are duplicated or unsorted")
    _validate_completeness(request["phase"], set(names))
    artifact_digest = hashlib.sha256(_canonical(semantic)).hexdigest()
    if output["output_artifacts_sha256"] != artifact_digest:
        raise OuterWorkflowStateError("coordinator artifact manifest digest is invalid")
    candidate_anchor = (
        next(item["sha256"] for item in semantic if item["name"] == "candidate-snapshot")
        if request["phase"] == "snapshot"
        else request["candidate_snapshot_sha256"]
    )
    packet_anchor = (
        next(item["sha256"] for item in semantic if item["name"] == "review-packet")
        if request["phase"] == "review-packet"
        else request["review_packet_sha256"]
    )
    if (
        output["candidate_snapshot_sha256"] != candidate_anchor
        or output["review_packet_sha256"] != packet_anchor
    ):
        raise OuterWorkflowStateError("coordinator output changed a workflow anchor")
    unsigned = {key: value for key, value in output.items() if key != "output_sha256"}
    if not hmac.compare_digest(
        _sha(output["output_sha256"], label="coordinator output SHA-256"),
        _domain(_OUTPUT_DOMAIN, unsigned),
    ):
        raise OuterWorkflowStateError("coordinator output digest is invalid")
    return output, tuple(semantic)


def _validate_phase_result(
    value: object,
    *,
    request: dict[str, Any],
    output: dict[str, Any],
    semantic: tuple[dict[str, str], ...],
    output_raw: bytes,
    external_raw: bytes | None,
) -> dict[str, Any]:
    result = _exact(
        value,
        {
            "schema_version",
            "request",
            "output_artifacts_sha256",
            "artifacts",
            "candidate_snapshot_sha256",
            "review_packet_sha256",
            "external_execution_sha256",
            "coordinator_output_sha256",
            "phase_sha256",
        },
        label="phase result",
    )
    expected_external = (
        hashlib.sha256(external_raw).hexdigest() if external_raw is not None else None
    )
    if (
        result["schema_version"] != "1.0"
        or result["request"] != request
        or result["artifacts"] != list(semantic)
        or result["output_artifacts_sha256"] != output["output_artifacts_sha256"]
        or result["candidate_snapshot_sha256"] != output["candidate_snapshot_sha256"]
        or result["review_packet_sha256"] != output["review_packet_sha256"]
        or result["external_execution_sha256"] != expected_external
        or result["coordinator_output_sha256"] != hashlib.sha256(output_raw).hexdigest()
    ):
        raise OuterWorkflowStateError("phase result differs from measured coordinator evidence")
    unsigned = {key: value for key, value in result.items() if key != "phase_sha256"}
    if not hmac.compare_digest(
        _sha(result["phase_sha256"], label="phase result SHA-256"),
        _domain(_RESULT_DOMAIN, unsigned),
    ):
        raise OuterWorkflowStateError("phase result digest is invalid")
    return result


@dataclass(frozen=True)
class FinalizedTransition:
    result: dict[str, Any]
    coordinator_output: bytes
    next_request: bytes | None
    finalized_sha256: str


def encode_finalized_transition(
    result: dict[str, Any],
    coordinator_output: bytes,
    next_request: bytes | None,
) -> bytes:
    body = {
        "coordinator_output_base64": base64.b64encode(coordinator_output).decode("ascii"),
        "next_request_base64": (
            None if next_request is None else base64.b64encode(next_request).decode("ascii")
        ),
        "phase_result": result,
        "schema_version": "1.0",
    }
    return _canonical({**body, "finalized_sha256": _domain(_FINALIZED_DOMAIN, body)})


def parse_finalized_transition(
    raw: bytes,
    *,
    request: dict[str, Any],
    external_raw: bytes | None,
) -> FinalizedTransition:
    value = _exact(
        _strict_json(raw, label="finalized transition", maximum=_MAX_FINALIZED_BYTES),
        {
            "coordinator_output_base64",
            "finalized_sha256",
            "next_request_base64",
            "phase_result",
            "schema_version",
        },
        label="finalized transition",
    )
    if value["schema_version"] != "1.0":
        raise OuterWorkflowStateError("finalized transition version is invalid")
    output_raw = _decode_base64(
        value["coordinator_output_base64"],
        label="coordinator output",
        maximum=8_000_000,
    )
    output, semantic = _validate_coordinator_output(output_raw, request=request)
    result = _validate_phase_result(
        value["phase_result"],
        request=request,
        output=output,
        semantic=semantic,
        output_raw=output_raw,
        external_raw=external_raw,
    )
    next_encoded = value["next_request_base64"]
    next_raw = (
        None
        if next_encoded is None
        else _decode_base64(next_encoded, label="next phase request", maximum=128_000)
    )
    if request["sequence"] == len(PHASE_ORDER):
        if next_raw is not None:
            raise OuterWorkflowStateError("final phase must not produce another request")
    else:
        if next_raw is None:
            raise OuterWorkflowStateError("non-final phase omitted its next request")
        next_request = validate_phase_request_bytes(next_raw)
        anchors = (
            (next_request["workflow_id"], request["workflow_id"]),
            (next_request["task_sha256"], request["task_sha256"]),
            (next_request["runtime_manifest_sha256"], request["runtime_manifest_sha256"]),
            (next_request["coordinator_key_id"], request["coordinator_key_id"]),
            (
                next_request["coordinator_public_key_sha256"],
                request["coordinator_public_key_sha256"],
            ),
            (next_request["candidate_sha256"], request["candidate_sha256"]),
            (
                next_request["candidate_snapshot_sha256"],
                output["candidate_snapshot_sha256"],
            ),
            (next_request["review_packet_sha256"], output["review_packet_sha256"]),
            (next_request["previous_phase_sha256"], result["phase_sha256"]),
            (
                next_request["input_artifacts_sha256"],
                result["output_artifacts_sha256"],
            ),
        )
        if (
            next_request["sequence"] != request["sequence"] + 1
            or next_request["phase"] != PHASE_ORDER[request["sequence"]]
            or any(actual != expected for actual, expected in anchors)
        ):
            raise OuterWorkflowStateError("next request is not chained to the finalized result")
    body = {
        "coordinator_output_base64": value["coordinator_output_base64"],
        "next_request_base64": next_encoded,
        "phase_result": value["phase_result"],
        "schema_version": "1.0",
    }
    finalized_sha256 = _sha(value["finalized_sha256"], label="finalized transition SHA-256")
    if not hmac.compare_digest(finalized_sha256, _domain(_FINALIZED_DOMAIN, body)):
        raise OuterWorkflowStateError("finalized transition digest is invalid")
    return FinalizedTransition(
        result=result,
        coordinator_output=output_raw,
        next_request=next_raw,
        finalized_sha256=finalized_sha256,
    )


@dataclass(frozen=True)
class WorkflowStateResult:
    transitions: tuple[FinalizedTransition, ...]


def run_fixed_workflow(
    initial_request: bytes,
    *,
    coordinator_prepare: Callable[[str, bytes], bytes],
    coordinator_finalize: Callable[[str, bytes, bytes], bytes],
    offline_execute: Callable[[bytes], bytes],
    broker_execute: Callable[[bytes], bytes],
    transition_committed: (
        Callable[[str, bytes, bytes, bytes, bytes, FinalizedTransition], None] | None
    ) = None,
) -> WorkflowStateResult:
    """Run the fixed chain; descriptors can originate only from coordinator prepare."""

    request_raw = initial_request
    transitions: list[FinalizedTransition] = []
    seen_requests: set[str] = set()
    seen_actions: set[str] = set()
    seen_finalized: set[str] = set()
    for expected_phase in PHASE_ORDER:
        request = validate_phase_request_bytes(request_raw)
        if request["phase"] != expected_phase or request["request_sha256"] in seen_requests:
            raise OuterWorkflowStateError("workflow request is reordered or replayed")
        seen_requests.add(request["request_sha256"])
        prepared_raw = coordinator_prepare(expected_phase, request_raw)
        prepared = parse_prepared_transition(prepared_raw, request=request)
        action_sha256 = prepared.action["action_sha256"]
        if action_sha256 in seen_actions:
            raise OuterWorkflowStateError("workflow action was replayed")
        seen_actions.add(action_sha256)
        kind = prepared.action["external_kind"]
        if kind == "offline":
            external = offline_execute(prepared.payload)
        elif kind == "broker":
            external = broker_execute(prepared.payload)
        else:
            external = prepared.payload
        maximum = _MAX_EXTERNAL_BYTES if kind != "none" else _MAX_PREPARED_BYTES
        if not isinstance(external, bytes) or not external or len(external) > maximum:
            raise OuterWorkflowStateError("outer execution evidence is empty or oversized")
        finalized_raw = coordinator_finalize(expected_phase, prepared_raw, external)
        finalized = parse_finalized_transition(
            finalized_raw,
            request=request,
            external_raw=(external if kind != "none" else None),
        )
        if finalized.finalized_sha256 in seen_finalized:
            raise OuterWorkflowStateError("finalized transition was replayed")
        seen_finalized.add(finalized.finalized_sha256)
        if transition_committed is not None:
            transition_committed(
                expected_phase,
                request_raw,
                prepared_raw,
                external,
                finalized_raw,
                finalized,
            )
        transitions.append(finalized)
        if finalized.next_request is not None:
            request_raw = finalized.next_request
    return WorkflowStateResult(transitions=tuple(transitions))
