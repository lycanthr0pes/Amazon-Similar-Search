"""Reconstruct external phase inputs from immutable workflow artifacts.

This module runs only inside the pinned coordinator image.  The root-owned
outer launcher supplies paths and manifest-bound scalar values; descriptors are
always derived here from remeasured snapshots, packets, policies, prompts, and
runtime bindings.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from pathlib import Path
from typing import Any

from tools.ai_review.broker_phase_protocol import BrokerRuntimeBinding
from tools.ai_review.codex_adapter import BrokerBoundaryEvidence
from tools.ai_review.coordinator_runtime import CoordinatorRuntimeEvidence
from tools.ai_review.models import PolicyReport
from tools.ai_review.models import TaskSpec
from tools.ai_review.offline_phase_protocol import offline_evidence_from_dict
from tools.ai_review.phase_protocol import CoordinatorPhaseOutput
from tools.ai_review.phase_protocol import PhaseProtocolError
from tools.ai_review.phase_protocol import PhaseRequest
from tools.ai_review.phase_protocol import canonical_json_bytes
from tools.ai_review.preflight import PreflightError
from tools.ai_review.preflight import assert_candidate_cannot_mutate
from tools.ai_review.preflight import assert_candidate_cannot_mutate_tree
from tools.ai_review.preflight import read_protected_file
from tools.ai_review.review_packet import ReviewPacket
from tools.ai_review.review_packet import canonical_packet_bytes
from tools.ai_review.snapshot import SnapshotEvidence
from tools.ai_review.snapshot import measure_red_tdd_snapshot
from tools.ai_review.snapshot import verify_readonly_snapshot


_PINNED_IMAGE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/:+-]*@(sha256:[0-9a-f]{64})$")


class CoordinatorWorkflowInputError(PhaseProtocolError):
    """Raised when committed artifacts cannot reconstruct one exact action."""


def _canonical_compact(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise CoordinatorWorkflowInputError("workflow input is not canonical JSON") from exc


def _strict_json(raw: bytes, *, label: str) -> object:
    def pairs(values: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in values:
            if key in result:
                raise CoordinatorWorkflowInputError(f"{label} contains a duplicate field")
            result[key] = value
        return result

    try:
        return json.loads(raw.decode("utf-8", errors="strict"), object_pairs_hook=pairs)
    except CoordinatorWorkflowInputError:
        raise
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise CoordinatorWorkflowInputError(f"{label} is not strict JSON") from exc


def _pinned_image(image: str, expected_digest: str, *, label: str) -> str:
    match = _PINNED_IMAGE_RE.fullmatch(image if isinstance(image, str) else "")
    if match is None or not hmac.compare_digest(match.group(1), expected_digest):
        raise CoordinatorWorkflowInputError(f"{label} is not runtime-manifest pinned")
    return image


def _prior_outputs(root: Path) -> dict[str, CoordinatorPhaseOutput]:
    outputs: dict[str, CoordinatorPhaseOutput] = {}
    for path in sorted(root.rglob("coordinator-output.json")):
        try:
            raw = path.read_bytes()
            output = CoordinatorPhaseOutput.model_validate_json(raw)
        except (OSError, ValueError) as exc:
            raise CoordinatorWorkflowInputError("committed coordinator output is invalid") from exc
        if canonical_json_bytes(output) != raw or output.phase in outputs:
            raise CoordinatorWorkflowInputError(
                "committed coordinator outputs are noncanonical or duplicated"
            )
        outputs[output.phase] = output
    return outputs


def _artifact(
    outputs: dict[str, CoordinatorPhaseOutput],
    *,
    phase: str,
    name: str,
) -> bytes:
    output = outputs.get(phase)
    if output is None:
        raise CoordinatorWorkflowInputError(f"missing committed {phase} output")
    matches = [artifact for artifact in output.artifacts if artifact.name == name]
    if len(matches) != 1:
        raise CoordinatorWorkflowInputError(f"missing or duplicate committed artifact: {name}")
    return matches[0].content()


def _snapshot(root: Path, digest: str, *, candidate_uid: int) -> SnapshotEvidence:
    candidates = [
        path
        for path in root.rglob(digest)
        if path.name == digest and path.is_dir() and (path / "manifest.json").is_file()
    ]
    if len(candidates) != 1:
        raise CoordinatorWorkflowInputError("snapshot content-addressed root is not unique")
    try:
        measured = verify_readonly_snapshot(candidates[0], candidate_uid=candidate_uid)
    except Exception as exc:
        raise CoordinatorWorkflowInputError("snapshot failed immutable verification") from exc
    if not hmac.compare_digest(measured.snapshot_sha256, digest):
        raise CoordinatorWorkflowInputError("snapshot digest differs from its phase artifact")
    return measured


def _snapshots(
    root: Path,
    outputs: dict[str, CoordinatorPhaseOutput],
    *,
    candidate_uid: int,
) -> tuple[SnapshotEvidence, SnapshotEvidence]:
    try:
        base_digest = _artifact(outputs, phase="snapshot", name="base-snapshot").decode(
            "ascii", errors="strict"
        )
        candidate_digest = _artifact(outputs, phase="snapshot", name="candidate-snapshot").decode(
            "ascii", errors="strict"
        )
    except UnicodeError as exc:
        raise CoordinatorWorkflowInputError("snapshot digest artifact is not ASCII") from exc
    return (
        _snapshot(root, base_digest, candidate_uid=candidate_uid),
        _snapshot(root, candidate_digest, candidate_uid=candidate_uid),
    )


def _red_snapshots(
    root: Path,
    outputs: dict[str, CoordinatorPhaseOutput],
    *,
    task: TaskSpec,
    base: SnapshotEvidence,
    candidate: SnapshotEvidence,
    candidate_uid: int,
) -> dict[str, Any]:
    red: dict[str, Any] = {}
    for acceptance in task.acceptance_tests:
        if acceptance.kind != "test":
            continue
        if not acceptance.test_paths:
            raise CoordinatorWorkflowInputError(
                "production RED reconstruction requires TaskSpec v2 exact test_paths"
            )
        try:
            digest = _artifact(
                outputs,
                phase="red-snapshot",
                name="red-snapshot:" + acceptance.id,
            ).decode("ascii", errors="strict")
        except UnicodeError as exc:
            raise CoordinatorWorkflowInputError("RED digest artifact is not ASCII") from exc
        red_root = _snapshot(root, digest, candidate_uid=candidate_uid).root
        try:
            red[acceptance.id] = measure_red_tdd_snapshot(
                red_root=red_root,
                base_snapshot=base,
                candidate_snapshot=candidate,
                test_paths=tuple(acceptance.test_paths),
                candidate_uid=candidate_uid,
            )
        except Exception as exc:
            raise CoordinatorWorkflowInputError("RED snapshot failed exact remeasurement") from exc
    if not red:
        raise CoordinatorWorkflowInputError("production workflow requires at least one RED test")
    return red


def _protected_runtime_bytes(
    runtime_root: Path,
    filename: str,
    *,
    expected_sha256: str,
    candidate_uid: int,
    label: str,
) -> bytes:
    try:
        _evidence, raw = read_protected_file(
            runtime_root / filename,
            candidate_uid=candidate_uid,
            label=label,
            expected_sha256=expected_sha256,
            max_bytes=32 * 1024 * 1024,
        )
    except PreflightError as exc:
        raise CoordinatorWorkflowInputError(str(exc)) from exc
    return raw


def _runtime_binding(raw: bytes, *, expected_sha256: str) -> BrokerRuntimeBinding:
    if not hmac.compare_digest(hashlib.sha256(raw).hexdigest(), expected_sha256):
        raise CoordinatorWorkflowInputError("broker runtime binding SHA-256 differs")
    value = _strict_json(raw, label="broker runtime binding")
    try:
        binding = BrokerRuntimeBinding(**value)  # type: ignore[arg-type]
    except (TypeError, ValueError) as exc:
        raise CoordinatorWorkflowInputError("broker runtime binding is invalid") from exc
    if canonical_json_bytes(vars(binding)) != raw:
        raise CoordinatorWorkflowInputError("broker runtime binding is not canonical")
    return binding


def _review_schema(
    runtime_root: Path,
    output_root: Path,
    *,
    coordinator: CoordinatorRuntimeEvidence,
    candidate_uid: int,
) -> Path:
    raw = _protected_runtime_bytes(
        runtime_root,
        "schemas.json",
        expected_sha256=coordinator.schema_bundle_sha256,
        candidate_uid=candidate_uid,
        label="review schema bundle",
    )
    bundle = _strict_json(raw, label="schema bundle")
    if (
        not isinstance(bundle, dict)
        or set(bundle) != {"schema_version", "schema_sha256", "schemas"}
        or bundle["schema_version"] != "1.0"
        or not isinstance(bundle["schema_sha256"], dict)
        or not isinstance(bundle["schemas"], dict)
    ):
        raise CoordinatorWorkflowInputError("schema bundle structure is invalid")
    schema = bundle["schemas"].get("review.schema.json")
    expected = bundle["schema_sha256"].get("review.schema.json")
    if not isinstance(schema, dict) or not isinstance(expected, str):
        raise CoordinatorWorkflowInputError("schema bundle lacks the review schema")
    schema_raw = _canonical_compact(schema)
    if not hmac.compare_digest(hashlib.sha256(schema_raw).hexdigest(), expected):
        raise CoordinatorWorkflowInputError("review schema digest is invalid")
    path = output_root / "review.schema.json"
    try:
        descriptor = path.open("xb")
        with descriptor:
            descriptor.write(schema_raw + b"\n")
            descriptor.flush()
    except OSError as exc:
        raise CoordinatorWorkflowInputError("review schema output must be new") from exc
    return path


def _prompt(
    snapshot: SnapshotEvidence, role: str, expected_sha256: str, *, candidate_uid: int
) -> str:
    try:
        _evidence, raw = read_protected_file(
            snapshot.tree / "specs" / "prompts" / f"{role}.md",
            candidate_uid=candidate_uid,
            label=f"{role} review prompt",
            expected_sha256=expected_sha256,
            max_bytes=100_000,
        )
        return raw.decode("utf-8", errors="strict")
    except (PreflightError, UnicodeError) as exc:
        raise CoordinatorWorkflowInputError(f"{role} review prompt is invalid") from exc


def _strict_phase_inputs(
    request: PhaseRequest,
    task: TaskSpec | None,
    *,
    phase: str,
) -> None:
    if type(request) is not PhaseRequest or request.phase != phase:
        raise CoordinatorWorkflowInputError(f"{phase} inputs requested for wrong phase")
    if task is not None and (type(task) is not TaskSpec or task.schema_version != "2.0"):
        raise CoordinatorWorkflowInputError("production workflow requires strict TaskSpec v2")


def _protected_directory(path: Path, *, candidate_uid: int, label: str) -> Path:
    try:
        protected = assert_candidate_cannot_mutate(path, candidate_uid=candidate_uid)
    except PreflightError as exc:
        raise CoordinatorWorkflowInputError(str(exc)) from exc
    if not protected.is_dir() or protected.is_symlink():
        raise CoordinatorWorkflowInputError(f"{label} must be a protected directory")
    return protected


def snapshot_prepare_inputs(
    request: PhaseRequest,
    *,
    task: TaskSpec,
    candidate_repo: Path,
    output_root: Path,
    candidate_uid: int,
) -> dict[str, Any]:
    """Build the only input mapping allowed to retain the candidate mount."""

    _strict_phase_inputs(request, task, phase="snapshot")
    try:
        candidate = assert_candidate_cannot_mutate_tree(
            candidate_repo,
            candidate_uid=candidate_uid,
        ).root
    except PreflightError as exc:
        raise CoordinatorWorkflowInputError(str(exc)) from exc
    return {
        "candidate_repo": candidate,
        "candidate_uid": candidate_uid,
        "output_root": _protected_directory(
            output_root,
            candidate_uid=candidate_uid,
            label="snapshot output root",
        ),
        "task": task,
    }


def snapshot_finalize_inputs(
    request: PhaseRequest,
    *,
    snapshot_artifact_root: Path,
    candidate_uid: int,
) -> dict[str, Any]:
    """Build candidate-free inputs for snapshot remeasurement."""

    _strict_phase_inputs(request, None, phase="snapshot")
    return {
        "candidate_uid": candidate_uid,
        "snapshot_artifact_root": _protected_directory(
            snapshot_artifact_root,
            candidate_uid=candidate_uid,
            label="snapshot artifact root",
        ),
    }


def _red_snapshot_sources(
    request: PhaseRequest,
    *,
    task: TaskSpec,
    artifact_root: Path,
    snapshot_artifact_root: Path,
    candidate_uid: int,
) -> tuple[SnapshotEvidence, SnapshotEvidence, Path]:
    _strict_phase_inputs(request, task, phase="red-snapshot")
    store = _protected_directory(
        snapshot_artifact_root,
        candidate_uid=candidate_uid,
        label="snapshot artifact root",
    )
    committed = _protected_directory(
        artifact_root,
        candidate_uid=candidate_uid,
        label="committed workflow artifact root",
    )
    outputs = _prior_outputs(committed)
    base, candidate = _snapshots(store, outputs, candidate_uid=candidate_uid)
    if request.candidate_snapshot_sha256 != candidate.snapshot_sha256:
        raise CoordinatorWorkflowInputError("RED request changed the candidate snapshot anchor")
    return base, candidate, store


def red_snapshot_prepare_inputs(
    request: PhaseRequest,
    *,
    task: TaskSpec,
    artifact_root: Path,
    snapshot_artifact_root: Path,
    output_root: Path,
    candidate_uid: int,
) -> dict[str, Any]:
    """Remeasure snapshot-phase sources for RED construction without a candidate mount."""

    base, candidate, _store = _red_snapshot_sources(
        request,
        task=task,
        artifact_root=artifact_root,
        snapshot_artifact_root=snapshot_artifact_root,
        candidate_uid=candidate_uid,
    )
    return {
        "base_snapshot": base,
        "candidate_snapshot": candidate,
        "candidate_uid": candidate_uid,
        "output_root": _protected_directory(
            output_root,
            candidate_uid=candidate_uid,
            label="RED output root",
        ),
        "task": task,
    }


def red_snapshot_finalize_inputs(
    request: PhaseRequest,
    *,
    task: TaskSpec,
    artifact_root: Path,
    snapshot_artifact_root: Path,
    candidate_uid: int,
) -> dict[str, Any]:
    """Remeasure base/candidate sources and expose only the dedicated RED store."""

    base, candidate, store = _red_snapshot_sources(
        request,
        task=task,
        artifact_root=artifact_root,
        snapshot_artifact_root=snapshot_artifact_root,
        candidate_uid=candidate_uid,
    )
    return {
        "base_snapshot": base,
        "candidate_snapshot": candidate,
        "candidate_uid": candidate_uid,
        "snapshot_artifact_root": store,
        "task": task,
    }


def review_packet_prepare_inputs(
    request: PhaseRequest,
    *,
    task: TaskSpec,
    artifact_root: Path,
    snapshot_artifact_root: Path,
    coordinator: CoordinatorRuntimeEvidence,
    candidate_uid: int,
    offline_image: str,
) -> dict[str, Any]:
    """Rebuild every packet input from prior immutable phase artifacts."""

    _strict_phase_inputs(request, task, phase="review-packet")
    committed = _protected_directory(
        artifact_root,
        candidate_uid=candidate_uid,
        label="committed workflow artifact root",
    )
    snapshots = _protected_directory(
        snapshot_artifact_root,
        candidate_uid=candidate_uid,
        label="snapshot artifact root",
    )
    outputs = _prior_outputs(committed)
    base, candidate = _snapshots(snapshots, outputs, candidate_uid=candidate_uid)
    if request.candidate_snapshot_sha256 != candidate.snapshot_sha256:
        raise CoordinatorWorkflowInputError("review packet request changed the snapshot anchor")
    policy_raw = _artifact(outputs, phase="snapshot", name="policy")
    try:
        policy = PolicyReport.model_validate_json(policy_raw)
    except ValueError as exc:
        raise CoordinatorWorkflowInputError("committed policy artifact is invalid") from exc
    if canonical_json_bytes(policy) != policy_raw:
        raise CoordinatorWorkflowInputError("committed policy artifact is noncanonical")
    return {
        "base_snapshot": base,
        "candidate_snapshot": candidate,
        "candidate_uid": candidate_uid,
        "coordinator": coordinator,
        "offline_runner_image": _pinned_image(
            offline_image,
            coordinator.offline_runner_image_digest,
            label="offline image",
        ),
        "policy": policy,
        "raw_offline_runs": offline_runs_from_artifacts(committed),
        "red_snapshots": _red_snapshots(
            snapshots,
            outputs,
            task=task,
            base=base,
            candidate=candidate,
            candidate_uid=candidate_uid,
        ),
        "task": task,
    }


def review_packet_finalize_inputs(request: PhaseRequest) -> dict[str, Any]:
    """Return the only allowed input mapping for packet finalization."""

    _strict_phase_inputs(request, None, phase="review-packet")
    return {}


def external_prepare_inputs(
    request: PhaseRequest,
    *,
    task: TaskSpec,
    artifact_root: Path,
    snapshot_artifact_root: Path,
    output_root: Path,
    runtime_root: Path,
    coordinator: CoordinatorRuntimeEvidence,
    candidate_uid: int,
    offline_image: str,
    broker_image: str,
    broker_gateway_image: str,
    broker_ledger_identity_sha256: str | None,
    broker_runtime_binding_raw: bytes | None,
    expected_broker_runtime_binding_sha256: str | None,
) -> dict[str, Any]:
    """Build the exact input mapping for one external phase adapter."""

    outputs = _prior_outputs(artifact_root)
    base, candidate = _snapshots(snapshot_artifact_root, outputs, candidate_uid=candidate_uid)
    if request.candidate_snapshot_sha256 != candidate.snapshot_sha256:
        raise CoordinatorWorkflowInputError("request does not bind the candidate snapshot")
    if request.phase == "offline":
        return {
            "approved_image_digest": coordinator.offline_runner_image_digest,
            "artifact_root": snapshot_artifact_root,
            "candidate_snapshot": candidate,
            "candidate_uid": candidate_uid,
            "image": _pinned_image(
                offline_image,
                coordinator.offline_runner_image_digest,
                label="offline image",
            ),
            "red_snapshots": _red_snapshots(
                snapshot_artifact_root,
                outputs,
                task=task,
                base=base,
                candidate=candidate,
                candidate_uid=candidate_uid,
            ),
            "task": task,
        }
    if request.phase != "broker":
        raise CoordinatorWorkflowInputError("external prepare inputs requested for wrong phase")
    if (
        broker_ledger_identity_sha256 is None
        or broker_runtime_binding_raw is None
        or expected_broker_runtime_binding_sha256 is None
    ):
        raise CoordinatorWorkflowInputError("broker prepare lacks its outer runtime bindings")
    packet_raw = _artifact(outputs, phase="review-packet", name="review-packet")
    try:
        packet = ReviewPacket.model_validate_json(packet_raw)
    except ValueError as exc:
        raise CoordinatorWorkflowInputError("review packet artifact is invalid") from exc
    if canonical_packet_bytes(packet) != packet_raw:
        raise CoordinatorWorkflowInputError("review packet artifact is noncanonical")
    runtime = _runtime_binding(
        broker_runtime_binding_raw,
        expected_sha256=expected_broker_runtime_binding_sha256,
    )
    if Path("/candidate").exists():
        raise CoordinatorWorkflowInputError("candidate filesystem is mounted during broker phase")
    allowlist = _protected_runtime_bytes(
        runtime_root,
        "broker-egress-policy.json",
        expected_sha256=coordinator.broker_allowlist_policy_sha256,
        candidate_uid=candidate_uid,
        label="broker allowlist policy",
    )
    pricing = _protected_runtime_bytes(
        runtime_root,
        "openai-pricing-policy.json",
        expected_sha256=coordinator.broker_pricing_policy_sha256,
        candidate_uid=candidate_uid,
        label="broker pricing policy",
    )
    boundary = BrokerBoundaryEvidence(
        packet_sha256=packet.packet_sha256,
        external_preflight_sha256=hashlib.sha256(broker_runtime_binding_raw).hexdigest(),
        snapshot_manifest_sha256=candidate.manifest_sha256,
        isolation_attestation_sha256=runtime.security_evidence_sha256,
        candidate_filesystem_unmounted=True,
        read_only_snapshot_verified=True,
        network_isolation_verified=True,
        coordinator_attestation_verified=True,
    )
    return {
        "adversary_prompt": _prompt(
            candidate,
            "adversary",
            task.review_prompts.adversary_sha256,
            candidate_uid=candidate_uid,
        ),
        "allowlist_policy": allowlist,
        "approved_image_digest": coordinator.broker_image_digest,
        "boundary_evidence": boundary,
        "broker_allowlist_policy_sha256": coordinator.broker_allowlist_policy_sha256,
        "broker_gateway_image_digest": coordinator.broker_gateway_image_digest,
        "broker_ledger_identity_sha256": broker_ledger_identity_sha256,
        "broker_packet_cost_limit_microusd": coordinator.broker_packet_cost_limit_microusd,
        "broker_packet_reservation_limit": coordinator.broker_packet_reservation_limit,
        "broker_pricing_policy_sha256": coordinator.broker_pricing_policy_sha256,
        "candidate_uid": candidate_uid,
        "gateway_image": _pinned_image(
            broker_gateway_image,
            coordinator.broker_gateway_image_digest,
            label="broker gateway image",
        ),
        "image": _pinned_image(
            broker_image,
            coordinator.broker_image_digest,
            label="broker image",
        ),
        "output_schema": _review_schema(
            runtime_root,
            output_root,
            coordinator=coordinator,
            candidate_uid=candidate_uid,
        ),
        "packet": packet,
        "pricing_policy": pricing,
        "reviewer_prompt": _prompt(
            candidate,
            "reviewer",
            task.review_prompts.reviewer_sha256,
            candidate_uid=candidate_uid,
        ),
        "runtime": runtime,
        "task": task,
        "trusted_cwd": output_root,
    }


def external_finalize_inputs(
    request: PhaseRequest,
    *,
    artifact_root: Path,
    snapshot_artifact_root: Path,
    runtime_root: Path,
    coordinator: CoordinatorRuntimeEvidence,
    candidate_uid: int,
) -> dict[str, Any]:
    if request.phase == "offline":
        return {"artifact_root": snapshot_artifact_root, "candidate_uid": candidate_uid}
    if request.phase != "broker":
        raise CoordinatorWorkflowInputError("external finalize inputs requested for wrong phase")
    return {
        "allowlist_policy": _protected_runtime_bytes(
            runtime_root,
            "broker-egress-policy.json",
            expected_sha256=coordinator.broker_allowlist_policy_sha256,
            candidate_uid=candidate_uid,
            label="broker allowlist policy",
        ),
        "pricing_policy": _protected_runtime_bytes(
            runtime_root,
            "openai-pricing-policy.json",
            expected_sha256=coordinator.broker_pricing_policy_sha256,
            candidate_uid=candidate_uid,
            label="broker pricing policy",
        ),
    }


def offline_runs_from_artifacts(artifact_root: Path) -> tuple[Any, ...]:
    """Rebuild every full raw offline run from the committed inline artifacts."""

    outputs = _prior_outputs(artifact_root)
    output = outputs.get("offline")
    if output is None:
        raise CoordinatorWorkflowInputError("missing committed offline phase output")
    runs = []
    for artifact in output.artifacts:
        value = _strict_json(artifact.content(), label=artifact.name)
        runs.append(offline_evidence_from_dict(value))
    return tuple(runs)
