"""Pinned-coordinator prepare/finalize dispatch for production workflow phases.

The root-owned outer process may choose only a phase and provide immutable input
artifacts.  It cannot supply a :class:`PhaseAction`, prepared payload, broker
invocation, argv, or descriptor.  This module derives those objects inside the
pinned coordinator, then wraps them in the canonical transition envelopes that
the independent stdlib outer state machine verifies.

All seven phases are connected here.  Signing and the attested judge rebuild
their expectations from the same canonical frozen evidence, without reopening
the broker ledger or re-probing its former runtime.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
import stat
import time
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from tools.ai_review.attestation import AttestationStatement
from tools.ai_review.attestation import SqliteNonceLedger
from tools.ai_review.attestation import load_coordinator_private_key
from tools.ai_review.attestation import load_trusted_public_key
from tools.ai_review.attestation import public_key_id
from tools.ai_review.attestation import sign_attestation
from tools.ai_review.attested_judge import build_frozen_bundle_expectations
from tools.ai_review.attested_judge import judge_frozen_attestation_bundle
from tools.ai_review.broker_phase_protocol import BrokerRuntimeBinding
from tools.ai_review.codex_adapter import BrokerBoundaryEvidence
from tools.ai_review.codex_adapter import CodexAdapter
from tools.ai_review.codex_adapter import IsolatedBrokerInvocation
from tools.ai_review.codex_adapter import ReviewRole
from tools.ai_review.coordinator_phase_protocol import finalize_transition_bytes
from tools.ai_review.coordinator_phase_protocol import prepare_transition_bytes
from tools.ai_review.coordinator_attestation_inputs import reconstruct_attestation_inputs
from tools.ai_review.coordinator_attestation_inputs import reconstruct_signed_attestations
from tools.ai_review.coordinator_review_packet_phase import build_review_packet_phase_output
from tools.ai_review.coordinator_runtime import CoordinatorRuntimeEvidence
from tools.ai_review.models import TaskSpec
from tools.ai_review.models import PolicyReport
from tools.ai_review.outer_workflow_state import parse_prepared_transition
from tools.ai_review.phase_execution_adapters import finalize_broker_phase_output
from tools.ai_review.phase_execution_adapters import finalize_offline_phase_output
from tools.ai_review.phase_execution_adapters import prepare_broker_phase_action
from tools.ai_review.phase_execution_adapters import prepare_offline_phase_action
from tools.ai_review.phase_protocol import CoordinatorPhaseOutput
from tools.ai_review.phase_protocol import PhaseAction
from tools.ai_review.phase_protocol import PhaseOutputArtifact
from tools.ai_review.phase_protocol import PhaseProtocolError
from tools.ai_review.phase_protocol import PhaseRequest
from tools.ai_review.phase_protocol import canonical_json_bytes
from tools.ai_review.policy import GitInspectionError
from tools.ai_review.policy import inspect_git_diff
from tools.ai_review.preflight import PreflightError
from tools.ai_review.preflight import assert_candidate_cannot_mutate
from tools.ai_review.preflight import assert_candidate_cannot_mutate_tree
from tools.ai_review.review_packet import ReviewPacket
from tools.ai_review.snapshot import RedTddSnapshotEvidence
from tools.ai_review.snapshot import SnapshotError
from tools.ai_review.snapshot import SnapshotEvidence
from tools.ai_review.snapshot import create_readonly_snapshot_pair_from_worktree
from tools.ai_review.snapshot import create_red_tdd_snapshot
from tools.ai_review.snapshot import measure_red_tdd_snapshot
from tools.ai_review.snapshot import verify_readonly_snapshot


class CoordinatorWorkflowOperationError(PhaseProtocolError):
    """Raised when a coordinator workflow operation is absent or discretionary."""


_SNAPSHOT_PREPARE_FIELDS = frozenset({"candidate_repo", "candidate_uid", "output_root", "task"})
_SNAPSHOT_FINALIZE_FIELDS = frozenset({"candidate_uid", "snapshot_artifact_root"})
_RED_PREPARE_FIELDS = frozenset(
    {"base_snapshot", "candidate_snapshot", "candidate_uid", "output_root", "task"}
)
_RED_FINALIZE_FIELDS = frozenset(
    {
        "base_snapshot",
        "candidate_snapshot",
        "candidate_uid",
        "snapshot_artifact_root",
        "task",
    }
)
_OFFLINE_PREPARE_FIELDS = frozenset(
    {
        "approved_image_digest",
        "artifact_root",
        "candidate_snapshot",
        "candidate_uid",
        "image",
        "red_snapshots",
        "task",
    }
)
_BROKER_PREPARE_FIELDS = frozenset(
    {
        "adversary_prompt",
        "allowlist_policy",
        "approved_image_digest",
        "boundary_evidence",
        "broker_allowlist_policy_sha256",
        "broker_gateway_image_digest",
        "broker_ledger_identity_sha256",
        "broker_packet_cost_limit_microusd",
        "broker_packet_reservation_limit",
        "broker_pricing_policy_sha256",
        "candidate_uid",
        "gateway_image",
        "image",
        "output_schema",
        "packet",
        "pricing_policy",
        "reviewer_prompt",
        "runtime",
        "task",
        "trusted_cwd",
    }
)
_OFFLINE_FINALIZE_FIELDS = frozenset({"artifact_root", "candidate_uid"})
_BROKER_FINALIZE_FIELDS = frozenset({"allowlist_policy", "pricing_policy"})
_REVIEW_PACKET_PREPARE_FIELDS = frozenset(
    {
        "base_snapshot",
        "candidate_snapshot",
        "candidate_uid",
        "coordinator",
        "offline_runner_image",
        "policy",
        "raw_offline_runs",
        "red_snapshots",
        "task",
    }
)
_REVIEW_PACKET_FINALIZE_FIELDS = frozenset()
_ATTESTATION_PREPARE_FIELDS = frozenset(
    {
        "artifact_root",
        "candidate_uid",
        "coordinator",
        "nonce_ledger",
        "runtime_root",
        "signing_key",
        "snapshot_artifact_root",
    }
)
_ATTESTATION_FINALIZE_FIELDS = frozenset()
_SUPPORTED_PHASES = frozenset(
    {
        "snapshot",
        "red-snapshot",
        "offline",
        "review-packet",
        "broker",
        "sign",
        "attested-judge",
    }
)
_FORBIDDEN_CALLER_FIELDS = frozenset(
    {
        "action",
        "argv",
        "descriptor",
        "external_kind",
        "invocation",
        "invocations",
        "payload",
        "prepared_payload",
    }
)
_PATH_TYPE = type(Path())
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_COMMIT_RE = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
_SNAPSHOT_IDENTITY_FIELDS = frozenset(
    {
        "commit_sha",
        "commit_tree_sha",
        "excluded_paths",
        "manifest_sha256",
        "snapshot_sha256",
    }
)
_SNAPSHOT_PAYLOAD_FIELDS = frozenset(
    {
        "base_snapshot",
        "candidate_snapshot",
        "phase",
        "policy",
        "policy_sha256",
        "request_sha256",
        "schema_version",
        "task_sha256",
    }
)
_RED_PAYLOAD_FIELDS = frozenset(
    {
        "base_snapshot",
        "candidate_snapshot",
        "phase",
        "red_snapshots",
        "request_sha256",
        "schema_version",
        "task_sha256",
    }
)
_RED_RECORD_FIELDS = frozenset(
    {
        "acceptance_test_id",
        "candidate_snapshot_sha256",
        "snapshot",
        "source_snapshot_sha256",
        "test_manifest_sha256",
        "test_patch_sha256",
        "test_paths",
    }
)


def _exact_inputs(
    value: object,
    expected: frozenset[str],
    *,
    phase: str,
    operation: str,
) -> dict[str, Any]:
    """Copy one plain mapping only when its complete field set is exact."""

    if type(value) is not dict:
        raise CoordinatorWorkflowOperationError(
            f"{phase} {operation} inputs must be one plain strict mapping"
        )
    fields = set(value)
    forbidden = fields & _FORBIDDEN_CALLER_FIELDS
    if forbidden:
        raise CoordinatorWorkflowOperationError(
            f"{phase} {operation} rejects caller-supplied descriptors"
        )
    if fields != expected:
        raise CoordinatorWorkflowOperationError(
            f"{phase} {operation} inputs have missing or unknown fields"
        )
    return dict(value)


def _request_for_supported_phase(request: object) -> PhaseRequest:
    if type(request) is not PhaseRequest:
        raise CoordinatorWorkflowOperationError("workflow request must be a strict PhaseRequest")
    if request.phase not in _SUPPORTED_PHASES:
        raise CoordinatorWorkflowOperationError(
            f"coordinator workflow phase is not implemented: {request.phase}"
        )
    return request


def _strict_path(value: object, *, label: str) -> Path:
    if type(value) is not _PATH_TYPE:
        raise CoordinatorWorkflowOperationError(f"{label} must be a concrete Path")
    return value


def _strict_bytes(value: object, *, label: str) -> bytes:
    if type(value) is not bytes or not value or len(value) > 6_000_000:
        raise CoordinatorWorkflowOperationError(f"{label} must be non-empty bytes")
    return value


def _strict_int(value: object, *, label: str, minimum: int, maximum: int) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise CoordinatorWorkflowOperationError(f"{label} is outside its strict range")
    return value


def _strict_text(value: object, *, label: str) -> str:
    if type(value) is not str or not value or "\x00" in value:
        raise CoordinatorWorkflowOperationError(f"{label} is invalid")
    try:
        encoded = value.encode("utf-8", errors="strict")
    except UnicodeError as exc:
        raise CoordinatorWorkflowOperationError(f"{label} is invalid") from exc
    if len(encoded) > 100_000:
        raise CoordinatorWorkflowOperationError(f"{label} is invalid")
    return value


def _strict_sha256(value: object, *, label: str) -> str:
    if type(value) is not str or _SHA256_RE.fullmatch(value) is None:
        raise CoordinatorWorkflowOperationError(f"{label} must be a lowercase SHA-256")
    return value


def _strict_payload(raw: bytes, *, label: str, fields: frozenset[str]) -> dict[str, Any]:
    if type(raw) is not bytes or not raw or len(raw) > 2_000_000:
        raise CoordinatorWorkflowOperationError(f"{label} is empty or oversized")

    def pairs(values: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in values:
            if key in result:
                raise CoordinatorWorkflowOperationError(f"{label} contains a duplicate field")
            result[key] = value
        return result

    def reject_constant(_value: str) -> object:
        raise CoordinatorWorkflowOperationError(f"{label} contains a non-finite number")

    try:
        value = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=pairs,
            parse_constant=reject_constant,
        )
    except CoordinatorWorkflowOperationError:
        raise
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise CoordinatorWorkflowOperationError(f"{label} is not strict JSON") from exc
    if type(value) is not dict or set(value) != fields:
        raise CoordinatorWorkflowOperationError(f"{label} has missing or unknown fields")
    if canonical_json_bytes(value) != raw:
        raise CoordinatorWorkflowOperationError(f"{label} is not canonical JSON")
    return value


def _protected_output_subdirectory(
    output_root: object,
    name: str,
    *,
    candidate_uid: int,
) -> Path:
    root = _strict_path(output_root, label=f"{name} output root")
    try:
        protected = assert_candidate_cannot_mutate(root, candidate_uid=candidate_uid)
    except PreflightError as exc:
        raise CoordinatorWorkflowOperationError(str(exc)) from exc
    if (
        not protected.is_dir()
        or protected.is_symlink()
        or stat.S_IMODE(os.lstat(protected).st_mode) & 0o077
        or any(protected.iterdir())
    ):
        raise CoordinatorWorkflowOperationError(
            f"{name} output root must be an empty private directory"
        )
    destination = protected / name
    try:
        destination.mkdir(mode=0o700)
    except OSError as exc:
        raise CoordinatorWorkflowOperationError(f"{name} output must be new") from exc
    return destination


def _snapshot_identity(snapshot: SnapshotEvidence) -> dict[str, object]:
    return {
        "commit_sha": snapshot.commit_sha,
        "commit_tree_sha": snapshot.commit_tree_sha,
        "excluded_paths": list(snapshot.excluded_paths),
        "manifest_sha256": snapshot.manifest_sha256,
        "snapshot_sha256": snapshot.snapshot_sha256,
    }


def _parsed_snapshot_identity(value: object, *, label: str) -> dict[str, object]:
    if type(value) is not dict or set(value) != _SNAPSHOT_IDENTITY_FIELDS:
        raise CoordinatorWorkflowOperationError(f"{label} identity has unknown fields")
    commit = value["commit_sha"]
    tree = value["commit_tree_sha"]
    excluded = value["excluded_paths"]
    if (
        type(commit) is not str
        or _COMMIT_RE.fullmatch(commit) is None
        or type(tree) is not str
        or _COMMIT_RE.fullmatch(tree) is None
        or type(excluded) is not list
        or any(type(item) is not str or not item for item in excluded)
        or excluded != sorted(set(excluded))
    ):
        raise CoordinatorWorkflowOperationError(f"{label} identity is invalid")
    return {
        "commit_sha": commit,
        "commit_tree_sha": tree,
        "excluded_paths": excluded,
        "manifest_sha256": _strict_sha256(
            value["manifest_sha256"], label=f"{label} manifest digest"
        ),
        "snapshot_sha256": _strict_sha256(
            value["snapshot_sha256"], label=f"{label} snapshot digest"
        ),
    }


def _verified_snapshot_store(
    root: object,
    *,
    category: str,
    identities: tuple[dict[str, object], ...],
    candidate_uid: int,
) -> dict[str, SnapshotEvidence]:
    store = _strict_path(root, label="snapshot artifact root")
    try:
        protected = assert_candidate_cannot_mutate_tree(store, candidate_uid=candidate_uid).root
    except PreflightError as exc:
        raise CoordinatorWorkflowOperationError(str(exc)) from exc
    directory = protected / category
    expected = {
        _strict_sha256(item["snapshot_sha256"], label="expected snapshot digest")
        for item in identities
    }
    try:
        entries = tuple(directory.iterdir())
    except OSError as exc:
        raise CoordinatorWorkflowOperationError(f"{category} store is unavailable") from exc
    actual = {
        item.name
        for item in entries
        if item.is_dir() and not item.is_symlink() and _SHA256_RE.fullmatch(item.name)
    }
    if not expected or actual != expected or len(entries) != len(actual):
        raise CoordinatorWorkflowOperationError(
            f"{category} physical set differs from the prepared payload"
        )
    measured: dict[str, SnapshotEvidence] = {}
    for identity in identities:
        digest = str(identity["snapshot_sha256"])
        try:
            snapshot = verify_readonly_snapshot(
                directory / digest,
                candidate_uid=candidate_uid,
            )
        except SnapshotError as exc:
            raise CoordinatorWorkflowOperationError(
                f"{category} snapshot failed immutable verification"
            ) from exc
        if _snapshot_identity(snapshot) != identity:
            raise CoordinatorWorkflowOperationError(
                f"{category} snapshot identity changed after prepare"
            )
        measured[digest] = snapshot
    return measured


def _task_v2(value: object) -> TaskSpec:
    if type(value) is not TaskSpec or value.schema_version != "2.0":
        raise CoordinatorWorkflowOperationError("workflow snapshot phases require TaskSpec v2")
    return value


def _phase_action(request: PhaseRequest, payload: bytes) -> bytes:
    action = PhaseAction.create(
        request=request,
        external_kind="none",
        payload_sha256=hashlib.sha256(payload).hexdigest(),
    )
    return prepare_transition_bytes(request, action, payload)


def _snapshot_policy(value: object, request: PhaseRequest) -> PolicyReport:
    try:
        policy = PolicyReport.model_validate(value)
    except (TypeError, ValueError) as exc:
        raise CoordinatorWorkflowOperationError("snapshot policy payload is invalid") from exc
    if policy.model_dump(mode="json") != value:
        raise CoordinatorWorkflowOperationError("snapshot policy payload is not strict")
    if (
        not policy.passed
        or policy.task_sha256 != request.task_sha256
        or policy.patch_sha256 != request.candidate_sha256
    ):
        raise CoordinatorWorkflowOperationError("snapshot policy does not match the request")
    return policy


def _prepare_snapshot(request: PhaseRequest, raw_inputs: object) -> bytes:
    inputs = _exact_inputs(
        raw_inputs,
        _SNAPSHOT_PREPARE_FIELDS,
        phase="snapshot",
        operation="prepare",
    )
    task = _task_v2(inputs["task"])
    candidate_uid = _strict_int(
        inputs["candidate_uid"],
        label="candidate uid",
        minimum=1,
        maximum=2**31 - 1,
    )
    candidate_repo = _strict_path(inputs["candidate_repo"], label="candidate repository")
    try:
        candidate = assert_candidate_cannot_mutate_tree(
            candidate_repo,
            candidate_uid=candidate_uid,
        ).root
        policy_before = inspect_git_diff(
            candidate,
            task,
            task_sha256=request.task_sha256,
            expected_patch_sha256=request.candidate_sha256,
        )
    except (PreflightError, GitInspectionError) as exc:
        raise CoordinatorWorkflowOperationError("snapshot policy inspection failed") from exc
    if not policy_before.passed or policy_before.patch_sha256 != request.candidate_sha256:
        raise CoordinatorWorkflowOperationError("candidate failed snapshot policy inspection")
    destination = _protected_output_subdirectory(
        inputs["output_root"],
        "snapshots",
        candidate_uid=candidate_uid,
    )
    try:
        base, candidate_snapshot = create_readonly_snapshot_pair_from_worktree(
            source_worktree=candidate,
            base_commit_sha=policy_before.base_sha,
            candidate_commit_sha=policy_before.head_sha,
            destination_root=destination,
            candidate_uid=candidate_uid,
        )
        policy_after = inspect_git_diff(
            candidate,
            task,
            task_sha256=request.task_sha256,
            expected_patch_sha256=request.candidate_sha256,
        )
    except (SnapshotError, GitInspectionError) as exc:
        raise CoordinatorWorkflowOperationError("snapshot construction failed") from exc
    if policy_after != policy_before or not policy_after.passed:
        raise CoordinatorWorkflowOperationError("candidate changed across snapshot construction")
    if (
        base.commit_sha != policy_after.base_sha
        or candidate_snapshot.commit_sha != policy_after.head_sha
        or base.snapshot_sha256 == candidate_snapshot.snapshot_sha256
    ):
        raise CoordinatorWorkflowOperationError("physical snapshots changed policy commit bindings")
    policy_raw = canonical_json_bytes(policy_after)
    payload = canonical_json_bytes(
        {
            "base_snapshot": _snapshot_identity(base),
            "candidate_snapshot": _snapshot_identity(candidate_snapshot),
            "phase": "snapshot",
            "policy": policy_after.model_dump(mode="json"),
            "policy_sha256": hashlib.sha256(policy_raw).hexdigest(),
            "request_sha256": request.request_sha256,
            "schema_version": "1.0",
            "task_sha256": request.task_sha256,
        }
    )
    return _phase_action(request, payload)


def _parsed_snapshot_payload(
    payload: bytes, request: PhaseRequest
) -> tuple[
    PolicyReport,
    dict[str, object],
    dict[str, object],
]:
    value = _strict_payload(
        payload,
        label="snapshot prepared payload",
        fields=_SNAPSHOT_PAYLOAD_FIELDS,
    )
    if (
        value["schema_version"] != "1.0"
        or value["phase"] != "snapshot"
        or value["request_sha256"] != request.request_sha256
        or value["task_sha256"] != request.task_sha256
    ):
        raise CoordinatorWorkflowOperationError("snapshot payload changed its request binding")
    policy = _snapshot_policy(value["policy"], request)
    policy_raw = canonical_json_bytes(policy)
    if not hmac.compare_digest(
        _strict_sha256(value["policy_sha256"], label="snapshot policy digest"),
        hashlib.sha256(policy_raw).hexdigest(),
    ):
        raise CoordinatorWorkflowOperationError("snapshot policy digest is invalid")
    base = _parsed_snapshot_identity(value["base_snapshot"], label="base snapshot")
    candidate = _parsed_snapshot_identity(value["candidate_snapshot"], label="candidate snapshot")
    if (
        base["commit_sha"] != policy.base_sha
        or candidate["commit_sha"] != policy.head_sha
        or base["snapshot_sha256"] == candidate["snapshot_sha256"]
    ):
        raise CoordinatorWorkflowOperationError("snapshot payload commit bindings are invalid")
    return policy, base, candidate


def _finalize_snapshot(
    request: PhaseRequest,
    action: PhaseAction,
    payload: bytes,
    execution_evidence: bytes,
    raw_inputs: object,
) -> bytes:
    inputs = _exact_inputs(
        raw_inputs,
        _SNAPSHOT_FINALIZE_FIELDS,
        phase="snapshot",
        operation="finalize",
    )
    if execution_evidence != payload:
        raise CoordinatorWorkflowOperationError(
            "snapshot finalize evidence differs from its prepared payload"
        )
    candidate_uid = _strict_int(
        inputs["candidate_uid"],
        label="candidate uid",
        minimum=1,
        maximum=2**31 - 1,
    )
    policy, base_identity, candidate_identity = _parsed_snapshot_payload(payload, request)
    measured = _verified_snapshot_store(
        inputs["snapshot_artifact_root"],
        category="snapshots",
        identities=(base_identity, candidate_identity),
        candidate_uid=candidate_uid,
    )
    base_digest = str(base_identity["snapshot_sha256"])
    candidate_digest = str(candidate_identity["snapshot_sha256"])
    if (
        measured[base_digest].commit_sha != policy.base_sha
        or measured[candidate_digest].commit_sha != policy.head_sha
    ):
        raise CoordinatorWorkflowOperationError("remeasured snapshots changed policy commits")
    output = CoordinatorPhaseOutput.create(
        request=request,
        artifacts=(
            PhaseOutputArtifact.create("base-snapshot", base_digest.encode("ascii")),
            PhaseOutputArtifact.create("candidate-snapshot", candidate_digest.encode("ascii")),
            PhaseOutputArtifact.create("policy", canonical_json_bytes(policy)),
        ),
    )
    return finalize_transition_bytes(request, action, payload, execution_evidence, output)


def _test_acceptances(task: TaskSpec) -> tuple[Any, ...]:
    tests = tuple(
        sorted(
            (item for item in task.acceptance_tests if item.kind == "test"),
            key=lambda item: item.id,
        )
    )
    if not tests or any(not item.test_paths for item in tests):
        raise CoordinatorWorkflowOperationError(
            "RED phase requires every TaskSpec test to declare exact test_paths"
        )
    return tests


def _red_record(acceptance_id: str, evidence: RedTddSnapshotEvidence) -> dict[str, object]:
    return {
        "acceptance_test_id": acceptance_id,
        "candidate_snapshot_sha256": evidence.candidate_snapshot_sha256,
        "snapshot": _snapshot_identity(evidence.snapshot),
        "source_snapshot_sha256": evidence.source_snapshot_sha256,
        "test_manifest_sha256": evidence.test_manifest_sha256,
        "test_patch_sha256": evidence.test_patch_sha256,
        "test_paths": list(evidence.test_paths),
    }


def _prepare_red_snapshot(request: PhaseRequest, raw_inputs: object) -> bytes:
    inputs = _exact_inputs(
        raw_inputs,
        _RED_PREPARE_FIELDS,
        phase="red-snapshot",
        operation="prepare",
    )
    task = _task_v2(inputs["task"])
    base = inputs["base_snapshot"]
    candidate = inputs["candidate_snapshot"]
    if type(base) is not SnapshotEvidence or type(candidate) is not SnapshotEvidence:
        raise CoordinatorWorkflowOperationError("RED source snapshot types are invalid")
    if (
        candidate.snapshot_sha256 != request.candidate_snapshot_sha256
        or base.commit_sha != task.base_sha
    ):
        raise CoordinatorWorkflowOperationError("RED sources differ from request or TaskSpec")
    candidate_uid = _strict_int(
        inputs["candidate_uid"],
        label="candidate uid",
        minimum=1,
        maximum=2**31 - 1,
    )
    try:
        base = verify_readonly_snapshot(base.root, candidate_uid=candidate_uid)
        candidate = verify_readonly_snapshot(candidate.root, candidate_uid=candidate_uid)
    except SnapshotError as exc:
        raise CoordinatorWorkflowOperationError("RED source snapshot verification failed") from exc
    destination = _protected_output_subdirectory(
        inputs["output_root"],
        "red-snapshots",
        candidate_uid=candidate_uid,
    )
    by_paths: dict[tuple[str, ...], RedTddSnapshotEvidence] = {}
    records: list[dict[str, object]] = []
    try:
        for acceptance in _test_acceptances(task):
            test_paths = tuple(acceptance.test_paths)
            evidence = by_paths.get(test_paths)
            if evidence is None:
                evidence = create_red_tdd_snapshot(
                    base_snapshot=base,
                    candidate_snapshot=candidate,
                    test_paths=test_paths,
                    destination_root=destination,
                    candidate_uid=candidate_uid,
                )
                by_paths[test_paths] = evidence
            records.append(_red_record(acceptance.id, evidence))
    except SnapshotError as exc:
        raise CoordinatorWorkflowOperationError("RED snapshot construction failed") from exc
    payload = canonical_json_bytes(
        {
            "base_snapshot": _snapshot_identity(base),
            "candidate_snapshot": _snapshot_identity(candidate),
            "phase": "red-snapshot",
            "red_snapshots": records,
            "request_sha256": request.request_sha256,
            "schema_version": "1.0",
            "task_sha256": request.task_sha256,
        }
    )
    return _phase_action(request, payload)


def _parsed_red_record(value: object) -> dict[str, object]:
    if type(value) is not dict or set(value) != _RED_RECORD_FIELDS:
        raise CoordinatorWorkflowOperationError("RED record has missing or unknown fields")
    acceptance_id = value["acceptance_test_id"]
    test_paths = value["test_paths"]
    if (
        type(acceptance_id) is not str
        or not acceptance_id
        or type(test_paths) is not list
        or not test_paths
        or any(type(path) is not str or not path for path in test_paths)
        or test_paths != sorted(set(test_paths))
    ):
        raise CoordinatorWorkflowOperationError("RED record identity or test paths are invalid")
    return {
        "acceptance_test_id": acceptance_id,
        "candidate_snapshot_sha256": _strict_sha256(
            value["candidate_snapshot_sha256"], label="RED candidate snapshot digest"
        ),
        "snapshot": _parsed_snapshot_identity(value["snapshot"], label="RED snapshot"),
        "source_snapshot_sha256": _strict_sha256(
            value["source_snapshot_sha256"], label="RED source snapshot digest"
        ),
        "test_manifest_sha256": _strict_sha256(
            value["test_manifest_sha256"], label="RED test manifest digest"
        ),
        "test_patch_sha256": _strict_sha256(
            value["test_patch_sha256"], label="RED test patch digest"
        ),
        "test_paths": test_paths,
    }


def _parsed_red_payload(
    payload: bytes,
    request: PhaseRequest,
    task: TaskSpec,
) -> tuple[dict[str, object], dict[str, object], tuple[dict[str, object], ...]]:
    value = _strict_payload(
        payload,
        label="RED prepared payload",
        fields=_RED_PAYLOAD_FIELDS,
    )
    if (
        value["schema_version"] != "1.0"
        or value["phase"] != "red-snapshot"
        or value["request_sha256"] != request.request_sha256
        or value["task_sha256"] != request.task_sha256
        or type(value["red_snapshots"]) is not list
    ):
        raise CoordinatorWorkflowOperationError("RED payload changed its request binding")
    base = _parsed_snapshot_identity(value["base_snapshot"], label="RED base snapshot")
    candidate = _parsed_snapshot_identity(
        value["candidate_snapshot"], label="RED candidate snapshot"
    )
    records = tuple(_parsed_red_record(item) for item in value["red_snapshots"])
    expected = {item.id: tuple(item.test_paths) for item in _test_acceptances(task)}
    actual_ids = tuple(str(item["acceptance_test_id"]) for item in records)
    if (
        actual_ids != tuple(sorted(expected))
        or any(
            tuple(item["test_paths"]) != expected[str(item["acceptance_test_id"])]
            for item in records
        )
        or base["commit_sha"] != task.base_sha
        or candidate["snapshot_sha256"] != request.candidate_snapshot_sha256
    ):
        raise CoordinatorWorkflowOperationError(
            "RED payload is incomplete or changes TaskSpec bindings"
        )
    return base, candidate, records


def _finalize_red_snapshot(
    request: PhaseRequest,
    action: PhaseAction,
    payload: bytes,
    execution_evidence: bytes,
    raw_inputs: object,
) -> bytes:
    inputs = _exact_inputs(
        raw_inputs,
        _RED_FINALIZE_FIELDS,
        phase="red-snapshot",
        operation="finalize",
    )
    if execution_evidence != payload:
        raise CoordinatorWorkflowOperationError(
            "RED finalize evidence differs from its prepared payload"
        )
    task = _task_v2(inputs["task"])
    candidate_uid = _strict_int(
        inputs["candidate_uid"],
        label="candidate uid",
        minimum=1,
        maximum=2**31 - 1,
    )
    base_identity, candidate_identity, records = _parsed_red_payload(payload, request, task)
    base_input = inputs["base_snapshot"]
    candidate_input = inputs["candidate_snapshot"]
    if type(base_input) is not SnapshotEvidence or type(candidate_input) is not SnapshotEvidence:
        raise CoordinatorWorkflowOperationError("RED finalize source types are invalid")
    try:
        base = verify_readonly_snapshot(base_input.root, candidate_uid=candidate_uid)
        candidate = verify_readonly_snapshot(candidate_input.root, candidate_uid=candidate_uid)
    except SnapshotError as exc:
        raise CoordinatorWorkflowOperationError("RED finalize source verification failed") from exc
    if (
        _snapshot_identity(base) != base_identity
        or _snapshot_identity(candidate) != candidate_identity
    ):
        raise CoordinatorWorkflowOperationError("RED finalize source identities changed")
    red_identities = tuple(item["snapshot"] for item in records)
    measured_store = _verified_snapshot_store(
        inputs["snapshot_artifact_root"],
        category="red-snapshots",
        identities=red_identities,  # type: ignore[arg-type]
        candidate_uid=candidate_uid,
    )
    artifacts: list[PhaseOutputArtifact] = []
    for record in records:
        identity = record["snapshot"]
        digest = str(identity["snapshot_sha256"])  # type: ignore[index]
        try:
            measured = measure_red_tdd_snapshot(
                red_root=measured_store[digest].root,
                base_snapshot=base,
                candidate_snapshot=candidate,
                test_paths=tuple(record["test_paths"]),  # type: ignore[arg-type]
                candidate_uid=candidate_uid,
            )
        except SnapshotError as exc:
            raise CoordinatorWorkflowOperationError("RED snapshot remeasurement failed") from exc
        if _red_record(str(record["acceptance_test_id"]), measured) != record:
            raise CoordinatorWorkflowOperationError("RED snapshot evidence changed after prepare")
        artifacts.append(
            PhaseOutputArtifact.create(
                "red-snapshot:" + str(record["acceptance_test_id"]),
                digest.encode("ascii"),
            )
        )
    output = CoordinatorPhaseOutput.create(
        request=request,
        artifacts=tuple(sorted(artifacts, key=lambda artifact: artifact.name)),
    )
    return finalize_transition_bytes(request, action, payload, execution_evidence, output)


def _prepare_offline(request: PhaseRequest, raw_inputs: object) -> bytes:
    inputs = _exact_inputs(
        raw_inputs,
        _OFFLINE_PREPARE_FIELDS,
        phase="offline",
        operation="prepare",
    )
    candidate = inputs["candidate_snapshot"]
    if type(candidate) is not SnapshotEvidence:
        raise CoordinatorWorkflowOperationError("offline candidate snapshot type is invalid")
    if type(inputs["task"]) is not TaskSpec:
        raise CoordinatorWorkflowOperationError("offline TaskSpec type is invalid")
    red = inputs["red_snapshots"]
    if type(red) is not dict or any(
        type(key) is not str or type(value) is not RedTddSnapshotEvidence
        for key, value in red.items()
    ):
        raise CoordinatorWorkflowOperationError("offline RED snapshot mapping is invalid")
    candidate_uid = _strict_int(
        inputs["candidate_uid"],
        label="candidate uid",
        minimum=1,
        maximum=2**31 - 1,
    )
    action, payload = prepare_offline_phase_action(
        request,
        task=inputs["task"],
        candidate_snapshot=candidate,
        red_snapshots=dict(red),
        artifact_root=_strict_path(inputs["artifact_root"], label="offline artifact root"),
        image=_strict_text(inputs["image"], label="offline image"),
        approved_image_digest=_strict_text(
            inputs["approved_image_digest"], label="offline image digest"
        ),
        candidate_uid=candidate_uid,
    )
    return prepare_transition_bytes(request, action, payload)


def _broker_invocations(
    request: PhaseRequest, inputs: Mapping[str, Any]
) -> tuple[IsolatedBrokerInvocation, IsolatedBrokerInvocation]:
    packet = inputs["packet"]
    if type(packet) is not ReviewPacket:
        raise CoordinatorWorkflowOperationError("broker packet type is invalid")
    if not hmac.compare_digest(packet.packet_sha256, request.review_packet_sha256 or ""):
        raise CoordinatorWorkflowOperationError("broker packet does not match the phase request")
    if not hmac.compare_digest(packet.task_sha256, request.task_sha256):
        raise CoordinatorWorkflowOperationError("broker packet task does not match the request")
    task = inputs["task"]
    if type(task) is not TaskSpec or task != packet.task:
        raise CoordinatorWorkflowOperationError("broker packet changed the verified TaskSpec")
    boundary = inputs["boundary_evidence"]
    if type(boundary) is not BrokerBoundaryEvidence:
        raise CoordinatorWorkflowOperationError("broker boundary evidence type is invalid")
    runtime = inputs["runtime"]
    if type(runtime) is not BrokerRuntimeBinding:
        raise CoordinatorWorkflowOperationError("broker runtime binding type is invalid")
    if runtime.name != "podman" or not runtime.rootless or not runtime.user_namespace:
        raise CoordinatorWorkflowOperationError(
            "broker workflow requires measured rootless Podman with a user namespace"
        )
    schema = _strict_path(inputs["output_schema"], label="broker output schema")
    cwd = _strict_path(inputs["trusted_cwd"], label="broker trusted cwd")
    image = _strict_text(inputs["image"], label="broker image")
    approved = _strict_text(inputs["approved_image_digest"], label="broker image digest")
    prompts = {
        "reviewer": _strict_text(inputs["reviewer_prompt"], label="reviewer prompt"),
        "adversary": _strict_text(inputs["adversary_prompt"], label="adversary prompt"),
    }
    adapter = CodexAdapter()
    invocations: list[IsolatedBrokerInvocation] = []
    roles: tuple[ReviewRole, ReviewRole] = ("reviewer", "adversary")
    for role in roles:
        inference_request = adapter.build_tool_free_responses_request(
            packet=packet,
            role=role,
            role_prompt=prompts[role],
            output_schema=schema,
            cwd=cwd,
            attempt=1,
        )
        invocations.append(
            adapter.build_isolated_broker_invocation(
                request=inference_request,
                packet=packet,
                boundary_evidence=boundary,
                container_runtime="podman",
                image=image,
                approved_image_digest=approved,
                allow_external_ai=True,
                allow_isolated_broker=True,
                runtime_rootless=runtime.rootless,
                runtime_user_namespace=runtime.user_namespace,
            )
        )
    return invocations[0], invocations[1]


def _prepare_broker(request: PhaseRequest, raw_inputs: object) -> bytes:
    inputs = _exact_inputs(
        raw_inputs,
        _BROKER_PREPARE_FIELDS,
        phase="broker",
        operation="prepare",
    )
    runtime = inputs["runtime"]
    if type(runtime) is not BrokerRuntimeBinding:
        raise CoordinatorWorkflowOperationError("broker runtime binding type is invalid")
    candidate_uid = _strict_int(
        inputs["candidate_uid"],
        label="candidate uid",
        minimum=1,
        maximum=2**31 - 1,
    )
    invocations = _broker_invocations(request, inputs)
    action, payload = prepare_broker_phase_action(
        request,
        invocations=invocations,
        runtime=runtime,
        gateway_image=_strict_text(inputs["gateway_image"], label="broker gateway image"),
        broker_gateway_image_digest=_strict_text(
            inputs["broker_gateway_image_digest"], label="broker gateway image digest"
        ),
        allowlist_policy=_strict_bytes(inputs["allowlist_policy"], label="broker allowlist policy"),
        broker_allowlist_policy_sha256=_strict_text(
            inputs["broker_allowlist_policy_sha256"],
            label="broker allowlist policy digest",
        ),
        pricing_policy=_strict_bytes(inputs["pricing_policy"], label="broker pricing policy"),
        broker_pricing_policy_sha256=_strict_text(
            inputs["broker_pricing_policy_sha256"], label="broker pricing policy digest"
        ),
        broker_ledger_identity_sha256=_strict_text(
            inputs["broker_ledger_identity_sha256"], label="broker ledger identity"
        ),
        broker_packet_reservation_limit=_strict_int(
            inputs["broker_packet_reservation_limit"],
            label="broker packet reservation limit",
            minimum=1,
            maximum=10_000_000,
        ),
        broker_packet_cost_limit_microusd=_strict_int(
            inputs["broker_packet_cost_limit_microusd"],
            label="broker packet cost limit",
            minimum=1,
            maximum=1_000_000_000,
        ),
        candidate_uid=candidate_uid,
    )
    return prepare_transition_bytes(request, action, payload)


def _prepare_review_packet(request: PhaseRequest, raw_inputs: object) -> bytes:
    inputs = _exact_inputs(
        raw_inputs,
        _REVIEW_PACKET_PREPARE_FIELDS,
        phase="review-packet",
        operation="prepare",
    )
    coordinator = inputs["coordinator"]
    if type(coordinator) is not CoordinatorRuntimeEvidence:
        raise CoordinatorWorkflowOperationError(
            "review-packet coordinator evidence type is invalid"
        )
    output, _packet = build_review_packet_phase_output(
        request,
        task=inputs["task"],
        policy=inputs["policy"],
        base_snapshot=inputs["base_snapshot"],
        candidate_snapshot=inputs["candidate_snapshot"],
        red_snapshots=inputs["red_snapshots"],
        raw_offline_runs=inputs["raw_offline_runs"],
        offline_runner_image=_strict_text(
            inputs["offline_runner_image"], label="review-packet offline image"
        ),
        coordinator=coordinator,
        candidate_uid=_strict_int(
            inputs["candidate_uid"],
            label="candidate uid",
            minimum=1,
            maximum=2**31 - 1,
        ),
    )
    return _phase_action(request, canonical_json_bytes(output))


def prepare_workflow_transition(request: PhaseRequest, *, inputs: object) -> bytes:
    """Derive one external phase action/payload and return its strict envelope.

    ``inputs`` must be one exact plain ``dict``.  Requiring an exact field set
    prevents an argparse/JSON caller from smuggling an action, descriptor, argv,
    invocation, or already-prepared payload across the coordinator boundary.
    """

    typed_request = _request_for_supported_phase(request)
    if typed_request.phase == "snapshot":
        return _prepare_snapshot(typed_request, inputs)
    if typed_request.phase == "red-snapshot":
        return _prepare_red_snapshot(typed_request, inputs)
    if typed_request.phase == "offline":
        return _prepare_offline(typed_request, inputs)
    if typed_request.phase == "review-packet":
        return _prepare_review_packet(typed_request, inputs)
    if typed_request.phase == "broker":
        return _prepare_broker(typed_request, inputs)
    if typed_request.phase == "sign":
        return _prepare_sign(typed_request, inputs)
    if typed_request.phase == "attested-judge":
        return _prepare_attested_judge(typed_request, inputs)
    raise CoordinatorWorkflowOperationError("workflow prepare dispatch is closed")


def _prepared_action_and_payload(
    request: PhaseRequest,
    prepared_transition: object,
) -> tuple[PhaseAction, bytes]:
    if type(prepared_transition) is not bytes or not prepared_transition:
        raise CoordinatorWorkflowOperationError("prepared transition must be non-empty bytes")
    try:
        parsed = parse_prepared_transition(
            prepared_transition,
            request=request.model_dump(mode="json"),
        )
        action = PhaseAction.model_validate(parsed.action)
    except (TypeError, ValueError) as exc:
        raise CoordinatorWorkflowOperationError("prepared transition is invalid") from exc
    action.validate_for(request, parsed.payload)
    return action, parsed.payload


def _typed_output(raw: bytes, request: PhaseRequest) -> CoordinatorPhaseOutput:
    try:
        output = CoordinatorPhaseOutput.model_validate_json(raw)
    except (TypeError, ValueError) as exc:
        raise CoordinatorWorkflowOperationError("phase finalizer returned invalid output") from exc
    output.validate_for(request)
    if canonical_json_bytes(output) != raw:
        raise CoordinatorWorkflowOperationError("phase finalizer output is not canonical")
    return output


def _finalize_offline(
    request: PhaseRequest,
    action: PhaseAction,
    payload: bytes,
    execution_evidence: bytes,
    raw_inputs: object,
) -> bytes:
    inputs = _exact_inputs(
        raw_inputs,
        _OFFLINE_FINALIZE_FIELDS,
        phase="offline",
        operation="finalize",
    )
    output = _typed_output(
        finalize_offline_phase_output(
            request,
            action,
            payload,
            execution_evidence,
            artifact_root=_strict_path(inputs["artifact_root"], label="offline artifact root"),
            candidate_uid=_strict_int(
                inputs["candidate_uid"],
                label="candidate uid",
                minimum=1,
                maximum=2**31 - 1,
            ),
        ),
        request,
    )
    return finalize_transition_bytes(request, action, payload, execution_evidence, output)


def _finalize_broker(
    request: PhaseRequest,
    action: PhaseAction,
    payload: bytes,
    execution_evidence: bytes,
    raw_inputs: object,
) -> bytes:
    inputs = _exact_inputs(
        raw_inputs,
        _BROKER_FINALIZE_FIELDS,
        phase="broker",
        operation="finalize",
    )
    output = _typed_output(
        finalize_broker_phase_output(
            request,
            action,
            payload,
            execution_evidence,
            allowlist_policy=_strict_bytes(
                inputs["allowlist_policy"], label="broker allowlist policy"
            ),
            pricing_policy=_strict_bytes(inputs["pricing_policy"], label="broker pricing policy"),
        ),
        request,
    )
    return finalize_transition_bytes(request, action, payload, execution_evidence, output)


def _finalize_review_packet(
    request: PhaseRequest,
    action: PhaseAction,
    payload: bytes,
    execution_evidence: bytes,
    raw_inputs: object,
) -> bytes:
    _exact_inputs(
        raw_inputs,
        _REVIEW_PACKET_FINALIZE_FIELDS,
        phase="review-packet",
        operation="finalize",
    )
    if execution_evidence != payload:
        raise CoordinatorWorkflowOperationError(
            "review-packet finalize evidence differs from its prepared payload"
        )
    output = _typed_output(payload, request)
    return finalize_transition_bytes(request, action, payload, execution_evidence, output)


def _attestation_inputs(
    request: PhaseRequest,
    raw_inputs: object,
    *,
    operation: str,
) -> tuple[dict[str, Any], Any, int]:
    inputs = _exact_inputs(
        raw_inputs,
        _ATTESTATION_PREPARE_FIELDS,
        phase=request.phase,
        operation=operation,
    )
    candidate_uid = _strict_int(
        inputs["candidate_uid"],
        label="candidate uid",
        minimum=1,
        maximum=2**31 - 1,
    )
    coordinator = inputs["coordinator"]
    if type(coordinator) is not CoordinatorRuntimeEvidence:
        raise CoordinatorWorkflowOperationError("coordinator evidence type is invalid")
    try:
        bundle = reconstruct_attestation_inputs(
            request,
            artifact_root=_strict_path(inputs["artifact_root"], label="artifact root"),
            snapshot_artifact_root=_strict_path(
                inputs["snapshot_artifact_root"], label="snapshot artifact root"
            ),
            runtime_root=_strict_path(inputs["runtime_root"], label="runtime root"),
            coordinator=coordinator,
            candidate_uid=candidate_uid,
        )
    except PhaseProtocolError as exc:
        raise CoordinatorWorkflowOperationError(
            "frozen attestation bundle reconstruction failed"
        ) from exc
    return inputs, bundle, candidate_uid


def _prepare_sign(request: PhaseRequest, raw_inputs: object) -> bytes:
    inputs, bundle, candidate_uid = _attestation_inputs(
        request,
        raw_inputs,
        operation="prepare",
    )
    signing_key = inputs["signing_key"]
    if type(signing_key) is not _PATH_TYPE or inputs["nonce_ledger"] is not None:
        raise CoordinatorWorkflowOperationError(
            "sign prepare requires only its protected private key"
        )
    try:
        private_key = load_coordinator_private_key(
            signing_key,
            candidate_root=_strict_path(inputs["artifact_root"], label="artifact root"),
            candidate_uid=candidate_uid,
        )
        if not hmac.compare_digest(
            public_key_id(private_key.public_key()), request.coordinator_key_id
        ):
            raise CoordinatorWorkflowOperationError(
                "private signing key differs from the workflow coordinator key"
            )
        expectations = build_frozen_bundle_expectations(bundle)
        issued_at = int(time.time())
        artifacts = tuple(
            sorted(
                (
                    PhaseOutputArtifact.create(
                        role,
                        canonical_json_bytes(
                            sign_attestation(
                                AttestationStatement(
                                    **expectation.model_dump(),
                                    nonce=secrets.token_hex(32),
                                    issued_at=issued_at,
                                ),
                                private_key,
                            )
                        ),
                    )
                    for role, expectation in expectations.items()
                ),
                key=lambda artifact: artifact.name,
            )
        )
        output = CoordinatorPhaseOutput.create(request=request, artifacts=artifacts)
    except (TypeError, ValueError) as exc:
        raise CoordinatorWorkflowOperationError("frozen attestation signing failed") from exc
    return _phase_action(request, canonical_json_bytes(output))


def _prepare_attested_judge(request: PhaseRequest, raw_inputs: object) -> bytes:
    inputs, bundle, candidate_uid = _attestation_inputs(
        request,
        raw_inputs,
        operation="prepare",
    )
    nonce_path = inputs["nonce_ledger"]
    if type(nonce_path) is not _PATH_TYPE or inputs["signing_key"] is not None:
        raise CoordinatorWorkflowOperationError(
            "attested-judge prepare requires only its nonce ledger"
        )
    runtime_root = _strict_path(inputs["runtime_root"], label="runtime root")
    coordinator = inputs["coordinator"]
    try:
        public_key = load_trusted_public_key(
            runtime_root / "coordinator-public-key.pem",
            expected_sha256=coordinator.coordinator_public_key_sha256,
            candidate_uid=candidate_uid,
        )
        attestations = reconstruct_signed_attestations(
            request,
            artifact_root=_strict_path(inputs["artifact_root"], label="artifact root"),
            candidate_uid=candidate_uid,
        )
        verdict = judge_frozen_attestation_bundle(
            bundle,
            attestations,
            trusted_public_keys={request.coordinator_key_id: public_key},
            nonce_ledger=SqliteNonceLedger(nonce_path),
        )
        output = CoordinatorPhaseOutput.create(
            request=request,
            artifacts=(PhaseOutputArtifact.create("verdict", canonical_json_bytes(verdict)),),
        )
    except (TypeError, ValueError) as exc:
        raise CoordinatorWorkflowOperationError("frozen attested judgment failed") from exc
    return _phase_action(request, canonical_json_bytes(output))


def _finalize_internal_attestation(
    request: PhaseRequest,
    action: PhaseAction,
    payload: bytes,
    execution_evidence: bytes,
    raw_inputs: object,
) -> bytes:
    _exact_inputs(
        raw_inputs,
        _ATTESTATION_FINALIZE_FIELDS,
        phase=request.phase,
        operation="finalize",
    )
    if execution_evidence != payload:
        raise CoordinatorWorkflowOperationError(
            f"{request.phase} finalize evidence differs from its prepared payload"
        )
    output = _typed_output(payload, request)
    return finalize_transition_bytes(request, action, payload, execution_evidence, output)


def finalize_workflow_transition(
    request: PhaseRequest,
    *,
    prepared_transition: bytes,
    execution_evidence: bytes,
    inputs: object,
) -> bytes:
    """Reverify raw outer evidence and return a strict finalized transition.

    The action and payload are recovered exclusively from the canonical
    coordinator-prepared envelope.  A caller has no parameter through which it
    can replace either value during finalize.
    """

    typed_request = _request_for_supported_phase(request)
    if type(execution_evidence) is not bytes or not execution_evidence:
        raise CoordinatorWorkflowOperationError("execution evidence must be non-empty bytes")
    action, payload = _prepared_action_and_payload(typed_request, prepared_transition)
    if typed_request.phase == "snapshot":
        return _finalize_snapshot(
            typed_request,
            action,
            payload,
            execution_evidence,
            inputs,
        )
    if typed_request.phase == "red-snapshot":
        return _finalize_red_snapshot(
            typed_request,
            action,
            payload,
            execution_evidence,
            inputs,
        )
    if typed_request.phase == "offline":
        return _finalize_offline(
            typed_request,
            action,
            payload,
            execution_evidence,
            inputs,
        )
    if typed_request.phase == "review-packet":
        return _finalize_review_packet(
            typed_request,
            action,
            payload,
            execution_evidence,
            inputs,
        )
    if typed_request.phase == "broker":
        return _finalize_broker(
            typed_request,
            action,
            payload,
            execution_evidence,
            inputs,
        )
    if typed_request.phase in {"sign", "attested-judge"}:
        return _finalize_internal_attestation(
            typed_request,
            action,
            payload,
            execution_evidence,
            inputs,
        )
    raise CoordinatorWorkflowOperationError("workflow finalize dispatch is closed")
