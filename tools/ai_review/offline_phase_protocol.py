"""Canonical three-stage protocol for offline acceptance execution.

This module deliberately uses only the Python standard library and other
stdlib-only harness modules.  The pinned coordinator prepares and finalizes the
typed batch; the root-owned outer process may parse and serialize it without
loading Pydantic, cryptography, or candidate code into the host interpreter.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
from collections.abc import Mapping
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from pathlib import PurePosixPath
from typing import Any

from tools.ai_review.offline_runner import OfflineRunEvidence
from tools.ai_review.offline_runner import OfflineRunnerError
from tools.ai_review.offline_runner import RunRequest
from tools.ai_review.offline_runner import validate_offline_run_evidence
from tools.ai_review.snapshot import RedTddSnapshotEvidence
from tools.ai_review.snapshot import SnapshotEvidence
from tools.ai_review.snapshot import verify_readonly_snapshot


_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_IMAGE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/:+-]*@(sha256:[0-9a-f]{64})$")
_ID_RE = re.compile(r"^[A-Z][A-Z0-9_-]{0,63}$")
_SESSION_RE = re.compile(r"^ai-review-[0-9a-f]{24}$")
_PREPARED_DOMAIN = b"amazon-explorer-prepared-offline-batch-v1\0"
_OUTER_DOMAIN = b"amazon-explorer-outer-offline-evidence-v1\0"
_MAX_PREPARED_BYTES = 2_000_000
_MAX_EVIDENCE_BYTES = 6_000_000
_MAX_RUNS = 300


class OfflinePhaseProtocolError(RuntimeError):
    """Raised when an offline phase hand-off is incomplete or non-canonical."""


def _canonical_json(value: object) -> bytes:
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
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise OfflinePhaseProtocolError("offline phase value is not canonical JSON") from exc


def _domain_sha256(domain: bytes, value: object) -> str:
    return hashlib.sha256(domain + _canonical_json(value)).hexdigest()


def _strict_json(raw: bytes, *, label: str, maximum: int) -> object:
    if not isinstance(raw, bytes) or not raw or len(raw) > maximum:
        raise OfflinePhaseProtocolError(f"{label} is empty or exceeds its byte limit")

    def pairs(values: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in values:
            if key in result:
                raise OfflinePhaseProtocolError(f"{label} contains a duplicate field")
            result[key] = value
        return result

    def reject_constant(_value: str) -> object:
        raise OfflinePhaseProtocolError(f"{label} contains a non-finite number")

    try:
        value = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=pairs,
            parse_constant=reject_constant,
        )
    except OfflinePhaseProtocolError:
        raise
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise OfflinePhaseProtocolError(f"{label} is invalid JSON") from exc
    if _canonical_json(value) != raw:
        raise OfflinePhaseProtocolError(f"{label} is not canonically encoded")
    return value


def _exact_dict(value: object, fields: set[str], *, label: str) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != fields:
        raise OfflinePhaseProtocolError(f"{label} has missing or unknown fields")
    return value


def _string(value: object, *, label: str, maximum: int = 4096) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value.encode("utf-8")) > maximum
        or "\x00" in value
    ):
        raise OfflinePhaseProtocolError(f"{label} is invalid")
    return value


def _sha256(value: object, *, label: str) -> str:
    text = _string(value, label=label, maximum=64)
    if _SHA256_RE.fullmatch(text) is None:
        raise OfflinePhaseProtocolError(f"{label} is not a lowercase SHA-256")
    return text


def _optional_sha256(value: object, *, label: str) -> str | None:
    return None if value is None else _sha256(value, label=label)


def _strict_int(value: object, *, label: str, minimum: int, maximum: int) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise OfflinePhaseProtocolError(f"{label} is outside its strict integer range")
    return value


def _strict_bool(value: object, *, label: str) -> bool:
    if type(value) is not bool:
        raise OfflinePhaseProtocolError(f"{label} must be a boolean")
    return value


def _strings(
    value: object,
    *,
    label: str,
    minimum: int = 1,
    maximum: int = 256,
) -> tuple[str, ...]:
    if not isinstance(value, list) or not minimum <= len(value) <= maximum:
        raise OfflinePhaseProtocolError(f"{label} has an invalid item count")
    return tuple(_string(item, label=label) for item in value)


def _snapshot_ref(value: object) -> str:
    text = _string(value, label="offline snapshot reference")
    path = PurePosixPath(text)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise OfflinePhaseProtocolError("offline snapshot reference must be a safe relative path")
    return text


def _resolve_snapshot(root: Path, reference: str, *, candidate_uid: int) -> SnapshotEvidence:
    try:
        protected_root = Path(os.path.abspath(root)).resolve(strict=True)
        target = protected_root.joinpath(*PurePosixPath(reference).parts).resolve(strict=True)
    except OSError as exc:
        raise OfflinePhaseProtocolError("offline snapshot reference is unavailable") from exc
    if not target.is_relative_to(protected_root):
        raise OfflinePhaseProtocolError("offline snapshot reference escaped the artifact root")
    try:
        return verify_readonly_snapshot(target, candidate_uid=candidate_uid)
    except Exception as exc:
        raise OfflinePhaseProtocolError("offline snapshot reference is not verified") from exc


def _relative_snapshot(root: Path, snapshot: SnapshotEvidence) -> str:
    try:
        artifact_root = Path(os.path.abspath(root)).resolve(strict=True)
        snapshot_root = snapshot.root.resolve(strict=True)
        relative = snapshot_root.relative_to(artifact_root).as_posix()
    except (OSError, ValueError) as exc:
        raise OfflinePhaseProtocolError("offline snapshot is outside the artifact input") from exc
    return _snapshot_ref(relative)


@dataclass(frozen=True)
class PreparedOfflineRun:
    ordinal: int
    phase: str
    acceptance_test_id: str
    snapshot_ref: str
    execution_snapshot_sha256: str
    source_snapshot_sha256: str
    candidate_snapshot_sha256: str
    test_patch_sha256: str | None
    test_manifest_sha256: str | None
    command: tuple[str, ...]
    session_id: str

    def as_dict(self) -> dict[str, object]:
        return {
            "acceptance_test_id": self.acceptance_test_id,
            "candidate_snapshot_sha256": self.candidate_snapshot_sha256,
            "command": list(self.command),
            "execution_snapshot_sha256": self.execution_snapshot_sha256,
            "ordinal": self.ordinal,
            "phase": self.phase,
            "session_id": self.session_id,
            "snapshot_ref": self.snapshot_ref,
            "source_snapshot_sha256": self.source_snapshot_sha256,
            "test_manifest_sha256": self.test_manifest_sha256,
            "test_patch_sha256": self.test_patch_sha256,
        }


@dataclass(frozen=True)
class PreparedOfflineBatch:
    schema_version: str
    workflow_id: str
    request_sha256: str
    task_sha256: str
    candidate_sha256: str
    candidate_snapshot_sha256: str
    image: str
    approved_image_digest: str
    timeout_seconds: int
    max_log_bytes: int
    runs: tuple[PreparedOfflineRun, ...]
    batch_sha256: str

    def body(self) -> dict[str, object]:
        return {
            "approved_image_digest": self.approved_image_digest,
            "candidate_sha256": self.candidate_sha256,
            "candidate_snapshot_sha256": self.candidate_snapshot_sha256,
            "image": self.image,
            "max_log_bytes": self.max_log_bytes,
            "request_sha256": self.request_sha256,
            "runs": [run.as_dict() for run in self.runs],
            "schema_version": self.schema_version,
            "task_sha256": self.task_sha256,
            "timeout_seconds": self.timeout_seconds,
            "workflow_id": self.workflow_id,
        }

    def as_dict(self) -> dict[str, object]:
        return {**self.body(), "batch_sha256": self.batch_sha256}

    def canonical_bytes(self) -> bytes:
        return _canonical_json(self.as_dict())


def _prepared_run_from_dict(value: object) -> PreparedOfflineRun:
    payload = _exact_dict(
        value,
        {
            "acceptance_test_id",
            "candidate_snapshot_sha256",
            "command",
            "execution_snapshot_sha256",
            "ordinal",
            "phase",
            "session_id",
            "snapshot_ref",
            "source_snapshot_sha256",
            "test_manifest_sha256",
            "test_patch_sha256",
        },
        label="prepared offline run",
    )
    phase = _string(payload["phase"], label="offline run phase", maximum=5)
    if phase not in {"gate", "red", "green"}:
        raise OfflinePhaseProtocolError("prepared offline run phase is invalid")
    acceptance_id = _string(payload["acceptance_test_id"], label="acceptance test id", maximum=64)
    if _ID_RE.fullmatch(acceptance_id) is None:
        raise OfflinePhaseProtocolError("prepared acceptance test id is invalid")
    session_id = _string(payload["session_id"], label="offline session id", maximum=34)
    if _SESSION_RE.fullmatch(session_id) is None:
        raise OfflinePhaseProtocolError("prepared offline session id is invalid")
    patch = _optional_sha256(payload["test_patch_sha256"], label="test patch SHA-256")
    manifest = _optional_sha256(payload["test_manifest_sha256"], label="test manifest SHA-256")
    if (phase == "gate" and (patch is not None or manifest is not None)) or (
        phase != "gate" and (patch is None or manifest is None)
    ):
        raise OfflinePhaseProtocolError("prepared offline TDD binding is invalid")
    return PreparedOfflineRun(
        ordinal=_strict_int(payload["ordinal"], label="offline ordinal", minimum=0, maximum=299),
        phase=phase,
        acceptance_test_id=acceptance_id,
        snapshot_ref=_snapshot_ref(payload["snapshot_ref"]),
        execution_snapshot_sha256=_sha256(
            payload["execution_snapshot_sha256"], label="execution snapshot SHA-256"
        ),
        source_snapshot_sha256=_sha256(
            payload["source_snapshot_sha256"], label="source snapshot SHA-256"
        ),
        candidate_snapshot_sha256=_sha256(
            payload["candidate_snapshot_sha256"], label="candidate snapshot SHA-256"
        ),
        test_patch_sha256=patch,
        test_manifest_sha256=manifest,
        command=_strings(payload["command"], label="offline command"),
        session_id=session_id,
    )


def parse_prepared_offline_batch(raw: bytes) -> PreparedOfflineBatch:
    value = _strict_json(raw, label="prepared offline batch", maximum=_MAX_PREPARED_BYTES)
    payload = _exact_dict(
        value,
        {
            "approved_image_digest",
            "batch_sha256",
            "candidate_sha256",
            "candidate_snapshot_sha256",
            "image",
            "max_log_bytes",
            "request_sha256",
            "runs",
            "schema_version",
            "task_sha256",
            "timeout_seconds",
            "workflow_id",
        },
        label="prepared offline batch",
    )
    if payload["schema_version"] != "1.0":
        raise OfflinePhaseProtocolError("prepared offline schema version is invalid")
    image = _string(payload["image"], label="offline image")
    approved = _string(payload["approved_image_digest"], label="offline image digest", maximum=71)
    match = _IMAGE_RE.fullmatch(image)
    if match is None or match.group(1) != approved:
        raise OfflinePhaseProtocolError("prepared offline image is not manifest-pinned")
    raw_runs = payload["runs"]
    if not isinstance(raw_runs, list) or not 1 <= len(raw_runs) <= _MAX_RUNS:
        raise OfflinePhaseProtocolError("prepared offline batch has an invalid run count")
    runs = tuple(_prepared_run_from_dict(run) for run in raw_runs)
    if tuple(run.ordinal for run in runs) != tuple(range(len(runs))):
        raise OfflinePhaseProtocolError("prepared offline run order is invalid")
    keys = tuple((run.phase, run.acceptance_test_id) for run in runs)
    if len(keys) != len(set(keys)):
        raise OfflinePhaseProtocolError("prepared offline run keys must be unique")
    phases = tuple(run.phase for run in runs)
    phase_rank = {"gate": 0, "red": 1, "green": 2}
    if tuple(phase_rank[item] for item in phases) != tuple(
        sorted(phase_rank[item] for item in phases)
    ):
        raise OfflinePhaseProtocolError("prepared offline batch must order gate, RED, then GREEN")
    gates = {run.acceptance_test_id for run in runs if run.phase == "gate"}
    red = {run.acceptance_test_id for run in runs if run.phase == "red"}
    green = {run.acceptance_test_id for run in runs if run.phase == "green"}
    if not gates or not red or red != green or not red <= gates:
        raise OfflinePhaseProtocolError(
            "prepared offline batch requires all gates and paired RED/GREEN runs"
        )
    batch = PreparedOfflineBatch(
        schema_version="1.0",
        workflow_id=_sha256(payload["workflow_id"], label="workflow id"),
        request_sha256=_sha256(payload["request_sha256"], label="phase request SHA-256"),
        task_sha256=_sha256(payload["task_sha256"], label="task SHA-256"),
        candidate_sha256=_sha256(payload["candidate_sha256"], label="candidate SHA-256"),
        candidate_snapshot_sha256=_sha256(
            payload["candidate_snapshot_sha256"], label="candidate snapshot SHA-256"
        ),
        image=image,
        approved_image_digest=approved,
        timeout_seconds=_strict_int(
            payload["timeout_seconds"], label="offline timeout", minimum=1, maximum=3600
        ),
        max_log_bytes=_strict_int(
            payload["max_log_bytes"],
            label="offline log limit",
            minimum=1024,
            maximum=1_000_000,
        ),
        runs=runs,
        batch_sha256=_sha256(payload["batch_sha256"], label="prepared batch SHA-256"),
    )
    measured = _domain_sha256(_PREPARED_DOMAIN, batch.body())
    if not hmac.compare_digest(measured, batch.batch_sha256):
        raise OfflinePhaseProtocolError("prepared offline batch digest is invalid")
    if batch.candidate_snapshot_sha256 != next(
        (run.candidate_snapshot_sha256 for run in runs), ""
    ) or any(run.candidate_snapshot_sha256 != batch.candidate_snapshot_sha256 for run in runs):
        raise OfflinePhaseProtocolError("prepared offline candidate snapshot binding changed")
    return batch


def canonical_prepared_offline_batch_bytes(batch: PreparedOfflineBatch) -> bytes:
    raw = batch.canonical_bytes()
    if parse_prepared_offline_batch(raw) != batch:
        raise OfflinePhaseProtocolError("prepared offline batch object is invalid")
    return raw


def _session_id(workflow_id: str, request_sha256: str, phase: str, acceptance_id: str) -> str:
    digest = hashlib.sha256(
        b"amazon-explorer-offline-session-v1\0"
        + workflow_id.encode("ascii")
        + request_sha256.encode("ascii")
        + phase.encode("ascii")
        + acceptance_id.encode("ascii")
    ).hexdigest()
    return "ai-review-" + digest[:24]


def prepare_offline_batch(
    *,
    workflow_id: str,
    request_sha256: str,
    task: Any,
    task_sha256: str,
    candidate_sha256: str,
    candidate_snapshot: SnapshotEvidence,
    red_snapshots: Mapping[str, RedTddSnapshotEvidence],
    artifact_root: Path,
    image: str,
    approved_image_digest: str,
    candidate_uid: int,
    timeout_seconds: int = 900,
    max_log_bytes: int = 1_000_000,
) -> PreparedOfflineBatch:
    """Derive the complete gate/RED/GREEN batch inside the coordinator."""

    candidate = verify_readonly_snapshot(candidate_snapshot.root, candidate_uid=candidate_uid)
    if candidate != candidate_snapshot:
        raise OfflinePhaseProtocolError("candidate snapshot changed before offline prepare")
    candidate_ref = _relative_snapshot(artifact_root, candidate)
    acceptances = tuple(getattr(task, "acceptance_tests", ()))
    if not acceptances or len(acceptances) > 100:
        raise OfflinePhaseProtocolError("TaskSpec has no bounded acceptance test set")
    ids = tuple(getattr(item, "id", None) for item in acceptances)
    if any(not isinstance(item, str) or _ID_RE.fullmatch(item) is None for item in ids) or len(
        ids
    ) != len(set(ids)):
        raise OfflinePhaseProtocolError("TaskSpec acceptance ids are invalid")
    expected_red_ids = {item.id for item in acceptances if getattr(item, "kind", None) == "test"}
    if set(red_snapshots) != expected_red_ids:
        raise OfflinePhaseProtocolError("RED snapshots do not exactly cover test acceptances")
    red_values: dict[str, tuple[RedTddSnapshotEvidence, str]] = {}
    for acceptance_id, raw_red in red_snapshots.items():
        if not isinstance(raw_red, RedTddSnapshotEvidence):
            raise OfflinePhaseProtocolError("RED snapshot evidence type is invalid")
        measured = _resolve_snapshot(
            artifact_root,
            _relative_snapshot(artifact_root, raw_red.snapshot),
            candidate_uid=candidate_uid,
        )
        if measured != raw_red.snapshot or raw_red.candidate_snapshot_sha256 != (
            candidate.snapshot_sha256
        ):
            raise OfflinePhaseProtocolError("RED snapshot binding changed before offline prepare")
        acceptance = next(item for item in acceptances if item.id == acceptance_id)
        if raw_red.phase != "red" or raw_red.test_paths != tuple(acceptance.test_paths):
            raise OfflinePhaseProtocolError("RED snapshot test-path binding changed")
        red_values[acceptance_id] = (raw_red, _relative_snapshot(artifact_root, measured))

    definitions: list[tuple[str, Any]] = []
    definitions.extend(("gate", acceptance) for acceptance in acceptances)
    definitions.extend(
        ("red", acceptance) for acceptance in acceptances if acceptance.id in expected_red_ids
    )
    definitions.extend(
        ("green", acceptance) for acceptance in acceptances if acceptance.id in expected_red_ids
    )
    runs: list[PreparedOfflineRun] = []
    for ordinal, (phase, acceptance) in enumerate(definitions):
        command = tuple(getattr(acceptance, "command", ()))
        if not command or any(not isinstance(value, str) or not value for value in command):
            raise OfflinePhaseProtocolError("TaskSpec acceptance command is invalid")
        if phase == "red":
            red, reference = red_values[acceptance.id]
            execution_sha = red.snapshot.snapshot_sha256
            source_sha = red.source_snapshot_sha256
            patch_sha = red.test_patch_sha256
            manifest_sha = red.test_manifest_sha256
        else:
            reference = candidate_ref
            execution_sha = candidate.snapshot_sha256
            source_sha = candidate.snapshot_sha256
            if phase == "green":
                red, _reference = red_values[acceptance.id]
                patch_sha = red.test_patch_sha256
                manifest_sha = red.test_manifest_sha256
            else:
                patch_sha = None
                manifest_sha = None
        runs.append(
            PreparedOfflineRun(
                ordinal=ordinal,
                phase=phase,
                acceptance_test_id=acceptance.id,
                snapshot_ref=reference,
                execution_snapshot_sha256=execution_sha,
                source_snapshot_sha256=source_sha,
                candidate_snapshot_sha256=candidate.snapshot_sha256,
                test_patch_sha256=patch_sha,
                test_manifest_sha256=manifest_sha,
                command=command,
                session_id=_session_id(workflow_id, request_sha256, phase, acceptance.id),
            )
        )
    body = {
        "approved_image_digest": approved_image_digest,
        "candidate_sha256": candidate_sha256,
        "candidate_snapshot_sha256": candidate.snapshot_sha256,
        "image": image,
        "max_log_bytes": max_log_bytes,
        "request_sha256": request_sha256,
        "runs": [run.as_dict() for run in runs],
        "schema_version": "1.0",
        "task_sha256": task_sha256,
        "timeout_seconds": timeout_seconds,
        "workflow_id": workflow_id,
    }
    batch = PreparedOfflineBatch(
        schema_version="1.0",
        workflow_id=workflow_id,
        request_sha256=request_sha256,
        task_sha256=task_sha256,
        candidate_sha256=candidate_sha256,
        candidate_snapshot_sha256=candidate.snapshot_sha256,
        image=image,
        approved_image_digest=approved_image_digest,
        timeout_seconds=timeout_seconds,
        max_log_bytes=max_log_bytes,
        runs=tuple(runs),
        batch_sha256=_domain_sha256(_PREPARED_DOMAIN, body),
    )
    return parse_prepared_offline_batch(batch.canonical_bytes())


def _run_request_dict(request: RunRequest) -> dict[str, object]:
    return {
        "acceptance_test_id": request.acceptance_test_id,
        "candidate_sha256": request.candidate_sha256,
        "candidate_snapshot_sha256": request.candidate_snapshot_sha256,
        "command": list(request.command),
        "execution_snapshot_sha256": request.execution_snapshot_sha256,
        "phase": request.phase,
        "runner_image_digest": request.runner_image_digest,
        "session_id": request.session_id,
        "source_commit_sha": request.source_commit_sha,
        "source_commit_tree_sha": request.source_commit_tree_sha,
        "source_snapshot_sha256": request.source_snapshot_sha256,
        "task_sha256": request.task_sha256,
        "test_manifest_sha256": request.test_manifest_sha256,
        "test_patch_sha256": request.test_patch_sha256,
    }


def offline_evidence_dict(evidence: OfflineRunEvidence) -> dict[str, object]:
    if not isinstance(evidence, OfflineRunEvidence):
        raise OfflinePhaseProtocolError("offline evidence type is invalid")
    return {
        "argv": list(evidence.argv),
        "argv_sha256": evidence.argv_sha256,
        "cleanup_succeeded": evidence.cleanup_succeeded,
        "container_id": evidence.container_id,
        "duration_ms": evidence.duration_ms,
        "exit_code": evidence.exit_code,
        "failure_fingerprint_sha256": evidence.failure_fingerprint_sha256,
        "log_base64": base64.b64encode(evidence.log).decode("ascii"),
        "log_sha256": evidence.log_sha256,
        "log_truncated": evidence.log_truncated,
        "request": _run_request_dict(evidence.request),
        "request_sha256": evidence.request_sha256,
        "response_sha256": evidence.response_sha256,
        "runner_image_digest": evidence.runner_image_digest,
        "runtime_name": evidence.runtime_name,
        "runtime_rootless": evidence.runtime_rootless,
        "runtime_seccomp_profile": evidence.runtime_seccomp_profile,
        "runtime_security_sha256": evidence.runtime_security_sha256,
        "runtime_sha256": evidence.runtime_sha256,
        "runtime_user_namespace": evidence.runtime_user_namespace,
        "snapshot_sha256": evidence.snapshot_sha256,
        "started_unix_ns": evidence.started_unix_ns,
        "stderr_base64": base64.b64encode(evidence.stderr).decode("ascii"),
        "stderr_bytes": evidence.stderr_bytes,
        "stderr_sha256": evidence.stderr_sha256,
        "stdout_base64": base64.b64encode(evidence.stdout).decode("ascii"),
        "stdout_bytes": evidence.stdout_bytes,
        "stdout_sha256": evidence.stdout_sha256,
    }


def canonical_offline_run_evidence_bytes(evidence: OfflineRunEvidence) -> bytes:
    """Serialize one raw run for a named phase artifact without trusting digest fields."""

    raw = _canonical_json(offline_evidence_dict(evidence))
    if offline_evidence_from_dict(_strict_json(raw, label="offline run", maximum=2_100_000)) != (
        evidence
    ):
        raise OfflinePhaseProtocolError("offline run evidence object is invalid")
    return raw


def _decoded_bytes(value: object, *, label: str, maximum: int) -> bytes:
    if (
        not isinstance(value, str)
        or len(value.encode("ascii", errors="ignore")) != len(value)
        or len(value) > max(4, maximum * 2)
    ):
        raise OfflinePhaseProtocolError(f"{label} is invalid")
    text = value
    try:
        raw = base64.b64decode(text, validate=True)
    except (ValueError, UnicodeEncodeError) as exc:
        raise OfflinePhaseProtocolError(f"{label} is not canonical base64") from exc
    if len(raw) > maximum or base64.b64encode(raw).decode("ascii") != text:
        raise OfflinePhaseProtocolError(f"{label} is invalid or oversized")
    return raw


def _request_from_dict(value: object) -> RunRequest:
    payload = _exact_dict(
        value,
        {
            "acceptance_test_id",
            "candidate_sha256",
            "candidate_snapshot_sha256",
            "command",
            "execution_snapshot_sha256",
            "phase",
            "runner_image_digest",
            "session_id",
            "source_commit_sha",
            "source_commit_tree_sha",
            "source_snapshot_sha256",
            "task_sha256",
            "test_manifest_sha256",
            "test_patch_sha256",
        },
        label="offline run request",
    )
    return RunRequest(
        phase=_string(payload["phase"], label="offline request phase", maximum=5),
        acceptance_test_id=_string(
            payload["acceptance_test_id"], label="acceptance test id", maximum=64
        ),
        session_id=_string(payload["session_id"], label="offline session id", maximum=34),
        source_commit_sha=_string(
            payload["source_commit_sha"], label="source commit SHA", maximum=64
        ),
        source_commit_tree_sha=_string(
            payload["source_commit_tree_sha"], label="source tree SHA", maximum=64
        ),
        source_snapshot_sha256=_sha256(
            payload["source_snapshot_sha256"], label="source snapshot SHA-256"
        ),
        task_sha256=_sha256(payload["task_sha256"], label="task SHA-256"),
        candidate_sha256=_sha256(payload["candidate_sha256"], label="candidate SHA-256"),
        candidate_snapshot_sha256=_sha256(
            payload["candidate_snapshot_sha256"], label="candidate snapshot SHA-256"
        ),
        execution_snapshot_sha256=_sha256(
            payload["execution_snapshot_sha256"], label="execution snapshot SHA-256"
        ),
        test_patch_sha256=_optional_sha256(
            payload["test_patch_sha256"], label="test patch SHA-256"
        ),
        test_manifest_sha256=_optional_sha256(
            payload["test_manifest_sha256"], label="test manifest SHA-256"
        ),
        command=_strings(payload["command"], label="offline command"),
        runner_image_digest=_string(
            payload["runner_image_digest"], label="offline runner image digest", maximum=71
        ),
    )


def offline_evidence_from_dict(value: object) -> OfflineRunEvidence:
    fields = {
        "argv",
        "argv_sha256",
        "cleanup_succeeded",
        "container_id",
        "duration_ms",
        "exit_code",
        "failure_fingerprint_sha256",
        "log_base64",
        "log_sha256",
        "log_truncated",
        "request",
        "request_sha256",
        "response_sha256",
        "runner_image_digest",
        "runtime_name",
        "runtime_rootless",
        "runtime_seccomp_profile",
        "runtime_security_sha256",
        "runtime_sha256",
        "runtime_user_namespace",
        "snapshot_sha256",
        "started_unix_ns",
        "stderr_base64",
        "stderr_bytes",
        "stderr_sha256",
        "stdout_base64",
        "stdout_bytes",
        "stdout_sha256",
    }
    payload = _exact_dict(value, fields, label="offline execution evidence")
    stdout = _decoded_bytes(payload["stdout_base64"], label="offline stdout", maximum=1_000_000)
    stderr = _decoded_bytes(payload["stderr_base64"], label="offline stderr", maximum=1_000_000)
    log = _decoded_bytes(payload["log_base64"], label="offline log", maximum=2_000_032)
    return OfflineRunEvidence(
        request=_request_from_dict(payload["request"]),
        request_sha256=_sha256(payload["request_sha256"], label="offline request SHA-256"),
        runtime_name=_string(payload["runtime_name"], label="offline runtime name", maximum=16),
        runtime_sha256=_sha256(payload["runtime_sha256"], label="offline runtime SHA-256"),
        runtime_security_sha256=_sha256(
            payload["runtime_security_sha256"], label="runtime security SHA-256"
        ),
        runtime_rootless=_strict_bool(payload["runtime_rootless"], label="runtime rootless"),
        runtime_user_namespace=_strict_bool(
            payload["runtime_user_namespace"], label="runtime user namespace"
        ),
        runtime_seccomp_profile=_string(
            payload["runtime_seccomp_profile"], label="runtime seccomp profile"
        ),
        runner_image_digest=_string(
            payload["runner_image_digest"], label="runner image digest", maximum=71
        ),
        snapshot_sha256=_sha256(payload["snapshot_sha256"], label="snapshot SHA-256"),
        argv=_strings(payload["argv"], label="offline argv", maximum=320),
        argv_sha256=_sha256(payload["argv_sha256"], label="offline argv SHA-256"),
        container_id=_string(payload["container_id"], label="container id", maximum=64),
        exit_code=_strict_int(
            payload["exit_code"], label="offline exit code", minimum=-255, maximum=255
        ),
        stdout=stdout,
        stderr=stderr,
        stdout_sha256=_sha256(payload["stdout_sha256"], label="stdout SHA-256"),
        stderr_sha256=_sha256(payload["stderr_sha256"], label="stderr SHA-256"),
        log=log,
        log_sha256=_sha256(payload["log_sha256"], label="log SHA-256"),
        log_truncated=_strict_bool(payload["log_truncated"], label="log truncation"),
        stdout_bytes=_strict_int(
            payload["stdout_bytes"], label="stdout bytes", minimum=0, maximum=1_000_000
        ),
        stderr_bytes=_strict_int(
            payload["stderr_bytes"], label="stderr bytes", minimum=0, maximum=1_000_000
        ),
        started_unix_ns=_strict_int(
            payload["started_unix_ns"],
            label="offline start time",
            minimum=1,
            maximum=9_223_372_036_854_775_807,
        ),
        duration_ms=_strict_int(
            payload["duration_ms"], label="offline duration", minimum=0, maximum=3_600_000
        ),
        cleanup_succeeded=_strict_bool(payload["cleanup_succeeded"], label="cleanup evidence"),
        failure_fingerprint_sha256=_sha256(
            payload["failure_fingerprint_sha256"], label="failure fingerprint SHA-256"
        ),
        response_sha256=_sha256(payload["response_sha256"], label="response SHA-256"),
    )


@dataclass(frozen=True)
class OuterOfflineEvidenceBatch:
    schema_version: str
    prepared_batch_sha256: str
    runs: tuple[OfflineRunEvidence, ...]
    evidence_sha256: str

    def body(self) -> dict[str, object]:
        return {
            "prepared_batch_sha256": self.prepared_batch_sha256,
            "runs": [offline_evidence_dict(run) for run in self.runs],
            "schema_version": self.schema_version,
        }

    def canonical_bytes(self) -> bytes:
        return _canonical_json({**self.body(), "evidence_sha256": self.evidence_sha256})


def create_outer_offline_evidence(
    prepared: PreparedOfflineBatch,
    runs: Sequence[OfflineRunEvidence],
) -> OuterOfflineEvidenceBatch:
    body = {
        "prepared_batch_sha256": prepared.batch_sha256,
        "runs": [offline_evidence_dict(run) for run in runs],
        "schema_version": "1.0",
    }
    batch = OuterOfflineEvidenceBatch(
        schema_version="1.0",
        prepared_batch_sha256=prepared.batch_sha256,
        runs=tuple(runs),
        evidence_sha256=_domain_sha256(_OUTER_DOMAIN, body),
    )
    return parse_outer_offline_evidence(batch.canonical_bytes())


def parse_outer_offline_evidence(raw: bytes) -> OuterOfflineEvidenceBatch:
    value = _strict_json(raw, label="outer offline evidence", maximum=_MAX_EVIDENCE_BYTES)
    payload = _exact_dict(
        value,
        {"evidence_sha256", "prepared_batch_sha256", "runs", "schema_version"},
        label="outer offline evidence",
    )
    if payload["schema_version"] != "1.0":
        raise OfflinePhaseProtocolError("outer offline evidence schema version is invalid")
    raw_runs = payload["runs"]
    if not isinstance(raw_runs, list) or not 1 <= len(raw_runs) <= _MAX_RUNS:
        raise OfflinePhaseProtocolError("outer offline evidence run count is invalid")
    runs = tuple(offline_evidence_from_dict(run) for run in raw_runs)
    batch = OuterOfflineEvidenceBatch(
        schema_version="1.0",
        prepared_batch_sha256=_sha256(
            payload["prepared_batch_sha256"], label="prepared batch SHA-256"
        ),
        runs=runs,
        evidence_sha256=_sha256(payload["evidence_sha256"], label="outer evidence SHA-256"),
    )
    measured = _domain_sha256(_OUTER_DOMAIN, batch.body())
    if not hmac.compare_digest(measured, batch.evidence_sha256):
        raise OfflinePhaseProtocolError("outer offline evidence digest is invalid")
    return batch


def canonical_outer_offline_evidence_bytes(batch: OuterOfflineEvidenceBatch) -> bytes:
    raw = batch.canonical_bytes()
    if parse_outer_offline_evidence(raw) != batch:
        raise OfflinePhaseProtocolError("outer offline evidence object is invalid")
    return raw


def _validate_run_against_plan(evidence: OfflineRunEvidence, run: PreparedOfflineRun) -> None:
    request = evidence.request
    pairs = (
        (request.phase, run.phase),
        (request.acceptance_test_id, run.acceptance_test_id),
        (request.session_id, run.session_id),
        (request.source_snapshot_sha256, run.source_snapshot_sha256),
        (request.candidate_snapshot_sha256, run.candidate_snapshot_sha256),
        (request.execution_snapshot_sha256, run.execution_snapshot_sha256),
        (request.test_patch_sha256, run.test_patch_sha256),
        (request.test_manifest_sha256, run.test_manifest_sha256),
        (request.command, run.command),
    )
    if any(actual != expected for actual, expected in pairs):
        raise OfflinePhaseProtocolError("offline raw evidence differs from its prepared run")


def finalize_offline_batch(
    prepared_raw: bytes,
    outer_raw: bytes,
    *,
    artifact_root: Path,
    candidate_uid: int,
) -> tuple[OfflineRunEvidence, ...]:
    """Strictly parse and remeasure the complete outer batch in the coordinator."""

    prepared = parse_prepared_offline_batch(prepared_raw)
    outer = parse_outer_offline_evidence(outer_raw)
    if not hmac.compare_digest(outer.prepared_batch_sha256, prepared.batch_sha256):
        raise OfflinePhaseProtocolError("outer evidence belongs to another prepared batch")
    if len(outer.runs) != len(prepared.runs):
        raise OfflinePhaseProtocolError("outer evidence does not exactly cover the prepared batch")
    verified: list[OfflineRunEvidence] = []
    for run, evidence in zip(prepared.runs, outer.runs, strict=True):
        _validate_run_against_plan(evidence, run)
        snapshot = _resolve_snapshot(artifact_root, run.snapshot_ref, candidate_uid=candidate_uid)
        if snapshot.snapshot_sha256 != run.execution_snapshot_sha256:
            raise OfflinePhaseProtocolError("prepared execution snapshot digest changed")
        try:
            measured = validate_offline_run_evidence(
                evidence,
                execution_snapshot=snapshot,
                image=prepared.image,
                approved_image_digest=prepared.approved_image_digest,
                candidate_uid=candidate_uid,
            )
        except OfflineRunnerError as exc:
            raise OfflinePhaseProtocolError(
                "offline evidence failed coordinator validation"
            ) from exc
        if measured.request.task_sha256 != prepared.task_sha256 or (
            measured.request.candidate_sha256 != prepared.candidate_sha256
        ):
            raise OfflinePhaseProtocolError("offline evidence changed task or candidate binding")
        verified.append(measured)
    return tuple(verified)
