"""Digest-chained production protocol for the attested review workflow.

The protocol intentionally does not implement snapshot, runner, broker, or judge logic.  It
orders those already-audited adapters, binds every hand-off to immutable digests, and gives the
root-owned launcher one closed dispatch table.  A consumed phase is never retried in place: an
operator starts a new workflow id after any interrupted or failed attempt.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import sqlite3
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Callable
from typing import Literal

from pydantic import BaseModel
from pydantic import ConfigDict
from pydantic import Field
from pydantic import model_validator

from tools.ai_review.path_safety import resolve_safe_output
from tools.ai_review.preflight import PreflightError
from tools.ai_review.preflight import assert_candidate_cannot_mutate


PhaseName = Literal[
    "snapshot",
    "red-snapshot",
    "offline",
    "review-packet",
    "broker",
    "sign",
    "attested-judge",
]
ExternalKind = Literal["none", "offline", "broker"]

PHASE_ORDER: tuple[PhaseName, ...] = (
    "snapshot",
    "red-snapshot",
    "offline",
    "review-packet",
    "broker",
    "sign",
    "attested-judge",
)
EXTERNAL_PHASES = frozenset({"offline", "broker"})
_EXPECTED_EXTERNAL_KIND: dict[PhaseName, ExternalKind] = {
    "snapshot": "none",
    "red-snapshot": "none",
    "offline": "offline",
    "review-packet": "none",
    "broker": "broker",
    "sign": "none",
    "attested-judge": "none",
}
_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_PHASE_REQUEST_DOMAIN = b"amazon-explorer-phase-request-v1\0"
_PHASE_ACTION_DOMAIN = b"amazon-explorer-phase-action-v1\0"
_PHASE_RESULT_DOMAIN = b"amazon-explorer-phase-result-v1\0"
_PHASE_OUTPUT_DOMAIN = b"amazon-explorer-coordinator-phase-output-v1\0"
_MAX_COORDINATOR_BYTES = 2_000_000
_MAX_EXTERNAL_BYTES = 6_000_000


class PhaseProtocolError(RuntimeError):
    """Raised when a production phase cannot be ordered or bound exactly."""


class _StrictFrozenModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)


def _jsonable(value: object) -> object:
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json")
    if isinstance(value, dict):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(item) for item in value]
    return value


def canonical_json_bytes(value: object) -> bytes:
    """Return the single JSON representation used by every protocol digest."""

    return (
        json.dumps(
            _jsonable(value),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")


# The first phase has no predecessor.  Binding it to the canonical empty semantic artifact set
# prevents callers from inventing an unaudited bootstrap payload while keeping later phases
# chained to the prior ``CoordinatorPhaseOutput`` digest.
EMPTY_INITIAL_ARTIFACTS_SHA256 = hashlib.sha256(canonical_json_bytes([])).hexdigest()


def _domain_sha256(domain: bytes, value: object) -> str:
    return hashlib.sha256(domain + canonical_json_bytes(value)).hexdigest()


class PhaseRequest(_StrictFrozenModel):
    """One coordinator request with all cross-phase anchors made explicit."""

    schema_version: Literal["1.0"] = "1.0"
    workflow_id: str = Field(pattern=_SHA256_PATTERN)
    phase: PhaseName
    sequence: int = Field(ge=1, le=len(PHASE_ORDER))
    previous_phase_sha256: str | None = Field(default=None, pattern=_SHA256_PATTERN)
    task_sha256: str = Field(pattern=_SHA256_PATTERN)
    runtime_manifest_sha256: str = Field(pattern=_SHA256_PATTERN)
    coordinator_key_id: str = Field(pattern=_SHA256_PATTERN)
    coordinator_public_key_sha256: str = Field(pattern=_SHA256_PATTERN)
    candidate_sha256: str = Field(pattern=_SHA256_PATTERN)
    candidate_snapshot_sha256: str | None = Field(default=None, pattern=_SHA256_PATTERN)
    review_packet_sha256: str | None = Field(default=None, pattern=_SHA256_PATTERN)
    input_artifacts_sha256: str = Field(pattern=_SHA256_PATTERN)
    request_sha256: str = Field(pattern=_SHA256_PATTERN)

    @classmethod
    def create(cls, **values: object) -> PhaseRequest:
        if "request_sha256" in values:
            raise ValueError("request_sha256 is computed, not caller supplied")
        payload = {"schema_version": "1.0", **values}
        return cls.model_validate(
            {
                **payload,
                "request_sha256": _domain_sha256(_PHASE_REQUEST_DOMAIN, payload),
            }
        )

    @model_validator(mode="after")
    def validate_contract(self) -> PhaseRequest:
        expected_sequence = PHASE_ORDER.index(self.phase) + 1
        if self.sequence != expected_sequence:
            raise ValueError("phase sequence does not match the closed production order")
        if (self.previous_phase_sha256 is None) != (self.sequence == 1):
            raise ValueError("only the first phase may omit the previous phase digest")
        if self.sequence == 1 and not hmac.compare_digest(
            self.input_artifacts_sha256,
            EMPTY_INITIAL_ARTIFACTS_SHA256,
        ):
            raise ValueError("first phase input artifacts must be the canonical empty artifact set")
        if self.sequence == 1 and self.candidate_snapshot_sha256 is not None:
            raise ValueError("snapshot request cannot pre-claim its output snapshot digest")
        if self.sequence > 1 and self.candidate_snapshot_sha256 is None:
            raise ValueError("post-snapshot phases require the candidate snapshot digest")
        packet_phase = PHASE_ORDER.index("broker") + 1
        if (self.review_packet_sha256 is not None) != (self.sequence >= packet_phase):
            raise ValueError("review packet digest must appear exactly after packet construction")
        payload = self.model_dump(exclude={"request_sha256"}, mode="json")
        measured = _domain_sha256(_PHASE_REQUEST_DOMAIN, payload)
        if not hmac.compare_digest(measured, self.request_sha256):
            raise ValueError("request_sha256 does not match canonical phase request bytes")
        return self


class PhaseAction(_StrictFrozenModel):
    """Coordinator-approved instruction for the outer, socket-owning launcher."""

    schema_version: Literal["1.0"] = "1.0"
    workflow_id: str = Field(pattern=_SHA256_PATTERN)
    phase: PhaseName
    sequence: int = Field(ge=1, le=len(PHASE_ORDER))
    request_sha256: str = Field(pattern=_SHA256_PATTERN)
    external_kind: ExternalKind
    payload_sha256: str = Field(pattern=_SHA256_PATTERN)
    action_sha256: str = Field(pattern=_SHA256_PATTERN)

    @classmethod
    def create(
        cls,
        *,
        request: PhaseRequest,
        external_kind: ExternalKind,
        payload_sha256: str,
    ) -> PhaseAction:
        payload = {
            "schema_version": "1.0",
            "workflow_id": request.workflow_id,
            "phase": request.phase,
            "sequence": request.sequence,
            "request_sha256": request.request_sha256,
            "external_kind": external_kind,
            "payload_sha256": payload_sha256,
        }
        return cls.model_validate(
            {**payload, "action_sha256": _domain_sha256(_PHASE_ACTION_DOMAIN, payload)}
        )

    @model_validator(mode="after")
    def validate_contract(self) -> PhaseAction:
        if self.external_kind != _EXPECTED_EXTERNAL_KIND[self.phase]:
            raise ValueError("phase action uses an unapproved external executor")
        if self.sequence != PHASE_ORDER.index(self.phase) + 1:
            raise ValueError("phase action sequence is invalid")
        payload = self.model_dump(exclude={"action_sha256"}, mode="json")
        if not hmac.compare_digest(
            self.action_sha256,
            _domain_sha256(_PHASE_ACTION_DOMAIN, payload),
        ):
            raise ValueError("action_sha256 does not match canonical phase action bytes")
        return self

    def validate_for(self, request: PhaseRequest, payload: bytes) -> None:
        checks = (
            self.workflow_id == request.workflow_id,
            self.phase == request.phase,
            self.sequence == request.sequence,
            hmac.compare_digest(self.request_sha256, request.request_sha256),
            hmac.compare_digest(self.payload_sha256, hashlib.sha256(payload).hexdigest()),
        )
        if not all(checks):
            raise PhaseProtocolError("coordinator action does not match the claimed phase request")


class PhaseArtifact(_StrictFrozenModel):
    """One semantic artifact whose digest contributes to the phase result chain."""

    name: str = Field(pattern=r"^[a-z][a-z0-9-]*(?::[A-Z][A-Z0-9_-]{0,63})?$")
    sha256: str = Field(pattern=_SHA256_PATTERN)


def _artifact_set_sha256(artifacts: tuple[PhaseArtifact, ...]) -> str:
    return hashlib.sha256(
        canonical_json_bytes([artifact.model_dump(mode="json") for artifact in artifacts])
    ).hexdigest()


class PhaseResult(_StrictFrozenModel):
    """Committed phase result and the digest used by the next transition."""

    schema_version: Literal["1.0"] = "1.0"
    request: PhaseRequest
    output_artifacts_sha256: str = Field(pattern=_SHA256_PATTERN)
    artifacts: tuple[PhaseArtifact, ...] = Field(min_length=1, max_length=512)
    candidate_snapshot_sha256: str | None = Field(default=None, pattern=_SHA256_PATTERN)
    review_packet_sha256: str | None = Field(default=None, pattern=_SHA256_PATTERN)
    external_execution_sha256: str | None = Field(default=None, pattern=_SHA256_PATTERN)
    coordinator_output_sha256: str = Field(pattern=_SHA256_PATTERN)
    phase_sha256: str = Field(pattern=_SHA256_PATTERN)

    @classmethod
    def create(cls, **values: object) -> PhaseResult:
        if "phase_sha256" in values:
            raise ValueError("phase_sha256 is computed, not caller supplied")
        payload = {"schema_version": "1.0", **values}
        return cls.model_validate(
            {**payload, "phase_sha256": _domain_sha256(_PHASE_RESULT_DOMAIN, payload)}
        )

    @model_validator(mode="after")
    def validate_contract(self) -> PhaseResult:
        phase = self.request.phase
        names = [artifact.name for artifact in self.artifacts]
        if names != sorted(names) or len(names) != len(set(names)):
            raise ValueError("phase artifacts must be uniquely sorted by semantic name")
        self._validate_artifact_completeness(phase, set(names))
        if not hmac.compare_digest(
            self.output_artifacts_sha256,
            _artifact_set_sha256(self.artifacts),
        ):
            raise ValueError("output artifact digest does not match the canonical artifact set")
        artifacts = {artifact.name: artifact.sha256 for artifact in self.artifacts}
        if phase == "snapshot":
            if self.candidate_snapshot_sha256 is None:
                raise ValueError("snapshot result requires the measured candidate snapshot digest")
            if self.candidate_snapshot_sha256 != artifacts["candidate-snapshot"]:
                raise ValueError("candidate snapshot anchor differs from its semantic artifact")
        elif self.candidate_snapshot_sha256 != self.request.candidate_snapshot_sha256:
            raise ValueError("phase result changed the candidate snapshot digest")
        if phase == "review-packet":
            if self.review_packet_sha256 is None:
                raise ValueError("review-packet result requires the measured packet digest")
            if self.review_packet_sha256 != artifacts["review-packet"]:
                raise ValueError("review packet anchor differs from its semantic artifact")
        elif self.review_packet_sha256 != self.request.review_packet_sha256:
            raise ValueError("phase result changed the review packet digest")
        if (self.external_execution_sha256 is not None) != (phase in EXTERNAL_PHASES):
            raise ValueError("external execution evidence is present for the wrong phase")
        payload = self.model_dump(exclude={"phase_sha256"}, mode="json")
        if not hmac.compare_digest(
            self.phase_sha256,
            _domain_sha256(_PHASE_RESULT_DOMAIN, payload),
        ):
            raise ValueError("phase_sha256 does not match canonical result bytes")
        return self

    @staticmethod
    def _suffixes(names: set[str], prefix: str) -> set[str]:
        marker = prefix + ":"
        return {name.removeprefix(marker) for name in names if name.startswith(marker)}

    @classmethod
    def _validate_artifact_completeness(cls, phase: PhaseName, names: set[str]) -> None:
        if phase == "snapshot" and names != {
            "base-snapshot",
            "candidate-snapshot",
            "policy",
        }:
            raise ValueError("snapshot phase requires policy plus base and candidate snapshots")
        if phase == "red-snapshot" and (
            not names or any(not name.startswith("red-snapshot:") for name in names)
        ):
            raise ValueError("RED phase must contain every named RED snapshot")
        if phase == "offline":
            gates = cls._suffixes(names, "gate")
            red = cls._suffixes(names, "tdd-red")
            green = cls._suffixes(names, "tdd-green")
            expected = {
                *(f"gate:{item}" for item in gates),
                *(f"tdd-red:{item}" for item in red),
                *(f"tdd-green:{item}" for item in green),
            }
            if not gates or not red or red != green or not red <= gates or names != expected:
                raise ValueError("offline phase requires all gates and paired RED/GREEN runs")
        if phase == "review-packet" and names != {"review-packet"}:
            raise ValueError("review phase requires exactly one bounded packet")
        if phase == "broker" and names != {"adversary", "reviewer"}:
            raise ValueError("broker phase requires reviewer and adversary runs")
        if phase == "sign":
            gates = cls._suffixes(names, "gate")
            red = cls._suffixes(names, "tdd-red")
            green = cls._suffixes(names, "tdd-green")
            fixed = {"task", "policy", "reviewer", "adversary"}
            expected = {
                *fixed,
                *(f"gate:{item}" for item in gates),
                *(f"tdd-red:{item}" for item in red),
                *(f"tdd-green:{item}" for item in green),
            }
            if not gates or not red or red != green or not red <= gates or names != expected:
                raise ValueError(
                    "sign phase requires the complete task, policy, gate, TDD, and review set"
                )
        if phase == "attested-judge" and names != {"verdict"}:
            raise ValueError("attested judge phase requires exactly one verdict")


class PhaseOutputArtifact(_StrictFrozenModel):
    """Canonical inline coordinator artifact; its semantic digest is derived, never supplied."""

    name: str = Field(pattern=r"^[a-z][a-z0-9-]*(?::[A-Z][A-Z0-9_-]{0,63})?$")
    content_base64: str = Field(min_length=4, max_length=8_000_000)

    @classmethod
    def create(cls, name: str, content: bytes) -> PhaseOutputArtifact:
        if not isinstance(content, bytes) or not content or len(content) > _MAX_EXTERNAL_BYTES:
            raise PhaseProtocolError("coordinator artifact is empty or exceeds its byte limit")
        return cls(name=name, content_base64=base64.b64encode(content).decode("ascii"))

    def content(self) -> bytes:
        try:
            raw = base64.b64decode(self.content_base64, validate=True)
        except (ValueError, UnicodeEncodeError) as exc:
            raise ValueError("coordinator artifact is not canonical base64") from exc
        if (
            not raw
            or len(raw) > _MAX_EXTERNAL_BYTES
            or base64.b64encode(raw).decode("ascii") != self.content_base64
        ):
            raise ValueError("coordinator artifact content is invalid")
        return raw

    def semantic_sha256(self) -> str:
        raw = self.content()
        if self.name in {"base-snapshot", "candidate-snapshot"} or self.name.startswith(
            "red-snapshot:"
        ):
            try:
                digest = raw.decode("ascii", errors="strict")
            except UnicodeError as exc:
                raise ValueError("snapshot artifact must contain its exact digest") from exc
            if re.fullmatch(_SHA256_PATTERN, digest) is None:
                raise ValueError("snapshot artifact must contain its exact digest")
            return digest
        if self.name == "review-packet":
            try:
                packet = json.loads(raw.decode("utf-8", errors="strict"))
            except (UnicodeError, json.JSONDecodeError) as exc:
                raise ValueError("review packet artifact must be canonical JSON") from exc
            if not isinstance(packet, dict):
                raise ValueError("review packet artifact must be a JSON object")
            digest = packet.get("packet_sha256")
            if not isinstance(digest, str) or re.fullmatch(_SHA256_PATTERN, digest) is None:
                raise ValueError("review packet artifact has no semantic digest")
            body = {key: value for key, value in packet.items() if key != "packet_sha256"}
            body_raw = json.dumps(
                body,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            ).encode("utf-8")
            full_raw = (
                json.dumps(
                    packet,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                    allow_nan=False,
                ).encode("utf-8")
                + b"\n"
            )
            if raw != full_raw or not hmac.compare_digest(
                digest,
                hashlib.sha256(body_raw).hexdigest(),
            ):
                raise ValueError("review packet semantic digest is invalid")
            return digest
        return hashlib.sha256(raw).hexdigest()


class CoordinatorPhaseOutput(_StrictFrozenModel):
    """Strict canonical result produced only after coordinator re-verification."""

    schema_version: Literal["1.0"] = "1.0"
    workflow_id: str = Field(pattern=_SHA256_PATTERN)
    phase: PhaseName
    sequence: int = Field(ge=1, le=len(PHASE_ORDER))
    request_sha256: str = Field(pattern=_SHA256_PATTERN)
    artifacts: tuple[PhaseOutputArtifact, ...] = Field(min_length=1, max_length=512)
    candidate_snapshot_sha256: str | None = Field(default=None, pattern=_SHA256_PATTERN)
    review_packet_sha256: str | None = Field(default=None, pattern=_SHA256_PATTERN)
    output_artifacts_sha256: str = Field(pattern=_SHA256_PATTERN)
    output_sha256: str = Field(pattern=_SHA256_PATTERN)

    @classmethod
    def create(
        cls,
        *,
        request: PhaseRequest,
        artifacts: tuple[PhaseOutputArtifact, ...],
    ) -> CoordinatorPhaseOutput:
        derived = tuple(
            PhaseArtifact(name=artifact.name, sha256=artifact.semantic_sha256())
            for artifact in artifacts
        )
        by_name = {artifact.name: artifact.sha256 for artifact in derived}
        candidate_snapshot = (
            by_name.get("candidate-snapshot")
            if request.phase == "snapshot"
            else request.candidate_snapshot_sha256
        )
        review_packet = (
            by_name.get("review-packet")
            if request.phase == "review-packet"
            else request.review_packet_sha256
        )
        payload = {
            "schema_version": "1.0",
            "workflow_id": request.workflow_id,
            "phase": request.phase,
            "sequence": request.sequence,
            "request_sha256": request.request_sha256,
            "artifacts": artifacts,
            "candidate_snapshot_sha256": candidate_snapshot,
            "review_packet_sha256": review_packet,
            "output_artifacts_sha256": _artifact_set_sha256(derived),
        }
        return cls.model_validate(
            {**payload, "output_sha256": _domain_sha256(_PHASE_OUTPUT_DOMAIN, payload)}
        )

    @model_validator(mode="after")
    def validate_contract(self) -> CoordinatorPhaseOutput:
        if self.sequence != PHASE_ORDER.index(self.phase) + 1:
            raise ValueError("coordinator output sequence is invalid")
        names = [artifact.name for artifact in self.artifacts]
        if names != sorted(names) or len(names) != len(set(names)):
            raise ValueError("coordinator artifacts must be uniquely sorted")
        derived = self.phase_artifacts()
        PhaseResult._validate_artifact_completeness(self.phase, set(names))
        if not hmac.compare_digest(
            self.output_artifacts_sha256,
            _artifact_set_sha256(derived),
        ):
            raise ValueError("coordinator output artifact digest is invalid")
        by_name = {artifact.name: artifact.sha256 for artifact in derived}
        if self.phase == "snapshot" and self.candidate_snapshot_sha256 != by_name.get(
            "candidate-snapshot"
        ):
            raise ValueError("coordinator candidate snapshot anchor is invalid")
        if self.phase == "review-packet" and self.review_packet_sha256 != by_name.get(
            "review-packet"
        ):
            raise ValueError("coordinator review packet anchor is invalid")
        payload = self.model_dump(exclude={"output_sha256"}, mode="json")
        if not hmac.compare_digest(
            self.output_sha256,
            _domain_sha256(_PHASE_OUTPUT_DOMAIN, payload),
        ):
            raise ValueError("coordinator output canonical digest is invalid")
        return self

    def phase_artifacts(self) -> tuple[PhaseArtifact, ...]:
        return tuple(
            PhaseArtifact(name=artifact.name, sha256=artifact.semantic_sha256())
            for artifact in self.artifacts
        )

    def validate_for(self, request: PhaseRequest) -> None:
        if (
            self.workflow_id != request.workflow_id
            or self.phase != request.phase
            or self.sequence != request.sequence
            or not hmac.compare_digest(self.request_sha256, request.request_sha256)
        ):
            raise PhaseProtocolError("coordinator output does not match the claimed request")
        if self.phase != "snapshot" and self.candidate_snapshot_sha256 != (
            request.candidate_snapshot_sha256
        ):
            raise PhaseProtocolError("coordinator output changed the snapshot anchor")
        if self.phase != "review-packet" and self.review_packet_sha256 != (
            request.review_packet_sha256
        ):
            raise PhaseProtocolError("coordinator output changed the packet anchor")


class CandidateMountPolicy:
    """Closed mount policy supplied to every coordinator invocation."""

    _ALLOWED = frozenset({"snapshot"})

    def allowed(self, phase: PhaseName) -> bool:
        if phase not in PHASE_ORDER:
            raise PhaseProtocolError("unknown production phase")
        return phase in self._ALLOWED


class PhaseChain:
    """In-memory verifier used both before durable claim and after coordinator output."""

    def __init__(self, results: tuple[PhaseResult, ...] = ()) -> None:
        self._results: list[PhaseResult] = []
        for result in results:
            self.accept(result)

    @property
    def results(self) -> tuple[PhaseResult, ...]:
        return tuple(self._results)

    def validate_request(self, request: PhaseRequest) -> None:
        expected_sequence = len(self._results) + 1
        if request.sequence != expected_sequence:
            raise PhaseProtocolError("request is not the next phase in the workflow")
        if request.phase != PHASE_ORDER[expected_sequence - 1]:
            raise PhaseProtocolError("request is not the next phase in the workflow")
        if not self._results:
            if request.previous_phase_sha256 is not None:
                raise PhaseProtocolError("first phase must not reference prior evidence")
            return
        previous = self._results[-1]
        if not hmac.compare_digest(
            request.previous_phase_sha256 or "",
            previous.phase_sha256,
        ):
            raise PhaseProtocolError("previous phase SHA-256 does not match the committed result")
        anchors = (
            ("workflow id", request.workflow_id, previous.request.workflow_id),
            ("task SHA-256", request.task_sha256, previous.request.task_sha256),
            (
                "runtime manifest SHA-256",
                request.runtime_manifest_sha256,
                previous.request.runtime_manifest_sha256,
            ),
            (
                "coordinator key id",
                request.coordinator_key_id,
                previous.request.coordinator_key_id,
            ),
            (
                "coordinator public key SHA-256",
                request.coordinator_public_key_sha256,
                previous.request.coordinator_public_key_sha256,
            ),
            ("candidate SHA-256", request.candidate_sha256, previous.request.candidate_sha256),
            (
                "candidate snapshot SHA-256",
                request.candidate_snapshot_sha256,
                previous.candidate_snapshot_sha256,
            ),
            (
                "review packet SHA-256",
                request.review_packet_sha256,
                previous.review_packet_sha256,
            ),
        )
        for label, actual, expected in anchors:
            if actual != expected:
                raise PhaseProtocolError(f"{label} changed across phase boundary")
        if not hmac.compare_digest(
            request.input_artifacts_sha256,
            previous.output_artifacts_sha256,
        ):
            raise PhaseProtocolError(
                "phase input artifacts SHA-256 does not match the prior committed output"
            )

    def accept(self, result: PhaseResult) -> None:
        self.validate_request(result.request)
        self._results.append(result)


class SqlitePhaseLedger:
    """Durable consume-before-execute journal for phase replay prevention."""

    def __init__(self, path: Path, *, candidate_uid: int) -> None:
        absolute = Path(os.path.abspath(path))
        try:
            parent = assert_candidate_cannot_mutate(
                absolute.parent,
                candidate_uid=candidate_uid,
            )
        except PreflightError as exc:
            raise PhaseProtocolError(str(exc)) from exc
        if not parent.is_dir() or stat.S_IMODE(parent.stat().st_mode) & 0o077:
            raise PhaseProtocolError("phase ledger parent must be a private protected directory")
        if absolute.exists() or absolute.is_symlink():
            try:
                checked = assert_candidate_cannot_mutate(absolute, candidate_uid=candidate_uid)
            except PreflightError as exc:
                raise PhaseProtocolError(str(exc)) from exc
            metadata = os.lstat(checked)
            if not stat.S_ISREG(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) & 0o077:
                raise PhaseProtocolError("phase ledger must be a private regular file")
        else:
            directory_fd = os.open(
                parent,
                os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
            )
            try:
                descriptor = os.open(
                    absolute.name,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                    0o600,
                    dir_fd=directory_fd,
                )
                os.close(descriptor)
            except OSError as exc:
                raise PhaseProtocolError("phase ledger could not be created exclusively") from exc
            finally:
                os.close(directory_fd)
        self.path = absolute
        self.path.chmod(0o600)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=30, isolation_level=None)
        connection.execute("PRAGMA journal_mode=DELETE")
        connection.execute("PRAGMA synchronous=FULL")
        return connection

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.execute(
                "CREATE TABLE IF NOT EXISTS phases ("
                "workflow_id TEXT NOT NULL, sequence INTEGER NOT NULL, phase TEXT NOT NULL, "
                "request_sha256 TEXT NOT NULL UNIQUE, request_json BLOB NOT NULL, "
                "status TEXT NOT NULL CHECK(status IN ('pending','complete')), "
                "result_sha256 TEXT UNIQUE, result_json BLOB, "
                "PRIMARY KEY(workflow_id, sequence))"
            )
        self.path.chmod(0o600)

    @staticmethod
    def _completed_results(
        connection: sqlite3.Connection, workflow_id: str
    ) -> tuple[PhaseResult, ...]:
        rows = connection.execute(
            "SELECT result_json FROM phases WHERE workflow_id = ? AND status = 'complete' "
            "ORDER BY sequence",
            (workflow_id,),
        ).fetchall()
        return tuple(PhaseResult.model_validate_json(bytes(row[0])) for row in rows)

    def claim(self, request: PhaseRequest) -> None:
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            present = connection.execute(
                "SELECT 1 FROM phases WHERE request_sha256 = ? OR "
                "(workflow_id = ? AND sequence = ?)",
                (request.request_sha256, request.workflow_id, request.sequence),
            ).fetchone()
            if present is not None:
                raise PhaseProtocolError("phase request was already claimed")
            pending = connection.execute(
                "SELECT 1 FROM phases WHERE workflow_id = ? AND status = 'pending'",
                (request.workflow_id,),
            ).fetchone()
            if pending is not None:
                raise PhaseProtocolError("workflow contains an interrupted consumed phase")
            PhaseChain(self._completed_results(connection, request.workflow_id)).validate_request(
                request
            )
            connection.execute(
                "INSERT INTO phases(workflow_id,sequence,phase,request_sha256,request_json,status) "
                "VALUES (?,?,?,?,?,'pending')",
                (
                    request.workflow_id,
                    request.sequence,
                    request.phase,
                    request.request_sha256,
                    canonical_json_bytes(request),
                ),
            )
            connection.execute("COMMIT")
        except Exception:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()

    def commit(self, result: PhaseResult) -> None:
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT request_json,status FROM phases WHERE workflow_id = ? AND sequence = ?",
                (result.request.workflow_id, result.request.sequence),
            ).fetchone()
            if row is None or row[1] != "pending":
                raise PhaseProtocolError("phase result has no uniquely pending claim")
            stored = PhaseRequest.model_validate_json(bytes(row[0]))
            if stored != result.request:
                raise PhaseProtocolError("phase result does not match the consumed request")
            connection.execute(
                "UPDATE phases SET status='complete',result_sha256=?,result_json=? "
                "WHERE workflow_id=? AND sequence=? AND status='pending'",
                (
                    result.phase_sha256,
                    canonical_json_bytes(result),
                    result.request.workflow_id,
                    result.request.sequence,
                ),
            )
            connection.execute("COMMIT")
        except Exception:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()


@dataclass(frozen=True)
class PhaseExecution:
    action: PhaseAction
    prepared_payload: bytes
    coordinator_output: CoordinatorPhaseOutput
    verified_output: bytes
    verified_output_sha256: str
    external_evidence: bytes | None
    external_evidence_sha256: str | None


CoordinatorPrepare = Callable[[PhaseRequest], tuple[PhaseAction, bytes]]
CoordinatorFinalize = Callable[[PhaseAction, bytes], bytes]
ExternalExecute = Callable[[PhaseAction, bytes], bytes]


def _bounded(raw: bytes, *, label: str, maximum: int) -> bytes:
    if not isinstance(raw, bytes) or not raw or len(raw) > maximum:
        raise PhaseProtocolError(f"{label} is empty or exceeds its byte limit")
    return raw


def execute_phase(
    request: PhaseRequest,
    *,
    coordinator_prepare: Callable[..., tuple[PhaseAction, bytes]],
    coordinator_finalize: CoordinatorFinalize,
    offline_execute: ExternalExecute,
    broker_execute: ExternalExecute,
) -> PhaseExecution:
    """Run prepare -> optional outer execution -> coordinator re-verification.

    Coordinator callbacks execute in the pinned no-network image.  Only the outer callback owns
    the container runtime; the broker callback receives no candidate path or mount parameter.
    """

    mount_candidate = CandidateMountPolicy().allowed(request.phase)
    action, payload = coordinator_prepare(request, mount_candidate=mount_candidate)
    payload = _bounded(payload, label="coordinator phase payload", maximum=_MAX_COORDINATOR_BYTES)
    action.validate_for(request, payload)
    external_digest: str | None = None
    if action.external_kind == "offline":
        external = _bounded(
            offline_execute(action, payload),
            label="offline execution evidence",
            maximum=_MAX_EXTERNAL_BYTES,
        )
        external_digest = hashlib.sha256(external).hexdigest()
        finalize_input = external
    elif action.external_kind == "broker":
        external = _bounded(
            broker_execute(action, payload),
            label="broker execution evidence",
            maximum=_MAX_EXTERNAL_BYTES,
        )
        external_digest = hashlib.sha256(external).hexdigest()
        finalize_input = external
    elif action.external_kind == "none":
        finalize_input = payload
    else:  # pragma: no cover - strict model makes this unreachable
        raise PhaseProtocolError("unknown external phase action")
    verified = _bounded(
        coordinator_finalize(action, finalize_input),
        label="coordinator verified output",
        maximum=_MAX_EXTERNAL_BYTES,
    )
    try:
        coordinator_output = CoordinatorPhaseOutput.model_validate_json(verified)
    except Exception as exc:
        raise PhaseProtocolError("coordinator output is not a strict phase envelope") from exc
    coordinator_output.validate_for(request)
    if canonical_json_bytes(coordinator_output) != verified:
        raise PhaseProtocolError("coordinator output must use the canonical JSON encoding")
    return PhaseExecution(
        action=action,
        prepared_payload=payload,
        coordinator_output=coordinator_output,
        verified_output=verified,
        verified_output_sha256=hashlib.sha256(verified).hexdigest(),
        external_evidence=(external if action.external_kind in {"offline", "broker"} else None),
        external_evidence_sha256=external_digest,
    )


def persist_phase_output(
    output: Path,
    raw: bytes,
    *,
    expected_sha256: str,
    max_bytes: int = _MAX_EXTERNAL_BYTES,
) -> str:
    """Persist a bounded coordinator-verified artifact with O_EXCL and fsync."""

    if (
        isinstance(max_bytes, bool)
        or not isinstance(max_bytes, int)
        or not 1_024 <= max_bytes <= _MAX_EXTERNAL_BYTES
    ):
        raise PhaseProtocolError("phase output byte limit is invalid")
    if not isinstance(raw, bytes) or len(raw) > max_bytes:
        raise PhaseProtocolError("phase output exceeds its byte limit")
    measured = hashlib.sha256(raw).hexdigest()
    if not hmac.compare_digest(measured, expected_sha256):
        raise PhaseProtocolError("phase output digest does not match verified evidence")
    try:
        safe = resolve_safe_output(output)
    except ValueError as exc:
        raise PhaseProtocolError("phase output must be a new exclusive file") from exc
    directory_fd = os.open(
        safe.parent,
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
    )
    created = False
    try:
        descriptor = os.open(
            safe.name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
            dir_fd=directory_fd,
        )
        created = True
        try:
            view = memoryview(raw)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise PhaseProtocolError("phase output write failed")
                view = view[written:]
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.fsync(directory_fd)
    except Exception:
        if created:
            try:
                os.unlink(safe.name, dir_fd=directory_fd)
            except FileNotFoundError:
                pass
        raise
    finally:
        os.close(directory_fd)
    return measured


def run_claimed_phase(
    request: PhaseRequest,
    *,
    ledger: SqlitePhaseLedger,
    output: Path,
    coordinator_prepare: Callable[..., tuple[PhaseAction, bytes]],
    coordinator_finalize: CoordinatorFinalize,
    offline_execute: ExternalExecute,
    broker_execute: ExternalExecute,
) -> PhaseResult:
    """Consume, execute, persist, and commit exactly one transition.

    The durable claim intentionally happens first.  Any crash leaves a consumed pending row and
    forces a fresh workflow id, so a costly or signed action is never silently replayed.
    """

    ledger.claim(request)
    execution = execute_phase(
        request,
        coordinator_prepare=coordinator_prepare,
        coordinator_finalize=coordinator_finalize,
        offline_execute=offline_execute,
        broker_execute=broker_execute,
    )
    coordinator_output = execution.coordinator_output
    result = PhaseResult.create(
        request=request,
        output_artifacts_sha256=coordinator_output.output_artifacts_sha256,
        artifacts=coordinator_output.phase_artifacts(),
        candidate_snapshot_sha256=coordinator_output.candidate_snapshot_sha256,
        review_packet_sha256=coordinator_output.review_packet_sha256,
        external_execution_sha256=execution.external_evidence_sha256,
        coordinator_output_sha256=execution.verified_output_sha256,
    )
    if execution.external_evidence is not None:
        persist_phase_output(
            output.with_name("prepared-payload.json"),
            execution.prepared_payload,
            expected_sha256=execution.action.payload_sha256,
        )
        persist_phase_output(
            output.with_name("external-evidence.json"),
            execution.external_evidence,
            expected_sha256=result.external_execution_sha256 or "",
        )
    persist_phase_output(
        output.with_name("coordinator-output.json"),
        execution.verified_output,
        expected_sha256=result.coordinator_output_sha256,
    )
    artifact_manifest = canonical_json_bytes(
        [artifact.model_dump(mode="json") for artifact in result.artifacts]
    )
    persist_phase_output(
        output.with_name("artifact-manifest.json"),
        artifact_manifest,
        expected_sha256=result.output_artifacts_sha256,
    )
    result_raw = canonical_json_bytes(result)
    persist_phase_output(
        output,
        result_raw,
        expected_sha256=hashlib.sha256(result_raw).hexdigest(),
    )
    ledger.commit(result)
    return result
