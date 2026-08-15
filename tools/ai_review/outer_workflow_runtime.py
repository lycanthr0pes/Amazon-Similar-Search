"""Stdlib-only durable runtime for the fixed seven-phase outer workflow.

This module owns filesystem hand-offs and constructs every coordinator command.
It never accepts a caller-provided descriptor or coordinator argv.  The pinned
coordinator returns canonical transition envelopes, and ``outer_workflow_state``
independently validates them before this runtime commits a phase directory.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import stat
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from tools.ai_review.outer_workflow_state import FinalizedTransition
from tools.ai_review.outer_workflow_state import PHASE_ORDER
from tools.ai_review.outer_workflow_state import OuterWorkflowStateError
from tools.ai_review.outer_workflow_state import WorkflowStateResult
from tools.ai_review.outer_workflow_state import parse_prepared_transition
from tools.ai_review.outer_workflow_state import run_fixed_workflow
from tools.ai_review.outer_workflow_state import validate_phase_request_bytes
from tools.ai_review.preflight import PreflightError
from tools.ai_review.preflight import assert_candidate_cannot_mutate
from tools.ai_review.preflight import assert_candidate_cannot_mutate_tree
from tools.ai_review.preflight import read_protected_file


_SHA_RE = re.compile(r"^[0-9a-f]{64}$")
_IMAGE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/:+-]*@(sha256:[0-9a-f]{64})$")
_MAX_TREE_ENTRIES = 200_000
_MAX_TREE_BYTES = 512 * 1024 * 1024
_MAX_FILE_BYTES = 16 * 1024 * 1024

# The stdlib launcher checks this tuple before it reads broker credentials,
# creates a cost ledger, or starts phase zero. Expanding it is an explicit
# release action after the matching pinned-coordinator handlers and end-to-end
# tests exist.
IMPLEMENTED_COORDINATOR_WORKFLOW_PHASES = (
    "snapshot",
    "red-snapshot",
    "offline",
    "review-packet",
    "broker",
    "sign",
    "attested-judge",
)


class OuterWorkflowRuntimeError(RuntimeError):
    """Raised before a filesystem or coordinator boundary can be weakened."""


@dataclass(frozen=True)
class WorkflowImages:
    coordinator: str
    coordinator_digest: str
    offline: str
    offline_digest: str
    broker: str
    broker_digest: str
    broker_gateway: str
    broker_gateway_digest: str

    def __post_init__(self) -> None:
        values = (
            (self.coordinator, self.coordinator_digest),
            (self.offline, self.offline_digest),
            (self.broker, self.broker_digest),
            (self.broker_gateway, self.broker_gateway_digest),
        )
        matches = tuple(_IMAGE_RE.fullmatch(image) for image, _digest in values)
        if any(match is None for match in matches) or any(
            match.group(1) != digest  # type: ignore[union-attr]
            for match, (_image, digest) in zip(matches, values, strict=True)
        ):
            raise OuterWorkflowRuntimeError("workflow images must use their manifest-pinned digest")


@dataclass(frozen=True)
class CoordinatorWorkflowCall:
    phase: str
    operation: str
    artifact_root: Path
    output_root: Path
    candidate_repo: Path | None
    signing_key: Path | None
    nonce_ledger_root: Path | None
    snapshot_artifact_root: Path | None
    command: tuple[str, ...]


CoordinatorExecute = Callable[[CoordinatorWorkflowCall], bytes]
OfflineExecute = Callable[[bytes, Path], bytes]
BrokerExecute = Callable[[bytes], bytes]


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
        raise OuterWorkflowRuntimeError("workflow artifact is not canonical JSON") from exc


def _validate_broker_runtime_binding(raw: bytes) -> dict[str, object]:
    """Strictly validate the host-measured, path-free broker runtime binding."""

    def pairs(values: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in values:
            if key in result:
                raise OuterWorkflowRuntimeError("broker runtime binding contains a duplicate field")
            result[key] = value
        return result

    if not isinstance(raw, bytes) or not raw or len(raw) > 16_384:
        raise OuterWorkflowRuntimeError("broker runtime binding is empty or oversized")
    try:
        value = json.loads(raw.decode("utf-8", errors="strict"), object_pairs_hook=pairs)
    except OuterWorkflowRuntimeError:
        raise
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise OuterWorkflowRuntimeError("broker runtime binding is not strict JSON") from exc
    fields = {
        "environment_sha256",
        "executable_sha256",
        "name",
        "rootless",
        "seccomp_profile",
        "security_evidence_sha256",
        "user_namespace",
    }
    if not isinstance(value, dict) or set(value) != fields or _canonical(value) != raw:
        raise OuterWorkflowRuntimeError(
            "broker runtime binding has unknown fields or noncanonical encoding"
        )
    security_payload = {
        "name": value["name"],
        "rootless": value["rootless"],
        "seccomp_profile": value["seccomp_profile"],
        "user_namespace": value["user_namespace"],
    }
    expected_security = hashlib.sha256(_canonical(security_payload)).hexdigest()
    if (
        value["name"] != "podman"
        or not isinstance(value["executable_sha256"], str)
        or _SHA_RE.fullmatch(value["executable_sha256"]) is None
        or not isinstance(value["environment_sha256"], str)
        or _SHA_RE.fullmatch(value["environment_sha256"]) is None
        or type(value["rootless"]) is not bool
        or type(value["user_namespace"]) is not bool
        or value["rootless"] is not True
        or value["user_namespace"] is not True
        or not isinstance(value["seccomp_profile"], str)
        or not value["seccomp_profile"]
        or "unconfined" in value["seccomp_profile"].casefold()
        or not isinstance(value["security_evidence_sha256"], str)
        or _SHA_RE.fullmatch(value["security_evidence_sha256"]) is None
        or not hmac.compare_digest(value["security_evidence_sha256"], expected_security)
    ):
        raise OuterWorkflowRuntimeError("broker runtime binding is invalid")
    return value


def _write_exclusive(path: Path, raw: bytes, *, maximum: int = 16 * 1024 * 1024) -> None:
    if not isinstance(raw, bytes) or not raw or len(raw) > maximum:
        raise OuterWorkflowRuntimeError("workflow artifact is empty or oversized")
    directory_fd = os.open(
        path.parent,
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
    )
    created = False
    try:
        descriptor = os.open(
            path.name,
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
                    raise OuterWorkflowRuntimeError("workflow artifact write failed")
                view = view[written:]
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.fsync(directory_fd)
    except Exception:
        if created:
            try:
                os.unlink(path.name, dir_fd=directory_fd)
            except FileNotFoundError:
                pass
        raise
    finally:
        os.close(directory_fd)


def _inspect_tree(root: Path) -> tuple[tuple[Path, os.stat_result], ...]:
    try:
        root = Path(os.path.abspath(root)).resolve(strict=True)
    except OSError as exc:
        raise OuterWorkflowRuntimeError("workflow artifact tree is unavailable") from exc
    if not root.is_dir() or root.is_symlink():
        raise OuterWorkflowRuntimeError("workflow artifact root must be a real directory")
    measured: list[tuple[Path, os.stat_result]] = []
    total = 0
    for directory, directories, filenames in os.walk(root, followlinks=False):
        directories.sort()
        filenames.sort()
        directory_path = Path(directory)
        directory_stat = os.lstat(directory_path)
        if not stat.S_ISDIR(directory_stat.st_mode):
            raise OuterWorkflowRuntimeError("workflow artifact directory changed type")
        for name in (*directories, *filenames):
            path = directory_path / name
            metadata = os.lstat(path)
            if stat.S_ISLNK(metadata.st_mode):
                raise OuterWorkflowRuntimeError("workflow artifact symlink is forbidden")
            if stat.S_ISREG(metadata.st_mode):
                if metadata.st_nlink != 1 or metadata.st_size > _MAX_FILE_BYTES:
                    raise OuterWorkflowRuntimeError(
                        "workflow artifact hardlink or oversized file is forbidden"
                    )
                total += metadata.st_size
            elif not stat.S_ISDIR(metadata.st_mode):
                raise OuterWorkflowRuntimeError("workflow artifact special file is forbidden")
            measured.append((path.relative_to(root), metadata))
            if len(measured) > _MAX_TREE_ENTRIES or total > _MAX_TREE_BYTES:
                raise OuterWorkflowRuntimeError("workflow artifact tree exceeds its limit")
    return tuple(measured)


def _copy_tree(source: Path, destination: Path) -> None:
    entries = _inspect_tree(source)
    try:
        destination.mkdir(mode=0o700)
    except OSError as exc:
        raise OuterWorkflowRuntimeError("workflow copy destination must be new") from exc
    try:
        for relative, metadata in entries:
            target = destination / relative
            if stat.S_ISDIR(metadata.st_mode):
                target.mkdir(mode=0o700)
                continue
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            source_fd = os.open(
                source / relative,
                os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
            )
            target_parent_fd = os.open(
                target.parent,
                os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
            )
            try:
                opened = os.fstat(source_fd)
                if (
                    (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino)
                    or not stat.S_ISREG(opened.st_mode)
                    or opened.st_nlink != 1
                ):
                    raise OuterWorkflowRuntimeError("workflow artifact changed during copy")
                target_fd = os.open(
                    target.name,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                    0o600,
                    dir_fd=target_parent_fd,
                )
                try:
                    while chunk := os.read(source_fd, 1024 * 1024):
                        view = memoryview(chunk)
                        while view:
                            written = os.write(target_fd, view)
                            if written <= 0:
                                raise OuterWorkflowRuntimeError("workflow artifact copy failed")
                            view = view[written:]
                    os.fsync(target_fd)
                finally:
                    os.close(target_fd)
            finally:
                os.close(target_parent_fd)
                os.close(source_fd)
    except BaseException:
        # The destination is newly created and not exposed as a committed input.
        # Leave it in place for operator forensics; a fresh workflow id is required.
        raise


def _freeze_tree(root: Path) -> None:
    entries = _inspect_tree(root)
    root_metadata = os.lstat(root)
    directory_flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    file_flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    root_fd = os.open(root, directory_flags)
    try:
        opened_root = os.fstat(root_fd)
        if (opened_root.st_dev, opened_root.st_ino) != (
            root_metadata.st_dev,
            root_metadata.st_ino,
        ):
            raise OuterWorkflowRuntimeError("workflow artifact root changed before freeze")
        for relative, metadata in reversed(entries):
            parent_fd = os.dup(root_fd)
            try:
                parts = relative.parts
                for component in parts[:-1]:
                    next_fd = os.open(component, directory_flags, dir_fd=parent_fd)
                    os.close(parent_fd)
                    parent_fd = next_fd
                flags = directory_flags if stat.S_ISDIR(metadata.st_mode) else file_flags
                descriptor = os.open(parts[-1], flags, dir_fd=parent_fd)
            finally:
                os.close(parent_fd)
            try:
                current = os.fstat(descriptor)
                if (current.st_dev, current.st_ino) != (metadata.st_dev, metadata.st_ino):
                    raise OuterWorkflowRuntimeError("workflow artifact changed before freeze")
                if stat.S_ISREG(current.st_mode) and current.st_nlink != 1:
                    raise OuterWorkflowRuntimeError("workflow artifact hardlink is forbidden")
                if not (stat.S_ISREG(current.st_mode) or stat.S_ISDIR(current.st_mode)):
                    raise OuterWorkflowRuntimeError("workflow artifact changed type before freeze")
                os.fchmod(descriptor, 0o555 if stat.S_ISDIR(current.st_mode) else 0o444)
            finally:
                os.close(descriptor)
        os.fchmod(root_fd, 0o555)
    finally:
        os.close(root_fd)


def _new_directory(parent: Path, name: str) -> Path:
    parent_fd = os.open(
        parent,
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        os.mkdir(name, 0o700, dir_fd=parent_fd)
        os.fsync(parent_fd)
    except OSError as exc:
        raise OuterWorkflowRuntimeError("workflow output must be new and exclusive") from exc
    finally:
        os.close(parent_fd)
    return parent / name


def _validate_snapshot_store_artifacts(
    phase: str,
    finalized: FinalizedTransition,
    snapshot_store: Path,
) -> None:
    directory_name = (
        "snapshots" if phase == "snapshot" else "red-snapshots" if phase == "red-snapshot" else None
    )
    if directory_name is None:
        return
    artifacts = finalized.result["artifacts"]
    expected = {
        artifact["sha256"]
        for artifact in artifacts
        if artifact["name"] in {"base-snapshot", "candidate-snapshot"}
        or artifact["name"].startswith("red-snapshot:")
    }
    directory = snapshot_store / directory_name
    try:
        actual = {
            path.name
            for path in directory.iterdir()
            if path.is_dir() and not path.is_symlink() and _SHA_RE.fullmatch(path.name)
        }
    except OSError as exc:
        raise OuterWorkflowRuntimeError("workflow snapshot artifacts are unavailable") from exc
    if not expected or actual != expected or len(tuple(directory.iterdir())) != len(actual):
        raise OuterWorkflowRuntimeError(
            "workflow physical snapshots differ from their semantic artifact set"
        )
    _inspect_tree(directory)


def _coordinator_command(
    *,
    phase: str,
    operation: str,
    request_raw: bytes,
    images: WorkflowImages,
    candidate_uid: int,
    broker_ledger_identity_sha256: str,
    broker_runtime_binding_sha256: str,
    prepared_raw: bytes | None = None,
    evidence_raw: bytes | None = None,
) -> tuple[str, ...]:
    command = [
        phase,
        "--workflow-operation",
        operation,
        "--task",
        "@task-container",
        "--artifact-root",
        "@artifact-root-container",
        "--expected-task-sha256",
        "@task-sha256",
        "--phase-request",
        "/artifacts/phase-request.json",
        "--expected-phase-request-file-sha256",
        hashlib.sha256(request_raw).hexdigest(),
        "--phase-output-root",
        "/output",
        "--candidate-uid",
        str(candidate_uid),
        "--offline-image",
        images.offline,
        "--broker-image",
        images.broker,
        "--broker-gateway-image",
        images.broker_gateway,
    ]
    if phase == "broker":
        if (
            _SHA_RE.fullmatch(broker_ledger_identity_sha256) is None
            or _SHA_RE.fullmatch(broker_runtime_binding_sha256) is None
        ):
            raise OuterWorkflowRuntimeError("broker ledger identity or runtime binding is invalid")
        command.extend(
            (
                "--broker-ledger-identity-sha256",
                broker_ledger_identity_sha256,
                "--broker-egress-policy",
                "@broker-egress-policy-container",
                "--expected-broker-egress-policy-sha256",
                "@broker-allowlist-policy-sha256",
                "--broker-pricing-policy",
                "@openai-pricing-policy-container",
                "--expected-broker-pricing-policy-sha256",
                "@broker-pricing-policy-sha256",
                "--broker-packet-reservation-limit",
                "@broker-packet-reservation-limit",
                "--broker-packet-cost-limit-microusd",
                "@broker-packet-cost-limit-microusd",
                "--broker-runtime-binding",
                "/artifacts/broker-runtime-binding.json",
                "--expected-broker-runtime-binding-sha256",
                broker_runtime_binding_sha256,
            )
        )
    if operation == "finalize":
        if prepared_raw is None or evidence_raw is None:
            raise OuterWorkflowRuntimeError("coordinator finalize lacks prepared or raw evidence")
        command.extend(
            (
                "--prepared-transition",
                "/artifacts/current-prepared-transition.json",
                "--expected-prepared-transition-sha256",
                hashlib.sha256(prepared_raw).hexdigest(),
                "--execution-evidence",
                "/artifacts/current-execution-evidence.json",
                "--expected-execution-evidence-sha256",
                hashlib.sha256(evidence_raw).hexdigest(),
            )
        )
    if phase == "snapshot" and operation == "prepare":
        command.extend(("--candidate-repo", "/candidate"))
    if phase == "attested-judge" and operation == "prepare":
        command.extend(("--nonce-ledger", "/nonce-ledger/nonces.sqlite3"))
    if phase != "snapshot" or operation == "finalize":
        command.extend(("--snapshot-artifact-root", "/snapshots"))
    command.extend(
        (
            "--runtime-root",
            "/runtime",
            "--runtime-manifest",
            "@runtime-manifest-container",
            "--expected-runtime-manifest-sha256",
            "@runtime-manifest-sha256",
            "--expected-coordinator-image-digest",
            "@coordinator-image-digest",
        )
    )
    return tuple(command)


def run_production_workflow(
    initial_request: Path,
    *,
    initial_artifact_root: Path,
    output_root: Path,
    candidate_repo: Path,
    signing_key: Path,
    nonce_ledger_root: Path,
    candidate_uid: int,
    images: WorkflowImages,
    broker_ledger_identity_sha256: str,
    broker_runtime_binding: bytes,
    coordinator_execute: CoordinatorExecute,
    offline_execute: OfflineExecute,
    broker_execute: BrokerExecute,
) -> WorkflowStateResult:
    """Run and durably commit the seven exact phases.

    ``coordinator_execute`` is the sole bridge to the pinned coordinator OCI.
    Production supplies ``coordinator_launcher.execute_coordinator`` through a
    narrow adapter; tests may replace only that process boundary.
    """

    if type(candidate_uid) is not int or candidate_uid <= 0 or candidate_uid == os.geteuid():
        raise OuterWorkflowRuntimeError("workflow candidate UID boundary is invalid")
    try:
        initial_root = Path(os.path.abspath(initial_artifact_root)).resolve(strict=True)
        request_path = Path(os.path.abspath(initial_request)).resolve(strict=True)
        root = Path(os.path.abspath(output_root)).resolve(strict=True)
        candidate = Path(os.path.abspath(candidate_repo)).resolve(strict=True)
        key = Path(os.path.abspath(signing_key)).resolve(strict=True)
        nonce_root = Path(os.path.abspath(nonce_ledger_root)).resolve(strict=True)
    except OSError as exc:
        raise OuterWorkflowRuntimeError("workflow protected input is unavailable") from exc
    try:
        initial_root = assert_candidate_cannot_mutate_tree(
            initial_root,
            candidate_uid=candidate_uid,
        ).root
        candidate = assert_candidate_cannot_mutate_tree(
            candidate,
            candidate_uid=candidate_uid,
        ).root
        root = assert_candidate_cannot_mutate(root, candidate_uid=candidate_uid)
        key_evidence, _key_raw = read_protected_file(
            key,
            candidate_uid=candidate_uid,
            label="workflow private signing key",
            max_bytes=64 * 1024,
        )
        nonce_root = assert_candidate_cannot_mutate_tree(
            nonce_root,
            candidate_uid=candidate_uid,
        ).root
    except PreflightError as exc:
        raise OuterWorkflowRuntimeError(str(exc)) from exc
    if key_evidence.mode & 0o077 or key_evidence.mode & 0o222:
        raise OuterWorkflowRuntimeError(
            "workflow private signing key must be private and read-only"
        )
    key = key_evidence.path
    nonce_metadata = os.lstat(nonce_root)
    if (
        stat.S_IMODE(nonce_metadata.st_mode) != 0o700
        or nonce_metadata.st_uid != os.geteuid()
        or nonce_metadata.st_gid != os.getegid()
    ):
        raise OuterWorkflowRuntimeError(
            "attestation nonce ledger root must be private and launcher-owned"
        )
    _validate_broker_runtime_binding(broker_runtime_binding)
    broker_runtime_binding_sha256 = hashlib.sha256(broker_runtime_binding).hexdigest()
    if not request_path.is_relative_to(initial_root):
        raise OuterWorkflowRuntimeError("initial request must be inside its artifact root")
    if not root.is_dir() or stat.S_IMODE(os.lstat(root).st_mode) != 0o700 or any(root.iterdir()):
        raise OuterWorkflowRuntimeError(
            "workflow output root must be a new empty private directory"
        )
    initial_raw = request_path.read_bytes()
    validate_phase_request_bytes(initial_raw)
    if _canonical(validate_phase_request_bytes(initial_raw)) != initial_raw:
        raise OuterWorkflowRuntimeError("initial request is not canonical")
    _inspect_tree(initial_root)
    snapshot_store = _new_directory(root, "snapshot-artifacts")
    current_artifacts = initial_root
    active: dict[str, Any] = {}

    def prepare(phase: str, request_raw: bytes) -> bytes:
        if any(snapshot_store.iterdir()):
            _inspect_tree(snapshot_store)
        phase_root = _new_directory(root, f"{PHASE_ORDER.index(phase) + 1:02d}-{phase}")
        prepare_input = phase_root / "prepare-input"
        _copy_tree(current_artifacts, prepare_input)
        direct_request = prepare_input / "phase-request.json"
        if direct_request.exists():
            if direct_request.is_symlink() or direct_request.read_bytes() != request_raw:
                raise OuterWorkflowRuntimeError(
                    "workflow phase request differs from committed state"
                )
        else:
            _write_exclusive(direct_request, request_raw, maximum=128_000)
        if phase == "broker":
            _write_exclusive(
                prepare_input / "broker-runtime-binding.json",
                broker_runtime_binding,
                maximum=16_384,
            )
        _freeze_tree(prepare_input)
        prepare_output = _new_directory(phase_root, "prepare-output")
        call = CoordinatorWorkflowCall(
            phase=phase,
            operation="prepare",
            artifact_root=prepare_input,
            output_root=prepare_output,
            candidate_repo=(candidate if phase == "snapshot" else None),
            signing_key=(key if phase == "sign" else None),
            nonce_ledger_root=(nonce_root if phase == "attested-judge" else None),
            snapshot_artifact_root=(snapshot_store if any(snapshot_store.iterdir()) else None),
            command=_coordinator_command(
                phase=phase,
                operation="prepare",
                request_raw=request_raw,
                images=images,
                candidate_uid=candidate_uid,
                broker_ledger_identity_sha256=broker_ledger_identity_sha256,
                broker_runtime_binding_sha256=broker_runtime_binding_sha256,
            ),
        )
        prepared = coordinator_execute(call)
        snapshot_directory = (
            "snapshots"
            if phase == "snapshot"
            else "red-snapshots"
            if phase == "red-snapshot"
            else None
        )
        if snapshot_directory is not None:
            source = prepare_output / snapshot_directory
            if source.exists():
                _inspect_tree(source)
                destination = snapshot_store / snapshot_directory
                if destination.exists() or destination.is_symlink():
                    raise OuterWorkflowRuntimeError(
                        "workflow snapshot store destination must be new"
                    )
                try:
                    os.rename(source, destination)
                except OSError as exc:
                    raise OuterWorkflowRuntimeError(
                        "workflow snapshot output could not be isolated"
                    ) from exc
                _freeze_tree(destination)
            if phase == "red-snapshot":
                _freeze_tree(snapshot_store)
        _inspect_tree(prepare_output)
        active.clear()
        active.update(
            phase=phase,
            request_raw=request_raw,
            phase_root=phase_root,
            prepare_input=prepare_input,
            prepare_output=prepare_output,
            prepared_raw=prepared,
        )
        return prepared

    def run_offline(payload: bytes) -> bytes:
        artifact_source = (
            snapshot_store if any(snapshot_store.iterdir()) else active["prepare_input"]
        )
        return offline_execute(payload, artifact_source)

    def run_broker(payload: bytes) -> bytes:
        return broker_execute(payload)

    def finalize(phase: str, prepared_raw: bytes, evidence_raw: bytes) -> bytes:
        if (
            active.get("phase") != phase
            or active.get("prepared_raw") != prepared_raw
            or active.get("request_raw") is None
        ):
            raise OuterWorkflowRuntimeError("workflow finalize does not match its prepare call")
        phase_root = active["phase_root"]
        finalize_input = phase_root / "finalize-input"
        _copy_tree(active["prepare_input"], finalize_input)
        prepared_output_copy = finalize_input / "current-prepare-output"
        _copy_tree(active["prepare_output"], prepared_output_copy)
        _write_exclusive(
            finalize_input / "current-prepared-transition.json",
            prepared_raw,
        )
        _write_exclusive(
            finalize_input / "current-execution-evidence.json",
            evidence_raw,
        )
        _freeze_tree(finalize_input)
        finalize_output = _new_directory(phase_root, "finalize-output")
        call = CoordinatorWorkflowCall(
            phase=phase,
            operation="finalize",
            artifact_root=finalize_input,
            output_root=finalize_output,
            candidate_repo=None,
            signing_key=None,
            nonce_ledger_root=None,
            snapshot_artifact_root=(snapshot_store if any(snapshot_store.iterdir()) else None),
            command=_coordinator_command(
                phase=phase,
                operation="finalize",
                request_raw=active["request_raw"],
                images=images,
                candidate_uid=candidate_uid,
                broker_ledger_identity_sha256=broker_ledger_identity_sha256,
                broker_runtime_binding_sha256=broker_runtime_binding_sha256,
                prepared_raw=prepared_raw,
                evidence_raw=evidence_raw,
            ),
        )
        finalized = coordinator_execute(call)
        _inspect_tree(finalize_output)
        active.update(
            evidence_raw=evidence_raw,
            finalized_raw=finalized,
            finalize_output=finalize_output,
        )
        return finalized

    def commit(
        phase: str,
        request_raw: bytes,
        prepared_raw: bytes,
        external_raw: bytes,
        finalized_raw: bytes,
        finalized: FinalizedTransition,
    ) -> None:
        nonlocal current_artifacts
        if (
            active.get("phase") != phase
            or active.get("request_raw") != request_raw
            or active.get("prepared_raw") != prepared_raw
            or active.get("evidence_raw") != external_raw
            or active.get("finalized_raw") != finalized_raw
        ):
            raise OuterWorkflowRuntimeError(
                "workflow commit does not match its executed transition"
            )
        phase_root = active["phase_root"]
        _validate_snapshot_store_artifacts(phase, finalized, snapshot_store)
        committed = _new_directory(phase_root, "committed")
        _copy_tree(current_artifacts, committed / "prior-artifacts")
        _copy_tree(active["prepare_output"], committed / "prepare-output")
        _copy_tree(active["finalize_output"], committed / "coordinator-files")
        prepared = parse_prepared_transition(
            prepared_raw,
            request=validate_phase_request_bytes(request_raw),
        )
        _write_exclusive(committed / "phase-request-input.json", request_raw, maximum=128_000)
        _write_exclusive(committed / "prepared-transition.json", prepared_raw)
        _write_exclusive(committed / "prepared-payload.json", prepared.payload)
        if prepared.action["external_kind"] in {"offline", "broker"}:
            _write_exclusive(committed / "external-evidence.json", external_raw)
        if phase == "broker":
            _write_exclusive(
                committed / "broker-runtime-binding.json",
                broker_runtime_binding,
                maximum=16_384,
            )
        _write_exclusive(committed / "finalized-transition.json", finalized_raw)
        _write_exclusive(committed / "coordinator-output.json", finalized.coordinator_output)
        result_raw = _canonical(finalized.result)
        _write_exclusive(committed / "phase-result.json", result_raw)
        _write_exclusive(
            committed / "artifact-manifest.json",
            _canonical(finalized.result["artifacts"]),
        )
        if finalized.next_request is not None:
            _write_exclusive(
                committed / "phase-request.json",
                finalized.next_request,
                maximum=128_000,
            )
        _freeze_tree(committed)
        current_artifacts = committed
        _freeze_tree(phase_root)

    try:
        return run_fixed_workflow(
            initial_raw,
            coordinator_prepare=prepare,
            coordinator_finalize=finalize,
            offline_execute=run_offline,
            broker_execute=run_broker,
            transition_committed=commit,
        )
    except (OSError, OuterWorkflowStateError) as exc:
        raise OuterWorkflowRuntimeError("production workflow stopped fail-closed") from exc
