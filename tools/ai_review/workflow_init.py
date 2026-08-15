"""Credential-free creation of the first production workflow request.

The initializer is run by the trusted coordinator after a human approves the exact candidate
patch digest.  It never reads model credentials and never performs network I/O.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import re
import secrets
import stat
from dataclasses import dataclass
from pathlib import Path

from tools.ai_review.attestation import AttestationError
from tools.ai_review.attestation import load_trusted_public_key
from tools.ai_review.attestation import public_key_id
from tools.ai_review.path_safety import resolve_safe_output
from tools.ai_review.phase_protocol import EMPTY_INITIAL_ARTIFACTS_SHA256
from tools.ai_review.phase_protocol import PhaseRequest
from tools.ai_review.phase_protocol import canonical_json_bytes
from tools.ai_review.policy import GitInspectionError
from tools.ai_review.policy import inspect_git_diff
from tools.ai_review.preflight import RUNTIME_ASSET_MAX_BYTES
from tools.ai_review.preflight import PreflightError
from tools.ai_review.preflight import assert_candidate_cannot_mutate_tree
from tools.ai_review.preflight import preflight_runtime
from tools.ai_review.preflight import read_protected_file
from tools.ai_review.runtime_release import RuntimeReleaseError
from tools.ai_review.runtime_release import validate_release_task


_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_WORKFLOW_ID_DOMAIN = b"amazon-explorer-production-workflow-id-v1\0"
_REQUEST_FILENAME = "phase-request.json"


class WorkflowInitializationError(ValueError):
    """Raised before an unsafe or incompletely bound workflow can be created."""


@dataclass(frozen=True)
class WorkflowInitialization:
    """Non-secret evidence returned after the frozen request is durably created."""

    request: PhaseRequest
    phase_request_file_sha256: str

    def safe_digests(self) -> dict[str, str]:
        return {
            "candidate_sha256": self.request.candidate_sha256,
            "coordinator_key_id": self.request.coordinator_key_id,
            "coordinator_public_key_sha256": self.request.coordinator_public_key_sha256,
            "phase_request_file_sha256": self.phase_request_file_sha256,
            "request_sha256": self.request.request_sha256,
            "runtime_manifest_sha256": self.request.runtime_manifest_sha256,
            "task_sha256": self.request.task_sha256,
            "workflow_id": self.request.workflow_id,
        }


def _new_workflow_id(request_binding: dict[str, str]) -> str:
    entropy = secrets.token_bytes(32)
    return hashlib.sha256(
        _WORKFLOW_ID_DOMAIN + entropy + canonical_json_bytes(request_binding)
    ).hexdigest()


def _write_frozen_request(output_dir: Path, raw: bytes) -> Path:
    """Create one 0700/0600 artifact atomically, then freeze it to 0500/0400."""

    safe_dir = resolve_safe_output(output_dir)
    parent_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    parent_flags |= getattr(os, "O_NOFOLLOW", 0)
    directory_flags = parent_flags
    parent_fd = os.open(safe_dir.parent, parent_flags)
    directory_fd: int | None = None
    created = False
    file_created = False
    try:
        os.mkdir(safe_dir.name, 0o700, dir_fd=parent_fd)
        created = True
        directory_fd = os.open(safe_dir.name, directory_flags, dir_fd=parent_fd)
        directory_metadata = os.fstat(directory_fd)
        if (
            not stat.S_ISDIR(directory_metadata.st_mode)
            or stat.S_IMODE(directory_metadata.st_mode) != 0o700
        ):
            raise WorkflowInitializationError("workflow output directory was not created as 0700")

        file_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        file_fd = os.open(_REQUEST_FILENAME, file_flags, 0o600, dir_fd=directory_fd)
        file_created = True
        with os.fdopen(file_fd, "wb") as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
            if stat.S_IMODE(os.fstat(handle.fileno()).st_mode) != 0o600:
                raise WorkflowInitializationError("phase request was not created as 0600")
            os.fchmod(handle.fileno(), 0o400)

        os.fsync(directory_fd)
        os.fchmod(directory_fd, 0o500)
        os.fsync(parent_fd)
        named = os.stat(safe_dir, follow_symlinks=False)
        if (named.st_dev, named.st_ino) != (
            directory_metadata.st_dev,
            directory_metadata.st_ino,
        ):
            raise WorkflowInitializationError("workflow output directory changed during freeze")
        return safe_dir / _REQUEST_FILENAME
    except Exception:
        if directory_fd is not None:
            try:
                os.fchmod(directory_fd, 0o700)
            except OSError:
                pass
        if file_created and directory_fd is not None:
            try:
                os.unlink(_REQUEST_FILENAME, dir_fd=directory_fd)
            except OSError:
                pass
        if created:
            try:
                os.rmdir(safe_dir.name, dir_fd=parent_fd)
            except OSError:
                pass
        raise
    finally:
        if directory_fd is not None:
            os.close(directory_fd)
        os.close(parent_fd)


def initialize_workflow(
    *,
    task: Path,
    runtime_manifest: Path,
    expected_runtime_manifest_sha256: str,
    coordinator_public_key: Path,
    candidate_repo: Path,
    candidate_uid: int,
    expected_patch_sha256: str,
    output_dir: Path,
) -> WorkflowInitialization:
    """Create the first request after re-verifying every release and candidate binding."""

    if _SHA256_RE.fullmatch(expected_patch_sha256) is None:
        raise WorkflowInitializationError(
            "human-approved expected patch SHA-256 must be lowercase hexadecimal"
        )
    if _SHA256_RE.fullmatch(expected_runtime_manifest_sha256) is None:
        raise WorkflowInitializationError(
            "externally anchored runtime manifest SHA-256 must be lowercase hexadecimal"
        )
    try:
        manifest_evidence, _manifest_raw = read_protected_file(
            runtime_manifest,
            candidate_uid=candidate_uid,
            label="runtime manifest",
            expected_sha256=expected_runtime_manifest_sha256,
            max_bytes=RUNTIME_ASSET_MAX_BYTES["manifest"],
        )
        with preflight_runtime(
            manifest_path=manifest_evidence.path,
            expected_manifest_sha256=expected_runtime_manifest_sha256,
            candidate_uid=candidate_uid,
        ) as runtime:
            task_evidence, task_raw = read_protected_file(
                task,
                candidate_uid=candidate_uid,
                label="workflow TaskSpec",
                expected_sha256=runtime.task.sha256,
                max_bytes=RUNTIME_ASSET_MAX_BYTES["task"],
            )
            if task_evidence.path != runtime.task.path:
                raise WorkflowInitializationError(
                    "workflow task path differs from the runtime manifest"
                )
            key_evidence, _key_raw = read_protected_file(
                coordinator_public_key,
                candidate_uid=candidate_uid,
                label="workflow coordinator public key",
                expected_sha256=runtime.coordinator_public_key.sha256,
                max_bytes=RUNTIME_ASSET_MAX_BYTES["coordinator_public_key"],
            )
            if key_evidence.path != runtime.coordinator_public_key.path:
                raise WorkflowInitializationError(
                    "workflow public key path differs from the runtime manifest"
                )

            parsed_task = validate_release_task(
                task_raw,
                harness_sha256=runtime.harness.sha256,
            )
            public_key = load_trusted_public_key(
                key_evidence.path,
                expected_sha256=key_evidence.sha256,
                candidate_uid=candidate_uid,
            )
            candidate_before = assert_candidate_cannot_mutate_tree(
                candidate_repo,
                candidate_uid=candidate_uid,
            )
            output_absolute = Path(os.path.abspath(output_dir))
            if output_absolute == candidate_before.root or output_absolute.is_relative_to(
                candidate_before.root
            ):
                raise WorkflowInitializationError(
                    "workflow output directory must be outside the candidate repository"
                )
            policy = inspect_git_diff(
                candidate_before.root,
                parsed_task,
                task_sha256=task_evidence.sha256,
                expected_patch_sha256=expected_patch_sha256,
            )
            if not policy.passed or policy.patch_sha256 is None:
                details = "; ".join(policy.violations) or "candidate policy did not pass"
                raise WorkflowInitializationError(details)
            if not hmac.compare_digest(policy.patch_sha256, expected_patch_sha256):
                raise WorkflowInitializationError(
                    "candidate patch SHA-256 differs from human approval"
                )
            candidate_after = assert_candidate_cannot_mutate_tree(
                candidate_before.root,
                candidate_uid=candidate_uid,
            )
            if candidate_after != candidate_before:
                raise WorkflowInitializationError(
                    "candidate repository metadata changed during workflow initialization"
                )

            request_binding = {
                "candidate_sha256": policy.patch_sha256,
                "coordinator_key_id": public_key_id(public_key),
                "coordinator_public_key_sha256": key_evidence.sha256,
                "runtime_manifest_sha256": runtime.manifest_sha256,
                "task_sha256": task_evidence.sha256,
            }
            request = PhaseRequest.create(
                workflow_id=_new_workflow_id(request_binding),
                phase="snapshot",
                sequence=1,
                previous_phase_sha256=None,
                task_sha256=task_evidence.sha256,
                runtime_manifest_sha256=runtime.manifest_sha256,
                coordinator_key_id=request_binding["coordinator_key_id"],
                coordinator_public_key_sha256=key_evidence.sha256,
                candidate_sha256=policy.patch_sha256,
                candidate_snapshot_sha256=None,
                review_packet_sha256=None,
                input_artifacts_sha256=EMPTY_INITIAL_ARTIFACTS_SHA256,
            )
            raw = canonical_json_bytes(request)
            request_path = _write_frozen_request(output_dir, raw)
            stored = request_path.read_bytes()
            if stored != raw:
                raise WorkflowInitializationError("frozen phase request differs from creation")
            return WorkflowInitialization(
                request=request,
                phase_request_file_sha256=hashlib.sha256(stored).hexdigest(),
            )
    except WorkflowInitializationError:
        raise
    except (AttestationError, GitInspectionError, PreflightError, RuntimeReleaseError) as exc:
        raise WorkflowInitializationError(str(exc)) from exc
    except (OSError, ValueError) as exc:
        raise WorkflowInitializationError(str(exc)) from exc
