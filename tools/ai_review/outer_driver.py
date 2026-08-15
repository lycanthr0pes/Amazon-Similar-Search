"""Root-owned phase driver that keeps container/runtime authority outside candidates."""

from __future__ import annotations

import os
import shutil
import stat
from pathlib import Path
from typing import Callable

from tools.ai_review.phase_protocol import ExternalExecute
from tools.ai_review.phase_protocol import PhaseAction
from tools.ai_review.phase_protocol import PhaseProtocolError
from tools.ai_review.phase_protocol import PhaseRequest
from tools.ai_review.phase_protocol import PhaseResult
from tools.ai_review.phase_protocol import SqlitePhaseLedger
from tools.ai_review.phase_protocol import canonical_json_bytes
from tools.ai_review.phase_protocol import run_claimed_phase
from tools.ai_review.preflight import PreflightError
from tools.ai_review.preflight import assert_candidate_cannot_mutate
from tools.ai_review.preflight import assert_candidate_cannot_mutate_tree
from tools.ai_review.preflight import read_protected_file


CoordinatorPrepare = Callable[..., tuple[PhaseAction, bytes]]
CoordinatorFinalize = Callable[..., bytes]


def _assert_readonly_artifact_tree(root: Path, *, candidate_uid: int) -> Path:
    try:
        tree = assert_candidate_cannot_mutate_tree(root, candidate_uid=candidate_uid)
    except PreflightError as exc:
        raise PhaseProtocolError(str(exc)) from exc
    for directory, _directories, filenames in os.walk(tree.root, followlinks=False):
        directory_path = Path(directory)
        if stat.S_IMODE(os.lstat(directory_path).st_mode) & 0o222:
            raise PhaseProtocolError("phase artifact input must be recursively read-only")
        for name in filenames:
            if stat.S_IMODE(os.lstat(directory_path / name).st_mode) & 0o222:
                raise PhaseProtocolError("phase artifact input must be recursively read-only")
    return tree.root


def _freeze_output_tree(root: Path) -> None:
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    directory_flag = getattr(os, "O_DIRECTORY", 0)

    def inspect_entry(parent_fd: int, name: str) -> tuple[os.stat_result, bool]:
        try:
            metadata = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        except OSError as exc:
            raise PhaseProtocolError("phase output changed while it was being inspected") from exc
        if stat.S_ISDIR(metadata.st_mode):
            return metadata, True
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise PhaseProtocolError(
                "phase output may not contain symlinks, hardlinks, or special files"
            )
        return metadata, False

    def validate_tree(directory_fd: int) -> None:
        try:
            names = sorted(os.listdir(directory_fd))
        except OSError as exc:
            raise PhaseProtocolError("phase output directory could not be inspected") from exc
        for name in names:
            expected, is_directory = inspect_entry(directory_fd, name)
            flags = os.O_RDONLY | nofollow | (directory_flag if is_directory else 0)
            try:
                child_fd = os.open(name, flags, dir_fd=directory_fd)
            except OSError as exc:
                raise PhaseProtocolError(
                    "phase output changed while it was being inspected"
                ) from exc
            try:
                actual = os.fstat(child_fd)
                if (actual.st_dev, actual.st_ino) != (expected.st_dev, expected.st_ino):
                    raise PhaseProtocolError("phase output changed while it was being inspected")
                if is_directory:
                    if not stat.S_ISDIR(actual.st_mode):
                        raise PhaseProtocolError("phase output entry changed type")
                    validate_tree(child_fd)
                elif not stat.S_ISREG(actual.st_mode) or actual.st_nlink != 1:
                    raise PhaseProtocolError("phase output hardlink is forbidden")
            finally:
                os.close(child_fd)

    def freeze_tree(directory_fd: int) -> None:
        for name in sorted(os.listdir(directory_fd)):
            expected, is_directory = inspect_entry(directory_fd, name)
            flags = os.O_RDONLY | nofollow | (directory_flag if is_directory else 0)
            try:
                child_fd = os.open(name, flags, dir_fd=directory_fd)
            except OSError as exc:
                raise PhaseProtocolError("phase output changed while it was being frozen") from exc
            try:
                actual = os.fstat(child_fd)
                if (actual.st_dev, actual.st_ino) != (expected.st_dev, expected.st_ino):
                    raise PhaseProtocolError("phase output changed while it was being frozen")
                if is_directory:
                    if not stat.S_ISDIR(actual.st_mode):
                        raise PhaseProtocolError("phase output entry changed type")
                    freeze_tree(child_fd)
                    os.fchmod(child_fd, 0o555)
                else:
                    if not stat.S_ISREG(actual.st_mode) or actual.st_nlink != 1:
                        raise PhaseProtocolError("phase output hardlink is forbidden")
                    os.fchmod(child_fd, 0o555 if actual.st_mode & 0o111 else 0o444)
            finally:
                os.close(child_fd)

    try:
        root_fd = os.open(root, os.O_RDONLY | directory_flag | nofollow)
    except OSError as exc:
        raise PhaseProtocolError("phase output root could not be opened safely") from exc
    try:
        validate_tree(root_fd)
        freeze_tree(root_fd)
        os.fchmod(root_fd, 0o555)
    finally:
        os.close(root_fd)


def _validate_prior_phase_input(
    artifact_input: Path,
    request: PhaseRequest,
) -> None:
    """Require the direct prior canonical result before carrying physical artifacts."""

    result_path = artifact_input / "phase-result.json"
    if not result_path.is_file() or result_path.is_symlink():
        raise PhaseProtocolError("post-snapshot artifact input lacks the prior phase result")
    try:
        raw = result_path.read_bytes()
        previous = PhaseResult.model_validate_json(raw)
    except Exception as exc:
        raise PhaseProtocolError("prior phase result is not strict canonical evidence") from exc
    if canonical_json_bytes(previous) != raw:
        raise PhaseProtocolError("prior phase result is not canonically encoded")
    if (
        previous.request.workflow_id != request.workflow_id
        or previous.request.sequence + 1 != request.sequence
        or previous.phase_sha256 != request.previous_phase_sha256
        or previous.output_artifacts_sha256 != request.input_artifacts_sha256
    ):
        raise PhaseProtocolError("artifact input does not match the requested prior phase")


def _carry_prior_artifacts(artifact_input: Path, phase_output: Path) -> None:
    """Copy the already-verified immutable input into the new cumulative phase tree."""

    destination = phase_output / "prior-artifacts"
    try:
        shutil.copytree(
            artifact_input,
            destination,
            symlinks=False,
            copy_function=shutil.copy2,
        )
    except OSError as exc:
        raise PhaseProtocolError("prior phase artifacts could not be carried forward") from exc


class OuterWorkflowDriver:
    """Consume and execute each phase while exposing only its allowed host handles."""

    def __init__(
        self,
        *,
        ledger: SqlitePhaseLedger,
        output_root: Path,
        candidate_uid: int,
    ) -> None:
        try:
            root = assert_candidate_cannot_mutate(output_root, candidate_uid=candidate_uid)
        except PreflightError as exc:
            raise PhaseProtocolError(str(exc)) from exc
        if not root.is_dir() or stat.S_IMODE(root.stat().st_mode) & 0o077:
            raise PhaseProtocolError("outer phase output root must be a private directory")
        self.ledger = ledger
        self.output_root = root
        self.candidate_uid = candidate_uid

    def _new_phase_output(self, request: PhaseRequest) -> Path:
        name = f"{request.sequence:02d}-{request.phase}"
        directory_fd = os.open(
            self.output_root,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        try:
            os.mkdir(name, 0o700, dir_fd=directory_fd)
            os.fsync(directory_fd)
        except OSError as exc:
            raise PhaseProtocolError("phase output directory must be new and exclusive") from exc
        finally:
            os.close(directory_fd)
        return self.output_root / name

    def run_phase(
        self,
        request: PhaseRequest,
        *,
        artifact_input_root: Path,
        coordinator_prepare: CoordinatorPrepare,
        coordinator_finalize: CoordinatorFinalize,
        offline_execute: ExternalExecute,
        broker_execute: ExternalExecute,
        candidate_repo: Path | None = None,
        signing_key: Path | None = None,
    ) -> tuple[PhaseResult, Path]:
        artifact_input = _assert_readonly_artifact_tree(
            artifact_input_root,
            candidate_uid=self.candidate_uid,
        )
        if request.sequence > 1:
            _validate_prior_phase_input(artifact_input, request)
        if (candidate_repo is not None) != (request.phase == "snapshot"):
            raise PhaseProtocolError("candidate repository is allowed only for snapshot phase")
        protected_candidate: Path | None = None
        if candidate_repo is not None:
            try:
                protected_candidate = assert_candidate_cannot_mutate_tree(
                    candidate_repo,
                    candidate_uid=self.candidate_uid,
                ).root
            except PreflightError as exc:
                raise PhaseProtocolError(str(exc)) from exc
        if (signing_key is not None) != (request.phase == "sign"):
            raise PhaseProtocolError("private signing key is allowed only for sign phase")
        protected_key: Path | None = None
        if signing_key is not None:
            try:
                evidence, _raw = read_protected_file(
                    signing_key,
                    candidate_uid=self.candidate_uid,
                    label="phase private signing key",
                    max_bytes=64 * 1024,
                )
            except PreflightError as exc:
                raise PhaseProtocolError(str(exc)) from exc
            if evidence.mode & 0o077 or evidence.mode & 0o222:
                raise PhaseProtocolError("private signing key must be private and read-only")
            protected_key = evidence.path
        phase_output = self._new_phase_output(request)
        if request.sequence > 1:
            _carry_prior_artifacts(artifact_input, phase_output)

        def prepare(value: PhaseRequest, *, mount_candidate: bool):
            if mount_candidate != (protected_candidate is not None):
                raise PhaseProtocolError("candidate mount decision changed inside outer driver")
            return coordinator_prepare(
                value,
                artifact_input_root=artifact_input,
                phase_output_root=phase_output,
                candidate_repo=protected_candidate,
                signing_key=protected_key,
            )

        def finalize(action: PhaseAction, evidence: bytes) -> bytes:
            return coordinator_finalize(
                action,
                evidence,
                artifact_input_root=artifact_input,
                phase_output_root=phase_output,
                candidate_repo=protected_candidate,
                signing_key=protected_key,
            )

        result = run_claimed_phase(
            request,
            ledger=self.ledger,
            output=phase_output / "phase-result.json",
            coordinator_prepare=prepare,
            coordinator_finalize=finalize,
            offline_execute=offline_execute,
            broker_execute=broker_execute,
        )
        _freeze_output_tree(phase_output)
        try:
            assert_candidate_cannot_mutate_tree(
                phase_output,
                candidate_uid=self.candidate_uid,
            )
        except PreflightError as exc:
            raise PhaseProtocolError(str(exc)) from exc
        return result, phase_output
