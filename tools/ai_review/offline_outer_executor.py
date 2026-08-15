"""Root-owned stdlib executor for coordinator-prepared offline batches."""

from __future__ import annotations

import hmac
from pathlib import Path
from typing import Any
from typing import Callable

from tools.ai_review.offline_phase_protocol import OfflinePhaseProtocolError
from tools.ai_review.offline_phase_protocol import canonical_outer_offline_evidence_bytes
from tools.ai_review.offline_phase_protocol import create_outer_offline_evidence
from tools.ai_review.offline_phase_protocol import parse_prepared_offline_batch
from tools.ai_review.offline_runner import execute_offline
from tools.ai_review.offline_runner import validate_offline_run_evidence
from tools.ai_review.snapshot import verify_readonly_snapshot


def execute_prepared_offline_outer(
    prepared_raw: bytes,
    *,
    artifact_root: Path,
    candidate_uid: int,
    which: Callable[[str], str | None] | None = None,
    probe: Callable[..., Any] | None = None,
    stream_runner: Callable[..., Any] | None = None,
    cleanup: Callable[..., bool] | None = None,
) -> bytes:
    """Execute only the exact canonical batch emitted by the pinned coordinator.

    Runtime callbacks exist for deterministic tests.  Production callers omit
    them and therefore use the audited runtime detection, bounded stream reader,
    and mandatory named-container cleanup in :func:`execute_offline`.
    """

    prepared = parse_prepared_offline_batch(prepared_raw)
    artifact_root = Path(artifact_root).resolve(strict=True)
    evidence = []
    for run in prepared.runs:
        try:
            snapshot_root = artifact_root.joinpath(*Path(run.snapshot_ref).parts).resolve(
                strict=True
            )
        except OSError as exc:
            raise OfflinePhaseProtocolError(
                "prepared offline snapshot is unavailable to the outer executor"
            ) from exc
        if not snapshot_root.is_relative_to(artifact_root):
            raise OfflinePhaseProtocolError("prepared offline snapshot escaped artifact root")
        before = verify_readonly_snapshot(snapshot_root, candidate_uid=candidate_uid)
        if not hmac.compare_digest(before.snapshot_sha256, run.execution_snapshot_sha256):
            raise OfflinePhaseProtocolError("prepared offline snapshot digest changed")
        kwargs: dict[str, object] = {
            "snapshot_root": before.root,
            "image": prepared.image,
            "approved_image_digest": prepared.approved_image_digest,
            "command": run.command,
            "phase": run.phase,
            "acceptance_test_id": run.acceptance_test_id,
            "session_id": run.session_id,
            "task_sha256": prepared.task_sha256,
            "candidate_sha256": prepared.candidate_sha256,
            "source_snapshot_sha256": run.source_snapshot_sha256,
            "test_patch_sha256": run.test_patch_sha256,
            "test_manifest_sha256": run.test_manifest_sha256,
            "candidate_snapshot_sha256": run.candidate_snapshot_sha256,
            "candidate_uid": candidate_uid,
            "timeout_seconds": prepared.timeout_seconds,
            "max_log_bytes": prepared.max_log_bytes,
        }
        if which is not None:
            kwargs["which"] = which
        if probe is not None:
            kwargs["probe"] = probe
        if stream_runner is not None:
            kwargs["stream_runner"] = stream_runner
        if cleanup is not None:
            kwargs["cleanup"] = cleanup
        measured = execute_offline(**kwargs)
        validate_offline_run_evidence(
            measured,
            execution_snapshot=before,
            image=prepared.image,
            approved_image_digest=prepared.approved_image_digest,
            candidate_uid=candidate_uid,
            expected_mount_source=before.tree,
        )
        after = verify_readonly_snapshot(snapshot_root, candidate_uid=candidate_uid)
        if after != before:
            raise OfflinePhaseProtocolError("offline snapshot changed during outer execution")
        evidence.append(measured)
    return canonical_outer_offline_evidence_bytes(create_outer_offline_evidence(prepared, evidence))
