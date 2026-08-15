from __future__ import annotations

import hashlib
import hmac
import io
import os
import re
import sys
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from tools.ai_review.path_safety import ensure_trusted_coordinator_directory
from tools.ai_review.path_safety import resolve_safe_input
from tools.ai_review.hashing import sha256_file
from tools.ai_review.preflight import PreflightError
from tools.ai_review.preflight import read_verified_fd_asset


SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")


class RuntimeTrustError(RuntimeError):
    """Raised when defense-in-depth checks detect an incorrectly started zipapp."""


@dataclass(frozen=True)
class TrustedRuntimeEvidence:
    zipapp_path: Path
    sha256: str
    executable: Path
    cwd: Path


def _inside(path: Path, directory: Path) -> bool:
    return path == directory or path.is_relative_to(directory)


def verify_trusted_zipapp(
    *,
    expected_sha256: str,
    candidate_repo: Path,
    zipapp_path: Path | None = None,
    executable: Path | None = None,
    cwd: Path | None = None,
    module_search_paths: Iterable[str] | None = None,
    isolated: bool | None = None,
    runtime_module_file: str | None = None,
) -> TrustedRuntimeEvidence:
    """Check an externally preflighted archive after import; this is not a trust anchor."""

    if SHA256_PATTERN.fullmatch(expected_sha256) is None:
        raise RuntimeTrustError("trusted harness SHA-256 must be 64 lowercase hexadecimal digits")
    if isolated is None:
        isolated = bool(sys.flags.isolated)
    if not isolated:
        raise RuntimeTrustError("trusted harness requires isolated Python (-I)")

    candidate = candidate_repo.resolve(strict=True)
    if not candidate.is_dir():
        raise RuntimeTrustError("candidate repository must be a directory")
    requested_archive = Path(zipapp_path or Path(sys.argv[0]))
    descriptor_archive = re.fullmatch(r"/proc/self/fd/(?:0|[1-9][0-9]*)", str(requested_archive))
    archive_bytes: bytes | None = None
    if descriptor_archive is not None:
        try:
            _archive_evidence, archive_bytes = read_verified_fd_asset(
                requested_archive,
                expected_sha256=expected_sha256,
                label="trusted harness",
                max_bytes=32 * 1024 * 1024,
            )
        except PreflightError as exc:
            raise RuntimeTrustError(str(exc)) from exc
        archive = requested_archive
        try:
            with zipfile.ZipFile(io.BytesIO(archive_bytes)) as candidate_archive:
                if "__main__.py" not in candidate_archive.namelist():
                    raise RuntimeTrustError("trusted harness must run from a zipapp (.pyz)")
        except (OSError, zipfile.BadZipFile) as exc:
            raise RuntimeTrustError("trusted harness must run from a zipapp (.pyz)") from exc
    else:
        archive = resolve_safe_input(requested_archive)
        if archive.suffix != ".pyz" or not zipfile.is_zipfile(archive):
            raise RuntimeTrustError("trusted harness must run from a zipapp (.pyz)")
        ensure_trusted_coordinator_directory(archive.parent)

    working_directory = ensure_trusted_coordinator_directory(cwd or Path.cwd())
    interpreter = (executable or Path(sys.executable)).resolve(strict=True)
    module_file = runtime_module_file or __file__
    archive_prefix = str(archive) + os.sep
    if not module_file.startswith(archive_prefix):
        raise RuntimeTrustError("AI review code was not imported from the trusted zipapp")

    protected_locations = {
        "trusted zipapp": archive,
        "coordinator cwd": working_directory,
        "Python executable": interpreter,
    }
    for label, location in protected_locations.items():
        if _inside(location, candidate):
            raise RuntimeTrustError(f"{label} must be outside the candidate repository")

    search_paths = list(sys.path if module_search_paths is None else module_search_paths)
    first_entry = str(search_paths[0] or working_directory) if search_paths else ""
    first_matches = (
        first_entry == str(archive)
        if descriptor_archive is not None
        else bool(search_paths) and Path(first_entry).resolve(strict=False) == archive
    )
    if not first_matches:
        raise RuntimeTrustError("trusted zipapp must be the first Python module search path")
    archive_present = False
    for entry in search_paths:
        raw_entry = str(entry or working_directory)
        resolved_entry = Path(raw_entry).resolve(strict=False)
        same_archive = (
            raw_entry == str(archive)
            if descriptor_archive is not None
            else resolved_entry == archive
        )
        if same_archive:
            archive_present = True
        if descriptor_archive is None and _inside(resolved_entry, candidate):
            raise RuntimeTrustError("Python module search path includes the candidate repository")
    if not archive_present:
        raise RuntimeTrustError("trusted zipapp is absent from the Python module search path")

    actual_sha256 = (
        hashlib.sha256(archive_bytes).hexdigest()
        if archive_bytes is not None
        else sha256_file(archive)
    )
    if not hmac.compare_digest(actual_sha256, expected_sha256):
        raise RuntimeTrustError("trusted harness SHA-256 does not match the task contract")
    return TrustedRuntimeEvidence(
        zipapp_path=archive,
        sha256=actual_sha256,
        executable=interpreter,
        cwd=working_directory,
    )
