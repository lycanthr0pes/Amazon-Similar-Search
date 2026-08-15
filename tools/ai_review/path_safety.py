from __future__ import annotations

import os
import stat
from pathlib import Path

from tools.ai_review.sensitive_paths import sensitive_path_reason


def _sensitive_reason(path: Path) -> str | None:
    reason = sensitive_path_reason(path)
    return {
        "sensitive environment path": "environment file",
        "sensitive Streamlit secrets path": "Streamlit secrets file",
        "sensitive cache path": "application cache",
    }.get(reason, reason)


def _reject_sensitive_path(path: Path, operation: str) -> None:
    reason = _sensitive_reason(path)
    if reason is not None:
        raise ValueError(f"refusing to {operation} a {reason}")


def resolve_safe_input(path: Path) -> Path:
    """Resolve a regular input while rejecting every symlink component."""

    _reject_sensitive_path(path, "read")
    absolute = Path(os.path.abspath(path))
    if absolute.is_symlink():
        raise ValueError("refusing to read through a symlink")
    resolved = absolute.resolve(strict=True)
    if resolved != absolute:
        raise ValueError("refusing to read through a symlinked parent")
    _reject_sensitive_path(resolved, "read")
    if not resolved.is_file():
        raise ValueError("input path must resolve to a regular file")
    if resolved.stat().st_nlink != 1:
        raise ValueError("trusted input must not be a hardlink")
    return resolved


def resolve_safe_output(path: Path) -> Path:
    """Validate a new output in a private, symlink-free coordinator directory."""

    _reject_sensitive_path(path, "write")
    absolute = Path(os.path.abspath(path))
    if absolute.is_symlink():
        raise ValueError("refusing to write through a symlink")
    if absolute.exists():
        raise ValueError("refusing to overwrite an output that already exists")
    parent = absolute.parent
    resolved_parent = parent.resolve(strict=True)
    if resolved_parent != parent:
        raise ValueError("refusing to write through a symlinked parent")
    if not resolved_parent.is_dir():
        raise ValueError("output parent must be a directory")
    parent_stat = resolved_parent.stat()
    if hasattr(os, "getuid") and parent_stat.st_uid != os.getuid():
        raise ValueError("output parent must be owned by the coordinator user")
    if stat.S_IMODE(parent_stat.st_mode) & 0o077:
        raise ValueError("output parent must be private (mode 0700 or stricter)")
    resolved = resolved_parent / absolute.name
    _reject_sensitive_path(resolved, "write")
    return resolved


def write_text_exclusive(path: Path, text: str) -> Path:
    """Create a 0600 output exactly once without following links or hardlinks."""

    safe_path = resolve_safe_output(path)
    directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    directory_flags |= getattr(os, "O_NOFOLLOW", 0)
    directory_fd = os.open(safe_path.parent, directory_flags)
    created = False
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        file_fd = os.open(safe_path.name, flags, 0o600, dir_fd=directory_fd)
        created = True
        with os.fdopen(file_fd, "w", encoding="utf-8", newline="") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
    except Exception:
        if created:
            try:
                os.unlink(safe_path.name, dir_fd=directory_fd)
            except FileNotFoundError:
                pass
        raise
    finally:
        os.close(directory_fd)
    return safe_path


def ensure_trusted_coordinator_directory(cwd: Path) -> Path:
    """Validate a private, non-Git coordinator directory without instruction files."""

    absolute = Path(os.path.abspath(cwd))
    resolved = absolute.resolve(strict=True)
    if resolved != absolute:
        raise ValueError("trusted coordinator directory must not use symlinked parents")
    if not resolved.is_dir():
        raise ValueError("Codex working directory must be a directory")
    directory_stat = resolved.stat()
    if hasattr(os, "getuid") and directory_stat.st_uid != os.getuid():
        raise ValueError("trusted coordinator directory must be owned by the current user")
    if stat.S_IMODE(directory_stat.st_mode) & 0o077:
        raise ValueError("trusted coordinator directory must be private (mode 0700 or stricter)")

    for ancestor in (resolved, *resolved.parents):
        if any(
            (ancestor / name).exists() or (ancestor / name).is_symlink()
            for name in (".git", "AGENTS.md", "AGENTS.override.md")
        ):
            raise ValueError(
                "Codex requires a trusted coordinator directory outside candidate Git and "
                "AGENTS instruction scopes"
            )

    present: list[str] = []
    for root, directories, filenames in os.walk(resolved, followlinks=False):
        root_path = Path(root)
        for name in [*directories, *filenames]:
            candidate = root_path / name
            relative = candidate.relative_to(resolved)
            if candidate.is_symlink():
                present.append(f"{relative.as_posix()} (symlink)")
                continue
            if _sensitive_reason(relative) is not None:
                present.append(relative.as_posix())
            if name in {".git", "AGENTS.md", "AGENTS.override.md"}:
                present.append(f"{relative.as_posix()} (untrusted instructions)")
        directories[:] = [name for name in directories if not (root_path / name).is_symlink()]
    present = sorted(set(present))
    if present:
        raise ValueError(
            "Codex requires a secret-free trusted coordinator directory; remove or isolate: "
            + ", ".join(present)
        )
    return resolved


def ensure_readonly_artifact_directory(path: Path) -> Path:
    """Validate a frozen evidence input mounted into the coordinator image."""

    absolute = Path(os.path.abspath(path))
    resolved = absolute.resolve(strict=True)
    if resolved != absolute or not resolved.is_dir() or resolved.is_symlink():
        raise ValueError("coordinator artifact input must be a symlink-free directory")
    if stat.S_IMODE(resolved.stat().st_mode) & 0o222:
        raise ValueError("coordinator artifact input must be read-only")
    present: list[str] = []
    for root, directories, filenames in os.walk(resolved, followlinks=False):
        root_path = Path(root)
        if root_path.is_symlink() or stat.S_IMODE(root_path.stat().st_mode) & 0o222:
            raise ValueError("coordinator artifact input contains a writable directory")
        for name in [*directories, *filenames]:
            candidate = root_path / name
            relative = candidate.relative_to(resolved)
            if candidate.is_symlink():
                present.append(f"{relative.as_posix()} (symlink)")
                continue
            if _sensitive_reason(relative) is not None:
                present.append(relative.as_posix())
            if name in {".git", "AGENTS.md", "AGENTS.override.md"}:
                present.append(f"{relative.as_posix()} (untrusted instructions)")
            if candidate.is_file():
                metadata = candidate.stat()
                if metadata.st_nlink != 1 or stat.S_IMODE(metadata.st_mode) & 0o222:
                    raise ValueError("coordinator artifact input contains a mutable file")
        directories[:] = [name for name in directories if not (root_path / name).is_symlink()]
    if present:
        raise ValueError(
            "coordinator artifact input contains protected entries: "
            + ", ".join(sorted(set(present)))
        )
    return resolved
