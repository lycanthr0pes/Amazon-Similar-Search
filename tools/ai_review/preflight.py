"""Stdlib-only, import-before-exec trust checks for the AI review runtime.

This module is intended to be installed as part of an external launcher.  It must
be imported before the harness zipapp, and the launcher's own integrity must be
anchored by the host (for example a root-owned image or signed package).
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import re
import stat
import zipfile
from dataclasses import dataclass
from dataclasses import field
from pathlib import Path
from typing import Any
from typing import Callable
from typing import Iterable


SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
IMAGE_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
MAX_BROKER_PACKET_RESERVATION_TOKENS = 1_088_000
MAX_BROKER_PACKET_COST_MICROUSD = 7_940_000
RUNTIME_ASSET_NAMES = (
    "python",
    "harness",
    "task",
    "dependency_lock",
    "schema_bundle",
    "coordinator_public_key",
    "broker_egress_policy",
    "openai_pricing_policy",
)
MAX_PROTECTED_FILE_BYTES = 512 * 1024 * 1024
RUNTIME_ASSET_MAX_BYTES = {
    "manifest": 64 * 1024,
    "python": 128 * 1024 * 1024,
    "harness": 32 * 1024 * 1024,
    "task": 2 * 1024 * 1024,
    "dependency_lock": 16 * 1024 * 1024,
    "schema_bundle": 16 * 1024 * 1024,
    "coordinator_public_key": 64 * 1024,
    "broker_egress_policy": 64 * 1024,
    "openai_pricing_policy": 64 * 1024,
}
MAX_PROTECTED_TREE_ENTRIES = 200_000
MAX_PROTECTED_TREE_BYTES = 512 * 1024 * 1024
MAX_PROTECTED_TREE_FILE_BYTES = 128 * 1024 * 1024
STABLE_FILE_STAT_FIELDS = (
    "st_dev",
    "st_ino",
    "st_mode",
    "st_uid",
    "st_gid",
    "st_size",
    "st_mtime_ns",
    "st_ctime_ns",
    "st_nlink",
)


class PreflightError(RuntimeError):
    """Raised before any candidate or harness code is imported or executed."""


@dataclass(frozen=True)
class RawAssetEvidence:
    path: Path
    sha256: str
    size: int
    device: int
    inode: int
    uid: int
    mode: int


@dataclass(frozen=True)
class ProtectedTreeLimits:
    max_entries: int = MAX_PROTECTED_TREE_ENTRIES
    max_total_bytes: int = MAX_PROTECTED_TREE_BYTES
    max_file_bytes: int = MAX_PROTECTED_TREE_FILE_BYTES


@dataclass(frozen=True)
class ProtectedTreeEvidence:
    root: Path
    candidate_uid: int
    device: int
    entry_count: int
    total_bytes: int


@dataclass
class RuntimePreflightEvidence:
    manifest_path: Path
    manifest_sha256: str
    candidate_uid: int
    python: RawAssetEvidence
    harness: RawAssetEvidence
    task: RawAssetEvidence
    dependency_lock: RawAssetEvidence
    schema_bundle: RawAssetEvidence
    coordinator_public_key: RawAssetEvidence
    broker_egress_policy: RawAssetEvidence
    openai_pricing_policy: RawAssetEvidence
    coordinator_image_digest: str
    offline_runner_image_digest: str
    broker_image_digest: str
    broker_gateway_image_digest: str
    broker_packet_reservation_limit: int
    broker_packet_cost_limit_microusd: int
    _file_descriptors: dict[str, int] = field(repr=False, compare=False)
    _closed: bool = field(default=False, init=False, repr=False, compare=False)

    def fd_path(self, name: str) -> str:
        """Return a Linux procfs path bound to the already-hashed open inode."""

        if self._closed:
            raise PreflightError("runtime preflight evidence is already closed")
        try:
            descriptor = self._file_descriptors[name]
        except KeyError as exc:
            raise PreflightError(f"runtime asset has no verified file descriptor: {name}") from exc
        try:
            os.fstat(descriptor)
        except OSError as exc:
            raise PreflightError(f"verified runtime descriptor is no longer open: {name}") from exc
        proc_path = f"/proc/self/fd/{descriptor}"
        if not Path(proc_path).exists():
            raise PreflightError("verified descriptor execution requires Linux /proc/self/fd")
        return proc_path

    def close(self) -> None:
        if self._closed:
            return
        for descriptor in self._file_descriptors.values():
            try:
                os.close(descriptor)
            except OSError:
                pass
        self._closed = True

    def __enter__(self) -> RuntimePreflightEvidence:
        return self

    def __exit__(self, _exc_type, _exc, _traceback) -> None:
        self.close()


def ensure_separate_candidate_uid(candidate_uid: int) -> None:
    """Require a real OS identity boundary; mode bits cannot isolate one UID from itself."""

    if isinstance(candidate_uid, bool) or not isinstance(candidate_uid, int) or candidate_uid < 0:
        raise PreflightError("candidate UID must be a non-negative integer")
    if hasattr(os, "geteuid") and candidate_uid == os.geteuid():
        raise PreflightError("coordinator and candidate require a different OS UID")
    if candidate_uid == 0:
        raise PreflightError("candidate execution as root is forbidden")


def _candidate_may_write(metadata: os.stat_result, candidate_uid: int) -> bool:
    mode = stat.S_IMODE(metadata.st_mode)
    if metadata.st_uid == candidate_uid and mode & stat.S_IWUSR:
        return True
    # Candidate supplementary groups are intentionally not accepted as an input.  Treat every
    # group-writable object as reachable by the candidate and fail closed.
    return bool(mode & (stat.S_IWGRP | stat.S_IWOTH))


def _candidate_may_replace(
    *, parent: os.stat_result, child: os.stat_result, candidate_uid: int
) -> bool:
    if not _candidate_may_write(parent, candidate_uid):
        return False
    sticky = bool(stat.S_IMODE(parent.st_mode) & stat.S_ISVTX)
    if not sticky:
        return True
    # In a sticky directory (normally /tmp), a different unprivileged UID cannot rename or
    # unlink a child owned by the coordinator or directory owner.
    return candidate_uid in {parent.st_uid, child.st_uid}


def assert_candidate_cannot_mutate(path: Path, *, candidate_uid: int) -> Path:
    """Validate ownership, permissions, and every path component without following links."""

    ensure_separate_candidate_uid(candidate_uid)
    absolute = Path(os.path.abspath(path))
    if not absolute.is_absolute() or absolute == Path(absolute.anchor):
        raise PreflightError("protected asset path must name a non-root absolute path")

    try:
        parent_metadata = os.lstat(absolute.anchor)
        current = Path(absolute.anchor)
        for part in absolute.parts[1:]:
            current = current / part
            child_metadata = os.lstat(current)
            if stat.S_ISLNK(child_metadata.st_mode):
                raise PreflightError(f"protected path must not contain symlinks: {current}")
            try:
                extended_attributes = set(os.listxattr(current, follow_symlinks=False))
            except OSError as exc:
                raise PreflightError("protected path ACL state could not be inspected") from exc
            if extended_attributes & {"system.posix_acl_access", "system.posix_acl_default"}:
                raise PreflightError("protected path must not use POSIX ACL permissions")
            if _candidate_may_replace(
                parent=parent_metadata,
                child=child_metadata,
                candidate_uid=candidate_uid,
            ):
                raise PreflightError(
                    f"candidate UID can replace a protected path component: {current}"
                )
            parent_metadata = child_metadata
    except FileNotFoundError as exc:
        raise PreflightError("protected asset path does not exist") from exc
    except OSError as exc:
        raise PreflightError("protected asset path could not be inspected safely") from exc

    metadata = os.lstat(absolute)
    if _candidate_may_write(metadata, candidate_uid):
        raise PreflightError("candidate UID can modify a protected asset")
    if metadata.st_uid == candidate_uid:
        raise PreflightError("candidate UID must not own a protected asset")
    return absolute


def _validate_tree_limits(limits: ProtectedTreeLimits) -> None:
    values = (
        ("entry", limits.max_entries, MAX_PROTECTED_TREE_ENTRIES),
        ("total byte", limits.max_total_bytes, MAX_PROTECTED_TREE_BYTES),
        ("file byte", limits.max_file_bytes, MAX_PROTECTED_TREE_FILE_BYTES),
    )
    for label, value, maximum in values:
        if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= maximum:
            raise PreflightError(f"protected tree {label} limit is invalid")
    if limits.max_file_bytes > limits.max_total_bytes:
        raise PreflightError("protected tree file limit must not exceed its total byte limit")


def _assert_tree_entry_protected(
    path: Path,
    metadata: os.stat_result,
    *,
    candidate_uid: int,
    root_device: int,
    same_device: bool,
) -> None:
    if stat.S_ISLNK(metadata.st_mode):
        raise PreflightError(f"protected tree must not contain symlinks: {path}")
    if not (stat.S_ISDIR(metadata.st_mode) or stat.S_ISREG(metadata.st_mode)):
        raise PreflightError(f"protected tree contains an unsupported entry: {path}")
    if same_device and metadata.st_dev != root_device:
        raise PreflightError(f"protected tree must not cross a nested filesystem mount: {path}")
    if metadata.st_uid == candidate_uid:
        raise PreflightError(f"candidate UID owns a protected tree entry: {path}")
    if _candidate_may_write(metadata, candidate_uid):
        raise PreflightError(f"candidate UID can modify a protected tree entry: {path}")
    if stat.S_ISREG(metadata.st_mode) and metadata.st_nlink != 1:
        raise PreflightError(f"protected tree files must not be hardlinks: {path}")
    try:
        extended_attributes = set(os.listxattr(path, follow_symlinks=False))
    except OSError as exc:
        raise PreflightError("protected tree ACL state could not be inspected") from exc
    if extended_attributes & {"system.posix_acl_access", "system.posix_acl_default"}:
        raise PreflightError(f"protected tree entries must not use POSIX ACL permissions: {path}")


def assert_candidate_cannot_mutate_tree(
    root: Path,
    *,
    candidate_uid: int,
    limits: ProtectedTreeLimits | None = None,
    same_device: bool = True,
) -> ProtectedTreeEvidence:
    """Recursively protect a coordinator-owned worktree, including its standalone ``.git``.

    This is a metadata/identity assertion, not a content snapshot.  A trusted coordinator can run
    it immediately before and after Git policy inspection while separately binding ``HEAD`` to the
    immutable candidate snapshot commit.
    """

    if not isinstance(same_device, bool):
        raise PreflightError("protected tree same_device flag must be boolean")
    selected_limits = limits or ProtectedTreeLimits()
    if not isinstance(selected_limits, ProtectedTreeLimits):
        raise PreflightError("protected tree limits must use ProtectedTreeLimits")
    _validate_tree_limits(selected_limits)
    absolute = assert_candidate_cannot_mutate(root, candidate_uid=candidate_uid)
    root_metadata = os.lstat(absolute)
    if not stat.S_ISDIR(root_metadata.st_mode):
        raise PreflightError("protected tree root must be a directory")
    root_device = root_metadata.st_dev
    _assert_tree_entry_protected(
        absolute,
        root_metadata,
        candidate_uid=candidate_uid,
        root_device=root_device,
        same_device=same_device,
    )

    entry_count = 0
    total_bytes = 0
    for directory, directories, filenames in os.walk(absolute, followlinks=False):
        directory_path = Path(directory)
        directory_metadata = os.lstat(directory_path)
        _assert_tree_entry_protected(
            directory_path,
            directory_metadata,
            candidate_uid=candidate_uid,
            root_device=root_device,
            same_device=same_device,
        )
        for name in [*directories, *filenames]:
            entry_count += 1
            if entry_count > selected_limits.max_entries:
                raise PreflightError("protected tree exceeds the entry limit")
            child = directory_path / name
            metadata = os.lstat(child)
            _assert_tree_entry_protected(
                child,
                metadata,
                candidate_uid=candidate_uid,
                root_device=root_device,
                same_device=same_device,
            )
            if stat.S_ISREG(metadata.st_mode):
                if metadata.st_size > selected_limits.max_file_bytes:
                    raise PreflightError(f"protected tree file exceeds the byte limit: {child}")
                total_bytes += metadata.st_size
                if total_bytes > selected_limits.max_total_bytes:
                    raise PreflightError("protected tree exceeds the total byte limit")

    return ProtectedTreeEvidence(
        root=absolute,
        candidate_uid=candidate_uid,
        device=root_device,
        entry_count=entry_count,
        total_bytes=total_bytes,
    )


def _open_regular_nofollow(path: Path) -> int:
    absolute = Path(os.path.abspath(path))
    components = absolute.parts[1:]
    if not components:
        raise PreflightError("protected asset must be a regular file")
    directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    directory_flags |= getattr(os, "O_NOFOLLOW", 0)
    file_flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    directory_fd = os.open(absolute.anchor, directory_flags)
    try:
        for component in components[:-1]:
            next_fd = os.open(component, directory_flags, dir_fd=directory_fd)
            os.close(directory_fd)
            directory_fd = next_fd
        return os.open(components[-1], file_flags, dir_fd=directory_fd)
    except OSError as exc:
        raise PreflightError("protected asset path contains a symlink or unsafe component") from exc
    finally:
        os.close(directory_fd)


def _read_protected_file_open(
    path: Path,
    *,
    candidate_uid: int,
    label: str,
    expected_sha256: str | None = None,
    max_bytes: int = MAX_PROTECTED_FILE_BYTES,
) -> tuple[RawAssetEvidence, bytes, int]:
    """Hash a raw regular file through no-follow descriptors and detect concurrent mutation."""

    if expected_sha256 is not None and SHA256_RE.fullmatch(expected_sha256) is None:
        raise PreflightError(f"{label} expected SHA-256 must be lowercase hexadecimal")
    if (
        isinstance(max_bytes, bool)
        or not isinstance(max_bytes, int)
        or not 1 <= max_bytes <= MAX_PROTECTED_FILE_BYTES
    ):
        raise PreflightError(f"{label} byte limit is invalid")
    absolute = assert_candidate_cannot_mutate(path, candidate_uid=candidate_uid)
    descriptor = _open_regular_nofollow(absolute)
    succeeded = False
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise PreflightError(f"{label} must be a regular file")
        if before.st_nlink != 1:
            raise PreflightError(f"{label} must not be a hardlink")
        if before.st_size > max_bytes:
            raise PreflightError(f"{label} exceeds the byte limit")
        named = os.stat(absolute, follow_symlinks=False)
        if (named.st_dev, named.st_ino) != (before.st_dev, before.st_ino):
            raise PreflightError(f"{label} path changed during preflight")

        chunks: list[bytes] = []
        digest = hashlib.sha256()
        while chunk := os.read(descriptor, 1024 * 1024):
            chunks.append(chunk)
            digest.update(chunk)
        after = os.fstat(descriptor)
        if any(
            getattr(before, field) != getattr(after, field) for field in STABLE_FILE_STAT_FIELDS
        ):
            raise PreflightError(f"{label} changed while it was being hashed")
        assert_candidate_cannot_mutate(absolute, candidate_uid=candidate_uid)
        named_after = os.stat(absolute, follow_symlinks=False)
        if (named_after.st_dev, named_after.st_ino) != (after.st_dev, after.st_ino):
            raise PreflightError(f"{label} path changed after hashing")

        actual = digest.hexdigest()
        if expected_sha256 is not None and actual != expected_sha256:
            raise PreflightError(f"{label} SHA-256 does not match the trusted runtime manifest")
        os.set_inheritable(descriptor, True)
        result = (
            RawAssetEvidence(
                path=absolute,
                sha256=actual,
                size=after.st_size,
                device=after.st_dev,
                inode=after.st_ino,
                uid=after.st_uid,
                mode=stat.S_IMODE(after.st_mode),
            ),
            b"".join(chunks),
            descriptor,
        )
        succeeded = True
        return result
    finally:
        if not succeeded:
            os.close(descriptor)


def read_protected_file(
    path: Path,
    *,
    candidate_uid: int,
    label: str,
    expected_sha256: str | None = None,
    max_bytes: int = MAX_PROTECTED_FILE_BYTES,
) -> tuple[RawAssetEvidence, bytes]:
    """Read a protected file and close its stable descriptor after validation."""

    evidence, raw, descriptor = _read_protected_file_open(
        path,
        candidate_uid=candidate_uid,
        label=label,
        expected_sha256=expected_sha256,
        max_bytes=max_bytes,
    )
    os.close(descriptor)
    return evidence, raw


def read_verified_fd_asset(
    proc_fd_path: str | Path,
    *,
    expected_sha256: str,
    label: str,
    max_bytes: int = MAX_PROTECTED_FILE_BYTES,
) -> tuple[RawAssetEvidence, bytes]:
    """Read one exact held ``/proc/self/fd/N`` without following a pathname symlink.

    The caller must supply a digest anchored by the external runtime manifest.  Positional reads
    leave the inherited descriptor offset unchanged, allowing multiple trusted consumers.
    """

    raw_path = str(proc_fd_path)
    match = re.fullmatch(r"/proc/self/fd/(0|[1-9][0-9]*)", raw_path)
    if match is None:
        raise PreflightError(f"{label} must use an exact /proc/self/fd/N path")
    if SHA256_RE.fullmatch(expected_sha256) is None:
        raise PreflightError(f"{label} expected SHA-256 must be lowercase hexadecimal")
    if (
        isinstance(max_bytes, bool)
        or not isinstance(max_bytes, int)
        or not 1 <= max_bytes <= MAX_PROTECTED_FILE_BYTES
    ):
        raise PreflightError(f"{label} byte limit is invalid")
    descriptor = int(match.group(1))
    try:
        before = os.fstat(descriptor)
    except OSError as exc:
        raise PreflightError(f"{label} verified descriptor is not open") from exc
    if not stat.S_ISREG(before.st_mode):
        raise PreflightError(f"{label} verified descriptor must be a regular file")
    if before.st_nlink != 1:
        raise PreflightError(f"{label} verified descriptor must not be a hardlink")
    if before.st_size > max_bytes:
        raise PreflightError(f"{label} exceeds the byte limit")
    if not hasattr(os, "pread"):
        raise PreflightError("verified descriptor reads require POSIX pread")

    chunks: list[bytes] = []
    digest = hashlib.sha256()
    offset = 0
    try:
        while offset < before.st_size:
            chunk = os.pread(descriptor, min(1024 * 1024, before.st_size - offset), offset)
            if not chunk:
                raise PreflightError(f"{label} became shorter during verified descriptor read")
            chunks.append(chunk)
            digest.update(chunk)
            offset += len(chunk)
        after = os.fstat(descriptor)
    except OSError as exc:
        raise PreflightError(f"{label} verified descriptor could not be read") from exc
    if any(getattr(before, field) != getattr(after, field) for field in STABLE_FILE_STAT_FIELDS):
        raise PreflightError(f"{label} changed during verified descriptor read")
    actual_sha256 = digest.hexdigest()
    if actual_sha256 != expected_sha256:
        raise PreflightError(f"{label} SHA-256 does not match its trusted binding")
    return (
        RawAssetEvidence(
            path=Path(raw_path),
            sha256=actual_sha256,
            size=after.st_size,
            device=after.st_dev,
            inode=after.st_ino,
            uid=after.st_uid,
            mode=stat.S_IMODE(after.st_mode),
        ),
        b"".join(chunks),
    )


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise PreflightError(f"duplicate JSON key in runtime manifest: {key}")
        result[key] = value
    return result


def _parse_manifest(raw: bytes) -> dict[str, Any]:
    try:
        payload = json.loads(raw.decode("utf-8"), object_pairs_hook=_reject_duplicate_keys)
    except PreflightError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PreflightError("runtime manifest must be valid UTF-8 JSON") from exc
    if not isinstance(payload, dict):
        raise PreflightError("runtime manifest must be a JSON object")
    if set(payload) != {
        "schema_version",
        *RUNTIME_ASSET_NAMES,
        "coordinator_image_digest",
        "offline_runner_image_digest",
        "broker_image_digest",
        "broker_gateway_image_digest",
        "broker_packet_reservation_limit",
        "broker_packet_cost_limit_microusd",
    }:
        raise PreflightError("runtime manifest contains missing or unknown fields")
    if payload["schema_version"] != "1.0":
        raise PreflightError("unsupported runtime manifest schema version")
    for name in RUNTIME_ASSET_NAMES:
        asset = payload[name]
        if not isinstance(asset, dict) or set(asset) != {"path", "sha256"}:
            raise PreflightError(f"runtime manifest {name} entry is invalid")
        if not isinstance(asset["path"], str) or not Path(asset["path"]).is_absolute():
            raise PreflightError(f"runtime manifest {name} path must be absolute")
        if "\x00" in asset["path"]:
            raise PreflightError(f"runtime manifest {name} path contains NUL")
        if not isinstance(asset["sha256"], str) or SHA256_RE.fullmatch(asset["sha256"]) is None:
            raise PreflightError(f"runtime manifest {name} SHA-256 is invalid")
    for name in (
        "coordinator_image_digest",
        "offline_runner_image_digest",
        "broker_image_digest",
        "broker_gateway_image_digest",
    ):
        if not isinstance(payload[name], str) or IMAGE_DIGEST_RE.fullmatch(payload[name]) is None:
            raise PreflightError(f"runtime manifest {name} is invalid")
    image_digests = {
        payload["coordinator_image_digest"],
        payload["offline_runner_image_digest"],
        payload["broker_image_digest"],
        payload["broker_gateway_image_digest"],
    }
    if len(image_digests) != 4:
        raise PreflightError(
            "coordinator, offline runner, broker, and egress gateway images must be distinct"
        )
    reservation_limit = payload["broker_packet_reservation_limit"]
    if (
        isinstance(reservation_limit, bool)
        or not isinstance(reservation_limit, int)
        or not 1 <= reservation_limit <= MAX_BROKER_PACKET_RESERVATION_TOKENS
    ):
        raise PreflightError("runtime manifest broker packet reservation limit is invalid")
    cost_limit = payload["broker_packet_cost_limit_microusd"]
    if (
        isinstance(cost_limit, bool)
        or not isinstance(cost_limit, int)
        or not 1 <= cost_limit <= MAX_BROKER_PACKET_COST_MICROUSD
    ):
        raise PreflightError("runtime manifest broker packet cost limit is invalid")
    return payload


def _validate_zipapp(raw: bytes) -> None:
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            names = archive.namelist()
            if "__main__.py" not in names or archive.testzip() is not None:
                raise PreflightError("trusted harness is not a valid runnable zipapp")
    except (OSError, zipfile.BadZipFile) as exc:
        raise PreflightError("trusted harness is not a valid runnable zipapp") from exc


def preflight_runtime(
    *, manifest_path: Path, expected_manifest_sha256: str, candidate_uid: int
) -> RuntimePreflightEvidence:
    """Verify manifest, Python, task, and zipapp bytes before importing the zipapp."""

    ensure_separate_candidate_uid(candidate_uid)
    held_descriptors: dict[str, int] = {}
    assets: dict[str, RawAssetEvidence] = {}
    raw_assets: dict[str, bytes] = {}
    try:
        manifest, raw_manifest, manifest_fd = _read_protected_file_open(
            manifest_path,
            candidate_uid=candidate_uid,
            label="runtime manifest",
            expected_sha256=expected_manifest_sha256,
            max_bytes=RUNTIME_ASSET_MAX_BYTES["manifest"],
        )
        held_descriptors["manifest"] = manifest_fd
        payload = _parse_manifest(raw_manifest)
        for name in RUNTIME_ASSET_NAMES:
            asset, raw, descriptor = _read_protected_file_open(
                Path(payload[name]["path"]),
                candidate_uid=candidate_uid,
                label=name,
                expected_sha256=payload[name]["sha256"],
                max_bytes=RUNTIME_ASSET_MAX_BYTES[name],
            )
            held_descriptors[name] = descriptor
            assets[name] = asset
            raw_assets[name] = raw

        if not assets["python"].mode & 0o111:
            raise PreflightError("trusted Python must have an executable mode bit")
        if assets["python"].mode & (stat.S_ISUID | stat.S_ISGID):
            raise PreflightError("trusted Python must not be setuid or setgid")
        if assets["harness"].path.suffix != ".pyz":
            raise PreflightError("trusted harness must use the .pyz suffix")
        _validate_zipapp(raw_assets["harness"])
        for name, descriptor in held_descriptors.items():
            try:
                position = os.lseek(descriptor, 0, os.SEEK_SET)
            except OSError as exc:
                raise PreflightError(
                    f"verified runtime descriptor could not be rewound: {name}"
                ) from exc
            if position != 0:
                raise PreflightError(f"verified runtime descriptor did not rewind: {name}")
        return RuntimePreflightEvidence(
            manifest_path=manifest.path,
            manifest_sha256=manifest.sha256,
            candidate_uid=candidate_uid,
            python=assets["python"],
            harness=assets["harness"],
            task=assets["task"],
            dependency_lock=assets["dependency_lock"],
            schema_bundle=assets["schema_bundle"],
            coordinator_public_key=assets["coordinator_public_key"],
            broker_egress_policy=assets["broker_egress_policy"],
            openai_pricing_policy=assets["openai_pricing_policy"],
            coordinator_image_digest=payload["coordinator_image_digest"],
            offline_runner_image_digest=payload["offline_runner_image_digest"],
            broker_image_digest=payload["broker_image_digest"],
            broker_gateway_image_digest=payload["broker_gateway_image_digest"],
            broker_packet_reservation_limit=payload["broker_packet_reservation_limit"],
            broker_packet_cost_limit_microusd=payload["broker_packet_cost_limit_microusd"],
            _file_descriptors=held_descriptors,
        )
    except Exception:
        for descriptor in held_descriptors.values():
            try:
                os.close(descriptor)
            except OSError:
                pass
        raise


def build_isolated_zipapp_argv(
    evidence: RuntimePreflightEvidence, arguments: Iterable[str]
) -> tuple[str, ...]:
    """Build an exec-form argv only after successful raw preflight."""

    values = tuple(arguments)
    if any(not isinstance(value, str) or not value or "\x00" in value for value in values):
        raise PreflightError("zipapp arguments must be non-empty strings without NUL")
    return (
        evidence.fd_path("python"),
        "-I",
        evidence.fd_path("harness"),
        *values,
    )


def exec_verified_zipapp(
    evidence: RuntimePreflightEvidence,
    arguments: Iterable[str],
    *,
    diagnostic_host_exec: bool = False,
    execve: Callable[[str, tuple[str, ...], dict[str, str]], Any] = os.execve,
) -> None:
    """Diagnostic-only host exec for verifying the FD handoff mechanism.

    Production must use the independently pinned coordinator OCI image because a host Python FD
    does not bind its site-packages, native extensions, loader, or shared libraries.  The external
    launcher itself remains a root-owned bootstrap trust boundary.
    """

    if diagnostic_host_exec is not True:
        raise PreflightError("host zipapp exec is diagnostic-only; use coordinator_image_digest")
    argv = build_isolated_zipapp_argv(evidence, arguments)
    clean_environment = {
        "PATH": os.defpath,
        "LC_ALL": "C",
        "PYTHONNOUSERSITE": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
    }
    try:
        execve(argv[0], argv, clean_environment)
    except OSError as exc:
        raise PreflightError("failed to exec verified runtime descriptors") from exc
