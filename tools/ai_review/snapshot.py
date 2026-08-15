"""Create and verify content-addressed candidate snapshots without checking out code via Git."""

from __future__ import annotations

import configparser
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from pathlib import PurePosixPath
from typing import Any
from typing import Callable

from tools.ai_review.preflight import PreflightError
from tools.ai_review.preflight import assert_candidate_cannot_mutate
from tools.ai_review.preflight import assert_candidate_cannot_mutate_tree
from tools.ai_review.preflight import ensure_separate_candidate_uid
from tools.ai_review.preflight import read_protected_file
from tools.ai_review.sensitive_paths import sensitive_path_reason
from tools.ai_review.sensitive_paths import validate_empty_env_example


COMMIT_RE = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
ALLOWED_GIT_MODES = {"100644", "100755"}
MAX_FILE_BYTES = 2_000_000
MAX_TOTAL_BYTES = 10_000_000
MAX_COMMIT_BYTES = 2_000_000
MAX_TREE_OBJECT_BYTES = 8_000_000
MAX_TREE_TOTAL_BYTES = 32_000_000
MAX_GIT_METADATA_ENTRIES = 200_000
MAX_GIT_METADATA_BYTES = 512_000_000
GIT_TIMEOUT_SECONDS = 120


class SnapshotError(RuntimeError):
    """Raised when a candidate cannot be frozen as a verified immutable snapshot."""


@dataclass(frozen=True)
class SnapshotEvidence:
    root: Path
    tree: Path
    manifest_path: Path
    manifest_sha256: str
    snapshot_sha256: str
    commit_sha: str
    commit_tree_sha: str
    candidate_uid: int
    excluded_paths: tuple[str, ...] = ()


@dataclass(frozen=True)
class TddOverlayEvidence:
    phase: str
    source_snapshot_sha256: str
    test_patch_sha256: str
    test_paths: tuple[str, ...]
    snapshot: SnapshotEvidence


@dataclass(frozen=True)
class RedTddSnapshotEvidence:
    """Measured RED tree: base production plus exact candidate test entries."""

    phase: str
    source_snapshot_sha256: str
    candidate_snapshot_sha256: str
    test_patch_sha256: str
    test_manifest_sha256: str
    test_paths: tuple[str, ...]
    snapshot: SnapshotEvidence


@dataclass(frozen=True)
class SnapshotTestManifestEvidence:
    snapshot_sha256: str
    test_manifest_sha256: str
    test_paths: tuple[str, ...]


def _canonical_json(payload: object) -> bytes:
    return (
        json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")


def _system_which(name: str) -> str | None:
    return shutil.which(name, path=os.defpath)


def _git_environment() -> dict[str, str]:
    return {
        "PATH": os.defpath,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_TERMINAL_PROMPT": "0",
        "LC_ALL": "C",
    }


def _run_git(
    git: Path,
    arguments: tuple[str, ...],
    *,
    cwd: Path | None = None,
    text: bool = False,
) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(
            [
                str(git),
                "-c",
                "core.hooksPath=/dev/null",
                "-c",
                "core.fsmonitor=false",
                "-c",
                "core.attributesFile=/dev/null",
                *arguments,
            ],
            cwd=cwd,
            check=True,
            capture_output=True,
            env=_git_environment(),
            shell=False,
            text=text,
            timeout=GIT_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        raise SnapshotError("trusted local Git operation failed") from exc


def _trusted_git_executable(candidate_uid: int, which: Callable[[str], str | None]) -> Path:
    located = which("git")
    if located is None:
        raise SnapshotError("trusted Git executable was not found")
    try:
        resolved = Path(located).resolve(strict=True)
        evidence, _raw = read_protected_file(
            resolved, candidate_uid=candidate_uid, label="Git executable"
        )
    except (OSError, PreflightError) as exc:
        raise SnapshotError(str(exc)) from exc
    if not evidence.mode & 0o111:
        raise SnapshotError("trusted Git executable is not executable")
    return evidence.path


def _validate_repository_config(raw: bytes) -> None:
    parser = configparser.ConfigParser(interpolation=None, strict=True)
    parser.optionxform = str.lower
    try:
        parser.read_string(raw.decode("utf-8"))
    except (UnicodeDecodeError, configparser.Error) as exc:
        raise SnapshotError("bare repository config is invalid") from exc
    allowed: dict[str, set[str]] = {
        "core": {
            "repositoryformatversion",
            "filemode",
            "bare",
            "logallrefupdates",
            "ignorecase",
            "precomposeunicode",
        },
        "extensions": {"objectformat", "compatobjectformat", "refstorage"},
    }
    for section in parser.sections():
        normalized = section.casefold()
        if normalized.startswith('remote "') and normalized.endswith('"'):
            unknown = set(parser[section]) - {"url", "fetch", "mirror", "tagopt"}
            if unknown:
                raise SnapshotError("bare repository remote config contains an unsafe option")
            continue
        if normalized not in allowed:
            raise SnapshotError(f"bare repository config section is not allowed: {section}")
        unknown = set(parser[section]) - allowed[normalized]
        if unknown:
            raise SnapshotError("bare repository config contains an unsafe option")
    if parser.get("core", "bare", fallback="").casefold() != "true":
        raise SnapshotError("snapshot source must be a local bare repository")


def _validate_git_metadata(repo: Path, *, candidate_uid: int) -> None:
    if not all((repo / name).exists() for name in ("HEAD", "config", "objects", "refs")):
        raise SnapshotError("snapshot source must be a local bare repository")
    forbidden = (
        repo / "objects" / "info" / "alternates",
        repo / "objects" / "info" / "http-alternates",
        repo / "refs" / "replace",
    )
    if any(path.exists() or path.is_symlink() for path in forbidden):
        raise SnapshotError("Git alternates and replace refs are forbidden")

    root_device = os.lstat(repo).st_dev
    entry_count = 0
    total_bytes = 0
    for directory, directories, filenames in os.walk(repo, followlinks=False):
        directory_path = Path(directory)
        if os.lstat(directory_path).st_dev != root_device:
            raise SnapshotError("Git metadata must not cross a nested filesystem mount")
        try:
            assert_candidate_cannot_mutate(directory_path, candidate_uid=candidate_uid)
        except PreflightError as exc:
            raise SnapshotError(str(exc)) from exc
        for name in [*directories, *filenames]:
            entry_count += 1
            if entry_count > MAX_GIT_METADATA_ENTRIES:
                raise SnapshotError("Git metadata exceeds the entry limit")
            child = directory_path / name
            metadata = os.lstat(child)
            if metadata.st_dev != root_device:
                raise SnapshotError("Git metadata must not cross a nested filesystem mount")
            if stat.S_ISLNK(metadata.st_mode):
                raise SnapshotError("Git metadata must not contain symlinks")
            if not (stat.S_ISDIR(metadata.st_mode) or stat.S_ISREG(metadata.st_mode)):
                raise SnapshotError("Git metadata must contain only regular files and directories")
            if stat.S_ISREG(metadata.st_mode) and metadata.st_nlink != 1:
                raise SnapshotError("Git metadata files must not be hardlinks")
            if stat.S_ISREG(metadata.st_mode):
                total_bytes += metadata.st_size
                if total_bytes > MAX_GIT_METADATA_BYTES:
                    raise SnapshotError("Git metadata exceeds the total byte limit")
            try:
                assert_candidate_cannot_mutate(child, candidate_uid=candidate_uid)
            except PreflightError as exc:
                raise SnapshotError(str(exc)) from exc
        directories[:] = [name for name in directories if not (directory_path / name).is_symlink()]

    try:
        _config_evidence, config_raw = read_protected_file(
            repo / "config",
            candidate_uid=candidate_uid,
            label="bare repository config",
            max_bytes=64 * 1024,
        )
        _validate_repository_config(config_raw)
        packed_refs = repo / "packed-refs"
        if packed_refs.exists():
            _packed_evidence, packed_raw = read_protected_file(
                packed_refs,
                candidate_uid=candidate_uid,
                label="packed refs",
                max_bytes=16 * 1024 * 1024,
            )
            if b" refs/replace/" in packed_raw:
                raise SnapshotError("packed replace refs are forbidden")
    except PreflightError as exc:
        raise SnapshotError(str(exc)) from exc


def _safe_source(source_repo: Path, candidate_uid: int) -> Path:
    try:
        source = assert_candidate_cannot_mutate(source_repo, candidate_uid=candidate_uid)
    except PreflightError as exc:
        raise SnapshotError(str(exc)) from exc
    if not source.is_dir():
        raise SnapshotError("snapshot source must be a local bare repository directory")
    _validate_git_metadata(source, candidate_uid=candidate_uid)
    return source


def _hash_git_object(object_type: str, content: bytes, object_id_length: int) -> str:
    framed = f"{object_type} {len(content)}\0".encode("ascii") + content
    if object_id_length == 40:
        return hashlib.sha1(framed, usedforsecurity=False).hexdigest()
    if object_id_length == 64:
        return hashlib.sha256(framed).hexdigest()
    raise SnapshotError("unsupported Git object ID length")


def _read_verified_object(
    git: Path,
    clone: Path,
    object_type: str,
    object_id: str,
    object_id_length: int,
    *,
    max_bytes: int,
) -> bytes:
    if len(object_id) != object_id_length or not all(
        character in "0123456789abcdef" for character in object_id
    ):
        raise SnapshotError("candidate tree contains an invalid object ID")
    size = _verified_object_size(git, clone, object_id, object_id_length)
    if size > max_bytes:
        raise SnapshotError(f"Git {object_type} exceeds the byte limit")
    content = _run_git(git, ("-C", str(clone), "cat-file", object_type, object_id)).stdout
    if len(content) != size:
        raise SnapshotError(f"Git {object_type} size changed during verification")
    if _hash_git_object(object_type, content, object_id_length) != object_id:
        raise SnapshotError(f"Git {object_type} content does not match its object ID")
    return content


def _verified_object_size(git: Path, clone: Path, object_id: str, object_id_length: int) -> int:
    if len(object_id) != object_id_length or not all(
        character in "0123456789abcdef" for character in object_id
    ):
        raise SnapshotError("candidate tree contains an invalid object ID")
    raw_size = _run_git(git, ("-C", str(clone), "cat-file", "-s", object_id)).stdout.strip()
    try:
        size = int(raw_size.decode("ascii"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise SnapshotError("Git object size is invalid") from exc
    if size < 0:
        raise SnapshotError("Git object size is invalid")
    return size


def _sensitive_tree_reason(path: str) -> str | None:
    return sensitive_path_reason(path)


def _tree_entries(
    git: Path,
    clone: Path,
    tree_id: str,
    *,
    object_id_length: int,
    prefix: PurePosixPath = PurePosixPath(),
    depth: int = 0,
    budget: list[int] | None = None,
    byte_budget: list[int] | None = None,
) -> list[tuple[str, str, str]]:
    if depth > 128:
        raise SnapshotError("candidate tree exceeds the maximum directory depth")
    if budget is None:
        budget = [100_000]
    if byte_budget is None:
        byte_budget = [MAX_TREE_TOTAL_BYTES]
    tree_size = _verified_object_size(git, clone, tree_id, object_id_length)
    byte_budget[0] -= tree_size
    if byte_budget[0] < 0:
        raise SnapshotError("candidate tree objects exceed the total byte limit")
    raw = _read_verified_object(
        git,
        clone,
        "tree",
        tree_id,
        object_id_length,
        max_bytes=MAX_TREE_OBJECT_BYTES,
    )
    position = 0
    parsed: list[tuple[str, str, str]] = []
    seen_names: set[str] = set()
    object_bytes = object_id_length // 2
    while position < len(raw):
        space = raw.find(b" ", position)
        nul = raw.find(b"\0", space + 1)
        if space < 0 or nul < 0 or nul + 1 + object_bytes > len(raw):
            raise SnapshotError("candidate tree object has invalid binary framing")
        try:
            mode = raw[position:space].decode("ascii")
            name = raw[space + 1 : nul].decode("utf-8")
        except (UnicodeDecodeError, ValueError) as exc:
            raise SnapshotError("candidate tree contains an unsupported filename") from exc
        object_id = raw[nul + 1 : nul + 1 + object_bytes].hex()
        position = nul + 1 + object_bytes
        if not name or name in {".", ".."} or "/" in name or "\x00" in name or name in seen_names:
            raise SnapshotError("candidate tree contains an unsafe or duplicate filename")
        seen_names.add(name)
        relative = prefix / name
        normalized = relative.as_posix()
        reason = None if normalized == ".env.example" else _sensitive_tree_reason(normalized)
        if reason is not None:
            raise SnapshotError(f"candidate tree contains {reason}: {normalized}")
        budget[0] -= 1
        if budget[0] < 0:
            raise SnapshotError("candidate tree exceeds the maximum entry count")
        if mode in {"40000", "040000"}:
            parsed.extend(
                _tree_entries(
                    git,
                    clone,
                    object_id,
                    object_id_length=object_id_length,
                    prefix=relative,
                    depth=depth + 1,
                    budget=budget,
                    byte_budget=byte_budget,
                )
            )
        elif mode in ALLOWED_GIT_MODES:
            parsed.append((mode, object_id, normalized))
        elif mode == "120000":
            raise SnapshotError("candidate tree must not contain symlinks")
        elif mode == "160000":
            raise SnapshotError("candidate tree must not contain submodules")
        else:
            raise SnapshotError(f"candidate tree uses unsupported file mode: {mode}")
    return parsed


def _verified_commit_tree(
    git: Path, clone: Path, commit_sha: str
) -> tuple[list[tuple[str, str, str]], int, str]:
    object_id_length = len(commit_sha)
    commit = _read_verified_object(
        git,
        clone,
        "commit",
        commit_sha,
        object_id_length,
        max_bytes=MAX_COMMIT_BYTES,
    )
    first_line = commit.split(b"\n", 1)[0]
    try:
        marker, raw_tree_id = first_line.split(b" ", 1)
        tree_id = raw_tree_id.decode("ascii")
    except (ValueError, UnicodeDecodeError) as exc:
        raise SnapshotError("candidate commit does not contain a valid tree") from exc
    if marker != b"tree":
        raise SnapshotError("candidate commit does not begin with a tree binding")
    entries = _tree_entries(git, clone, tree_id, object_id_length=object_id_length)
    paths = [entry[2] for entry in entries]
    if len(paths) != len(set(paths)):
        raise SnapshotError("candidate tree contains duplicate materialized paths")
    return entries, object_id_length, tree_id


def _write_blob(path: Path, content: bytes) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o600)
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
    finally:
        os.close(descriptor)


def _make_read_only(root: Path, entries: list[dict[str, Any]]) -> None:
    for entry in entries:
        path = root / "tree" / entry["path"]
        path.chmod(0o555 if entry["mode"] == "100755" else 0o444)
    directories = sorted(
        (path for path in (root / "tree").rglob("*") if path.is_dir()),
        key=lambda path: len(path.parts),
        reverse=True,
    )
    for directory in directories:
        directory.chmod(0o555)
    (root / "tree").chmod(0o555)
    (root / "manifest.json").chmod(0o444)
    root.chmod(0o555)


def _freeze_staging_tree(
    *,
    staging: Path,
    destination: Path,
    commit_sha: str,
    commit_tree_sha: str,
    manifest_entries: list[dict[str, Any]],
    candidate_uid: int,
    excluded_paths: tuple[str, ...] = (),
) -> SnapshotEvidence:
    manifest_entries.sort(key=lambda entry: entry["path"])
    digest_payload = {
        "schema_version": "1.0",
        "commit_sha": commit_sha,
        "commit_tree_sha": commit_tree_sha,
        "excluded_paths": list(excluded_paths),
        "files": manifest_entries,
    }
    snapshot_sha256 = hashlib.sha256(_canonical_json(digest_payload)).hexdigest()
    stored_manifest = {**digest_payload, "snapshot_sha256": snapshot_sha256}
    manifest_path = staging / "manifest.json"
    manifest_path.write_bytes(_canonical_json(stored_manifest))
    with manifest_path.open("rb") as handle:
        os.fsync(handle.fileno())
    manifest_sha256 = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
    final_root = destination / snapshot_sha256
    if final_root.exists() or final_root.is_symlink():
        raise SnapshotError("content-addressed snapshot already exists")
    os.replace(staging, final_root)
    _make_read_only(final_root, manifest_entries)
    return SnapshotEvidence(
        root=final_root,
        tree=final_root / "tree",
        manifest_path=final_root / "manifest.json",
        manifest_sha256=manifest_sha256,
        snapshot_sha256=snapshot_sha256,
        commit_sha=commit_sha,
        commit_tree_sha=commit_tree_sha,
        candidate_uid=candidate_uid,
        excluded_paths=excluded_paths,
    )


def create_readonly_snapshot(
    *,
    source_repo: Path,
    commit_sha: str,
    destination_root: Path,
    candidate_uid: int,
    which: Callable[[str], str | None] = _system_which,
) -> SnapshotEvidence:
    """Clone a trusted bare repo locally, materialize blobs, and freeze a digest-named tree."""

    try:
        ensure_separate_candidate_uid(candidate_uid)
        destination = assert_candidate_cannot_mutate(destination_root, candidate_uid=candidate_uid)
    except PreflightError as exc:
        raise SnapshotError(str(exc)) from exc
    if not destination.is_dir():
        raise SnapshotError("snapshot destination root must be a directory")
    if stat.S_IMODE(destination.stat().st_mode) & 0o077:
        raise SnapshotError("snapshot destination root must be private (0700 or stricter)")
    if COMMIT_RE.fullmatch(commit_sha) is None:
        raise SnapshotError("snapshot commit must be a full lowercase object ID")

    source = _safe_source(source_repo, candidate_uid)
    git = _trusted_git_executable(candidate_uid, which)
    staging = Path(tempfile.mkdtemp(prefix=".building-", dir=destination))
    clone = staging / "clone.git"
    tree = staging / "tree"
    try:
        _run_git(
            git,
            (
                "clone",
                "--quiet",
                "--bare",
                "--no-local",
                "--no-hardlinks",
                "--",
                str(source),
                str(clone),
            ),
        )
        _validate_git_metadata(clone, candidate_uid=candidate_uid)
        tree_entries, object_id_length, commit_tree_sha = _verified_commit_tree(
            git, clone, commit_sha
        )
        excluded_paths: list[str] = []
        materialized_entries: list[tuple[str, str, str]] = []
        blob_sizes: dict[str, int] = {}
        total_bytes = 0
        for mode, object_id, relative in tree_entries:
            size = _verified_object_size(git, clone, object_id, object_id_length)
            if size > MAX_FILE_BYTES:
                raise SnapshotError(f"candidate file exceeds the byte limit: {relative}")
            if relative == ".env.example":
                if size > 64 * 1024:
                    raise SnapshotError("tracked .env.example exceeds the template byte limit")
                try:
                    validate_empty_env_example(
                        _read_verified_object(
                            git,
                            clone,
                            "blob",
                            object_id,
                            object_id_length,
                            max_bytes=size,
                        )
                    )
                except ValueError as exc:
                    raise SnapshotError(
                        "tracked .env.example is not a safe empty template"
                    ) from exc
                excluded_paths.append(relative)
                continue
            total_bytes += size
            if total_bytes > MAX_TOTAL_BYTES:
                raise SnapshotError("candidate tree exceeds the total byte limit")
            blob_sizes[relative] = size
            materialized_entries.append((mode, object_id, relative))
        tree.mkdir(mode=0o700)
        manifest_entries: list[dict[str, Any]] = []
        for mode, object_id, relative in materialized_entries:
            blob = _read_verified_object(
                git,
                clone,
                "blob",
                object_id,
                object_id_length,
                max_bytes=blob_sizes[relative],
            )
            target = tree.joinpath(*PurePosixPath(relative).parts)
            _write_blob(target, blob)
            manifest_entries.append(
                {
                    "mode": mode,
                    "path": relative,
                    "sha256": hashlib.sha256(blob).hexdigest(),
                    "size": len(blob),
                }
            )
        # The selected commit, every recursively reachable tree, and every materialized blob were
        # re-hashed above with their canonical Git headers.  Avoid a full-history fsck here: history
        # is not mounted and adversarial unreachable/delta objects would create an unbounded DoS.
        shutil.rmtree(clone)
        return _freeze_staging_tree(
            staging=staging,
            destination=destination,
            commit_sha=commit_sha,
            commit_tree_sha=commit_tree_sha,
            manifest_entries=manifest_entries,
            candidate_uid=candidate_uid,
            excluded_paths=tuple(excluded_paths),
        )
    except SnapshotError:
        raise
    except (OSError, ValueError) as exc:
        raise SnapshotError("failed to materialize candidate snapshot safely") from exc
    finally:
        if staging.exists():
            shutil.rmtree(staging, ignore_errors=True)


def create_readonly_snapshot_pair_from_worktree(
    *,
    source_worktree: Path,
    base_commit_sha: str,
    candidate_commit_sha: str,
    destination_root: Path,
    candidate_uid: int,
    which: Callable[[str], str | None] = _system_which,
) -> tuple[SnapshotEvidence, SnapshotEvidence]:
    """Freeze base and candidate snapshots from one protected standalone worktree.

    ``create_readonly_snapshot`` deliberately accepts only a validated local bare
    repository.  Production, however, mounts a standalone worktree so policy
    inspection can verify its clean ``HEAD``.  This compound helper bridges those
    contracts without asking the outer caller for a second repository: it creates
    one private, non-local, no-hardlink bare clone under the coordinator output,
    feeds that clone to the existing verified snapshot factory, and removes the
    temporary Git metadata before returning.
    """

    try:
        worktree = assert_candidate_cannot_mutate_tree(
            source_worktree,
            candidate_uid=candidate_uid,
        ).root
        destination = assert_candidate_cannot_mutate(
            destination_root,
            candidate_uid=candidate_uid,
        )
    except PreflightError as exc:
        raise SnapshotError(str(exc)) from exc
    git_metadata = worktree / ".git"
    if not git_metadata.is_dir() or git_metadata.is_symlink():
        raise SnapshotError("snapshot worktree must contain standalone Git metadata")
    if not destination.is_dir() or stat.S_IMODE(os.lstat(destination).st_mode) & 0o077:
        raise SnapshotError("snapshot pair destination must be a private directory")
    if any(destination.iterdir()):
        raise SnapshotError("snapshot pair destination must start empty")
    if (
        COMMIT_RE.fullmatch(base_commit_sha) is None
        or COMMIT_RE.fullmatch(candidate_commit_sha) is None
    ):
        raise SnapshotError("snapshot pair commits must be full lowercase object IDs")
    git = _trusted_git_executable(candidate_uid, which)

    def bound_which(name: str) -> str | None:
        return str(git) if name == "git" else None

    staging = Path(tempfile.mkdtemp(prefix=".source-", dir=destination))
    bare = staging / "source.git"
    try:
        _run_git(
            git,
            (
                "clone",
                "--quiet",
                "--bare",
                "--no-local",
                "--no-hardlinks",
                "--",
                str(worktree),
                str(bare),
            ),
        )
        base = create_readonly_snapshot(
            source_repo=bare,
            commit_sha=base_commit_sha,
            destination_root=destination,
            candidate_uid=candidate_uid,
            which=bound_which,
        )
        candidate = create_readonly_snapshot(
            source_repo=bare,
            commit_sha=candidate_commit_sha,
            destination_root=destination,
            candidate_uid=candidate_uid,
            which=bound_which,
        )
        return base, candidate
    except SnapshotError:
        raise
    except (OSError, ValueError) as exc:
        raise SnapshotError("failed to construct snapshot pair from worktree") from exc
    finally:
        try:
            shutil.rmtree(staging)
        except OSError as exc:
            raise SnapshotError("temporary bare snapshot source cleanup failed") from exc


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise SnapshotError(f"duplicate JSON key in snapshot manifest: {key}")
        result[key] = value
    return result


def _load_manifest(raw: bytes) -> dict[str, Any]:
    try:
        payload = json.loads(raw.decode("utf-8"), object_pairs_hook=_reject_duplicate_keys)
    except SnapshotError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SnapshotError("snapshot manifest must be valid UTF-8 JSON") from exc
    if not isinstance(payload, dict) or set(payload) != {
        "schema_version",
        "commit_sha",
        "commit_tree_sha",
        "snapshot_sha256",
        "excluded_paths",
        "files",
    }:
        raise SnapshotError("snapshot manifest contains missing or unknown fields")
    if (
        payload["schema_version"] != "1.0"
        or not isinstance(payload["commit_sha"], str)
        or COMMIT_RE.fullmatch(payload["commit_sha"]) is None
        or not isinstance(payload["commit_tree_sha"], str)
        or COMMIT_RE.fullmatch(payload["commit_tree_sha"]) is None
    ):
        raise SnapshotError("snapshot manifest version or commit is invalid")
    if (
        not isinstance(payload["snapshot_sha256"], str)
        or SHA256_RE.fullmatch(payload["snapshot_sha256"]) is None
    ):
        raise SnapshotError("snapshot manifest digest is invalid")
    if not isinstance(payload["files"], list):
        raise SnapshotError("snapshot manifest files must be an array")
    if payload["excluded_paths"] not in ([], [".env.example"]):
        raise SnapshotError("snapshot manifest contains an unsupported excluded path")
    return payload


def _validated_test_paths(test_paths: tuple[str, ...]) -> tuple[str, ...]:
    if not test_paths or len(test_paths) > 256:
        raise SnapshotError("test_paths must contain between 1 and 256 exact paths")
    normalized: list[str] = []
    for value in test_paths:
        if not isinstance(value, str) or not value or "\x00" in value:
            raise SnapshotError("test_paths contains an invalid path")
        path = PurePosixPath(value)
        if (
            path.is_absolute()
            or path.as_posix() != value
            or any(part in {"", ".", ".."} for part in path.parts)
            or not path.parts
            or path.parts[0].casefold() != "tests"
            or _sensitive_tree_reason(value) is not None
        ):
            raise SnapshotError("test_paths must contain only safe paths below tests/")
        normalized.append(value)
    if len(normalized) != len(set(normalized)):
        raise SnapshotError("test_paths must not contain duplicates")
    return tuple(sorted(normalized))


def _patch_paths(raw: bytes, *, allowed: set[str]) -> set[str]:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise SnapshotError("test patch must be UTF-8 unified diff text") from exc
    forbidden_prefixes = (
        "GIT binary patch",
        "Binary files ",
        "rename from ",
        "rename to ",
        "copy from ",
        "copy to ",
        "old mode ",
        "new mode ",
        "deleted file mode ",
    )
    paths: set[str] = set()
    for line in text.splitlines():
        if line.startswith(forbidden_prefixes) or line == "new file mode 120000":
            raise SnapshotError("test patch contains a forbidden binary, rename, or mode operation")
        if line.startswith("new file mode ") and line != "new file mode 100644":
            raise SnapshotError("new test files must use regular mode 100644")
        if line.startswith("diff --git "):
            match = re.fullmatch(r"diff --git a/([^\s]+) b/([^\s]+)", line)
            if match is None or match.group(1) != match.group(2):
                raise SnapshotError("test patch must not rename paths or use quoted path syntax")
            paths.add(match.group(1))
        elif line.startswith(("--- ", "+++ ")):
            value = line[4:].split("\t", 1)[0]
            if value == "/dev/null":
                continue
            if not value.startswith(("a/", "b/")):
                raise SnapshotError("test patch contains an unsafe file header")
            paths.add(value[2:])
    if not paths:
        raise SnapshotError("test patch contains no file changes")
    if not paths <= allowed:
        raise SnapshotError("test patch may modify only exact test_paths")
    return paths


def _make_tree_writable(tree: Path) -> None:
    for directory, directories, filenames in os.walk(tree, followlinks=False):
        directory_path = Path(directory)
        directory_path.chmod(0o700)
        for name in directories:
            child = directory_path / name
            if child.is_symlink():
                raise SnapshotError("overlay source must not contain symlinks")
        for name in filenames:
            child = directory_path / name
            if child.is_symlink():
                raise SnapshotError("overlay source must not contain symlinks")
            child.chmod(0o700 if child.stat().st_mode & 0o111 else 0o600)


def _manifest_entries_from_tree(tree: Path, *, candidate_uid: int) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    total_bytes = 0
    root_device = os.lstat(tree).st_dev
    for directory, directories, filenames in os.walk(tree, followlinks=False):
        directory_path = Path(directory)
        if os.lstat(directory_path).st_dev != root_device:
            raise SnapshotError("materialized tree must not cross a nested filesystem mount")
        if directory_path.is_symlink():
            raise SnapshotError("materialized tree must not contain symlinks")
        for name in directories:
            child = directory_path / name
            if child.is_symlink():
                raise SnapshotError("materialized tree must not contain symlinks")
            if os.lstat(child).st_dev != root_device:
                raise SnapshotError("materialized tree must not cross a nested filesystem mount")
        for name in filenames:
            child = directory_path / name
            relative = child.relative_to(tree).as_posix()
            reason = _sensitive_tree_reason(relative)
            if reason is not None:
                raise SnapshotError(f"materialized tree contains {reason}: {relative}")
            try:
                evidence, content = read_protected_file(
                    child,
                    candidate_uid=candidate_uid,
                    label=f"materialized file {relative}",
                    max_bytes=MAX_FILE_BYTES,
                )
            except PreflightError as exc:
                raise SnapshotError(str(exc)) from exc
            if evidence.device != root_device:
                raise SnapshotError("materialized tree must not cross a nested filesystem mount")
            if evidence.mode & (stat.S_ISUID | stat.S_ISGID):
                raise SnapshotError("materialized tree contains setuid or setgid content")
            total_bytes += evidence.size
            if total_bytes > MAX_TOTAL_BYTES:
                raise SnapshotError("materialized tree exceeds the total byte limit")
            entries.append(
                {
                    "mode": "100755" if evidence.mode & 0o111 else "100644",
                    "path": relative,
                    "sha256": evidence.sha256,
                    "size": evidence.size,
                }
            )
    entries.sort(key=lambda entry: entry["path"])
    return entries


def _snapshot_file_map(
    snapshot: SnapshotEvidence, *, candidate_uid: int, label: str
) -> dict[str, dict[str, Any]]:
    try:
        _manifest_evidence, raw_manifest = read_protected_file(
            snapshot.manifest_path,
            candidate_uid=candidate_uid,
            label=f"{label} manifest",
            expected_sha256=snapshot.manifest_sha256,
            max_bytes=32 * 1024 * 1024,
        )
    except PreflightError as exc:
        raise SnapshotError(str(exc)) from exc
    payload = _load_manifest(raw_manifest)
    return {entry["path"]: entry for entry in payload["files"]}


def _project_test_entry(entry: dict[str, Any] | None) -> dict[str, Any] | None:
    if entry is None:
        return None
    return {
        "mode": entry["mode"],
        "sha256": entry["sha256"],
        "size": entry["size"],
    }


def _test_delta(
    *,
    base_map: dict[str, dict[str, Any]],
    candidate_map: dict[str, dict[str, Any]],
    test_paths: tuple[str, ...],
) -> tuple[bytes, str]:
    files: list[dict[str, Any]] = []
    for path in test_paths:
        candidate_entry = candidate_map.get(path)
        if candidate_entry is None:
            raise SnapshotError(f"candidate test path is missing or deleted: {path}")
        before = _project_test_entry(base_map.get(path))
        after = _project_test_entry(candidate_entry)
        if before == after:
            raise SnapshotError("candidate must change every exact test path")
        files.append({"after": after, "before": before, "path": path})
    raw_delta = _canonical_json({"files": files, "schema_version": "1.0"})
    return raw_delta, hashlib.sha256(raw_delta).hexdigest()


def _test_manifest_sha256(
    *, candidate_map: dict[str, dict[str, Any]], test_paths: tuple[str, ...]
) -> str:
    digest = hashlib.sha256()
    digest.update(b"amazon-explorer-ai-review-test-manifest-v1\0")
    for path in test_paths:
        entry = candidate_map.get(path)
        if entry is None:
            raise SnapshotError(f"candidate test path is missing or deleted: {path}")
        for value in (path, entry["sha256"]):
            encoded = value.encode("utf-8")
            digest.update(len(encoded).to_bytes(4, "big"))
            digest.update(encoded)
    return digest.hexdigest()


def build_snapshot_test_manifest(
    *,
    snapshot: SnapshotEvidence,
    test_paths: tuple[str, ...],
    candidate_uid: int,
) -> SnapshotTestManifestEvidence:
    """Measure exact candidate test content using the attestation manifest domain."""

    verified = verify_readonly_snapshot(snapshot.root, candidate_uid=candidate_uid)
    if verified != snapshot:
        raise SnapshotError("test manifest snapshot evidence changed before measurement")
    exact_test_paths = _validated_test_paths(test_paths)
    candidate_map = _snapshot_file_map(
        verified, candidate_uid=candidate_uid, label="test manifest snapshot"
    )
    return SnapshotTestManifestEvidence(
        snapshot_sha256=verified.snapshot_sha256,
        test_manifest_sha256=_test_manifest_sha256(
            candidate_map=candidate_map, test_paths=exact_test_paths
        ),
        test_paths=exact_test_paths,
    )


def _assert_exact_red_tree(
    *,
    base_map: dict[str, dict[str, Any]],
    candidate_map: dict[str, dict[str, Any]],
    red_map: dict[str, dict[str, Any]],
    test_paths: tuple[str, ...],
) -> None:
    changed = {
        path
        for path in base_map.keys() | red_map.keys()
        if _project_test_entry(base_map.get(path)) != _project_test_entry(red_map.get(path))
    }
    if changed != set(test_paths):
        raise SnapshotError("RED snapshot must change exactly the declared test_paths")
    for path in test_paths:
        if _project_test_entry(red_map.get(path)) != _project_test_entry(candidate_map.get(path)):
            raise SnapshotError(f"RED test entry does not match candidate content and mode: {path}")


def create_red_tdd_snapshot(
    *,
    base_snapshot: SnapshotEvidence,
    candidate_snapshot: SnapshotEvidence,
    test_paths: tuple[str, ...],
    destination_root: Path,
    candidate_uid: int,
) -> RedTddSnapshotEvidence:
    """Freeze RED as base production plus candidate's exact changed test files.

    GREEN is deliberately not constructed here: it is the verified candidate snapshot itself.
    The test patch digest is the canonical before/after metadata delta, so no candidate text is
    re-applied by a coordinator parser.
    """

    base = verify_readonly_snapshot(base_snapshot.root, candidate_uid=candidate_uid)
    candidate = verify_readonly_snapshot(candidate_snapshot.root, candidate_uid=candidate_uid)
    if base != base_snapshot:
        raise SnapshotError("base snapshot evidence changed before RED construction")
    if candidate != candidate_snapshot:
        raise SnapshotError("candidate snapshot evidence changed before RED construction")
    if base.excluded_paths != candidate.excluded_paths:
        raise SnapshotError("base and candidate protected-path exclusions differ")
    exact_test_paths = _validated_test_paths(test_paths)
    base_map = _snapshot_file_map(base, candidate_uid=candidate_uid, label="base snapshot")
    candidate_map = _snapshot_file_map(
        candidate, candidate_uid=candidate_uid, label="candidate snapshot"
    )
    _raw_delta, test_patch_sha256 = _test_delta(
        base_map=base_map,
        candidate_map=candidate_map,
        test_paths=exact_test_paths,
    )
    test_manifest_sha256 = _test_manifest_sha256(
        candidate_map=candidate_map, test_paths=exact_test_paths
    )
    try:
        destination = assert_candidate_cannot_mutate(destination_root, candidate_uid=candidate_uid)
    except PreflightError as exc:
        raise SnapshotError(str(exc)) from exc
    if not destination.is_dir() or stat.S_IMODE(destination.stat().st_mode) & 0o077:
        raise SnapshotError("RED snapshot destination root must be a private directory")

    staging = Path(tempfile.mkdtemp(prefix=".red-", dir=destination))
    tree = staging / "tree"
    try:
        shutil.copytree(base.tree, tree, symlinks=False, copy_function=shutil.copy2)
        _make_tree_writable(tree)
        for relative in exact_test_paths:
            candidate_entry = candidate_map[relative]
            try:
                _test_evidence, content = read_protected_file(
                    candidate.tree.joinpath(*PurePosixPath(relative).parts),
                    candidate_uid=candidate_uid,
                    label=f"candidate test file {relative}",
                    expected_sha256=candidate_entry["sha256"],
                    max_bytes=MAX_FILE_BYTES,
                )
            except PreflightError as exc:
                raise SnapshotError(str(exc)) from exc
            if len(content) != candidate_entry["size"]:
                raise SnapshotError("candidate test size does not match its manifest")
            target = tree.joinpath(*PurePosixPath(relative).parts)
            if target.exists() and target.is_dir():
                raise SnapshotError("RED test path conflicts with a base directory")
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            if not target.parent.is_dir() or target.parent.is_symlink():
                raise SnapshotError("RED test path conflicts with a base file or symlink")
            if target.exists():
                target.unlink()
            _write_blob(target, content)
            target.chmod(0o700 if candidate_entry["mode"] == "100755" else 0o600)

        red_entries = _manifest_entries_from_tree(tree, candidate_uid=candidate_uid)
        red_map = {entry["path"]: entry for entry in red_entries}
        _assert_exact_red_tree(
            base_map=base_map,
            candidate_map=candidate_map,
            red_map=red_map,
            test_paths=exact_test_paths,
        )
        frozen = _freeze_staging_tree(
            staging=staging,
            destination=destination,
            commit_sha=base.commit_sha,
            commit_tree_sha=base.commit_tree_sha,
            manifest_entries=red_entries,
            candidate_uid=candidate_uid,
            excluded_paths=base.excluded_paths,
        )
        evidence = RedTddSnapshotEvidence(
            phase="red",
            source_snapshot_sha256=base.snapshot_sha256,
            candidate_snapshot_sha256=candidate.snapshot_sha256,
            test_patch_sha256=test_patch_sha256,
            test_manifest_sha256=test_manifest_sha256,
            test_paths=exact_test_paths,
            snapshot=frozen,
        )
        return measure_red_tdd_snapshot(
            red_root=evidence.snapshot.root,
            base_snapshot=base,
            candidate_snapshot=candidate,
            test_paths=exact_test_paths,
            candidate_uid=candidate_uid,
        )
    except SnapshotError:
        raise
    except (OSError, ValueError) as exc:
        raise SnapshotError("failed to construct RED TDD snapshot") from exc
    finally:
        if staging.exists():
            shutil.rmtree(staging, ignore_errors=True)


def measure_red_tdd_snapshot(
    *,
    red_root: Path,
    base_snapshot: SnapshotEvidence,
    candidate_snapshot: SnapshotEvidence,
    test_paths: tuple[str, ...],
    candidate_uid: int,
) -> RedTddSnapshotEvidence:
    """Reconstruct trusted RED evidence from three measured snapshot manifests."""

    base = verify_readonly_snapshot(base_snapshot.root, candidate_uid=candidate_uid)
    candidate = verify_readonly_snapshot(candidate_snapshot.root, candidate_uid=candidate_uid)
    red = verify_readonly_snapshot(red_root, candidate_uid=candidate_uid)
    if base != base_snapshot:
        raise SnapshotError("RED source snapshot evidence changed before measurement")
    if candidate != candidate_snapshot:
        raise SnapshotError("RED candidate snapshot evidence changed before measurement")
    if (red.commit_sha, red.commit_tree_sha) != (base.commit_sha, base.commit_tree_sha):
        raise SnapshotError("RED snapshot source commit/tree does not match the verified base")
    if not red.excluded_paths == base.excluded_paths == candidate.excluded_paths:
        raise SnapshotError("RED snapshot protected-path exclusions do not match its sources")
    exact_test_paths = _validated_test_paths(test_paths)
    base_map = _snapshot_file_map(base, candidate_uid=candidate_uid, label="base snapshot")
    candidate_map = _snapshot_file_map(
        candidate, candidate_uid=candidate_uid, label="candidate snapshot"
    )
    red_map = _snapshot_file_map(red, candidate_uid=candidate_uid, label="RED snapshot")
    _raw_delta, test_patch_sha256 = _test_delta(
        base_map=base_map,
        candidate_map=candidate_map,
        test_paths=exact_test_paths,
    )
    test_manifest_sha256 = _test_manifest_sha256(
        candidate_map=candidate_map, test_paths=exact_test_paths
    )
    _assert_exact_red_tree(
        base_map=base_map,
        candidate_map=candidate_map,
        red_map=red_map,
        test_paths=exact_test_paths,
    )
    return RedTddSnapshotEvidence(
        phase="red",
        source_snapshot_sha256=base.snapshot_sha256,
        candidate_snapshot_sha256=candidate.snapshot_sha256,
        test_patch_sha256=test_patch_sha256,
        test_manifest_sha256=test_manifest_sha256,
        test_paths=exact_test_paths,
        snapshot=red,
    )


def verify_red_tdd_snapshot(
    evidence: RedTddSnapshotEvidence,
    *,
    base_snapshot: SnapshotEvidence,
    candidate_snapshot: SnapshotEvidence,
    candidate_uid: int,
) -> RedTddSnapshotEvidence:
    """Compare supplied RED evidence with a fresh three-manifest measurement."""

    if evidence.source_snapshot_sha256 != base_snapshot.snapshot_sha256:
        raise SnapshotError("RED source snapshot binding does not match evidence")
    if evidence.candidate_snapshot_sha256 != candidate_snapshot.snapshot_sha256:
        raise SnapshotError("RED candidate snapshot binding does not match evidence")
    measured = measure_red_tdd_snapshot(
        red_root=evidence.snapshot.root,
        base_snapshot=base_snapshot,
        candidate_snapshot=candidate_snapshot,
        test_paths=evidence.test_paths,
        candidate_uid=candidate_uid,
    )
    if measured != evidence:
        if measured.candidate_snapshot_sha256 != evidence.candidate_snapshot_sha256:
            raise SnapshotError("RED candidate snapshot binding does not match evidence")
        raise SnapshotError("supplied RED evidence does not match measured snapshot manifests")
    return measured


def create_tdd_overlay_snapshot(
    *,
    phase: str,
    source_snapshot: SnapshotEvidence,
    test_patch_path: Path,
    expected_test_patch_sha256: str,
    test_paths: tuple[str, ...],
    destination_root: Path,
    candidate_uid: int,
    which: Callable[[str], str | None] = _system_which,
) -> TddOverlayEvidence:
    """Diagnostic compatibility API for applying a coordinator-owned RED patch.

    Production TDD should use :func:`create_red_tdd_snapshot`; GREEN is always the candidate
    snapshot itself and must never receive a second patch application.
    """

    if phase != "red":
        raise SnapshotError("textual TDD overlay is RED-only; GREEN is the candidate snapshot")
    source = verify_readonly_snapshot(source_snapshot.root, candidate_uid=candidate_uid)
    if source != source_snapshot:
        raise SnapshotError("source snapshot evidence changed before TDD overlay")
    exact_test_paths = _validated_test_paths(test_paths)
    try:
        patch_evidence, raw_patch = read_protected_file(
            test_patch_path,
            candidate_uid=candidate_uid,
            label="test patch",
            expected_sha256=expected_test_patch_sha256,
            max_bytes=2 * 1024 * 1024,
        )
        destination = assert_candidate_cannot_mutate(destination_root, candidate_uid=candidate_uid)
    except PreflightError as exc:
        raise SnapshotError(str(exc)) from exc
    if not destination.is_dir() or stat.S_IMODE(destination.stat().st_mode) & 0o077:
        raise SnapshotError("overlay destination root must be a private directory")
    declared_patch_paths = _patch_paths(raw_patch, allowed=set(exact_test_paths))
    git = _trusted_git_executable(candidate_uid, which)
    staging = Path(tempfile.mkdtemp(prefix=".overlay-", dir=destination))
    tree = staging / "tree"
    try:
        shutil.copytree(source.tree, tree, symlinks=False, copy_function=shutil.copy2)
        _make_tree_writable(tree)
        _run_git(
            git,
            (
                "apply",
                "--no-index",
                "--whitespace=nowarn",
                "--",
                str(patch_evidence.path),
            ),
            cwd=tree,
        )
        actual_entries = _manifest_entries_from_tree(tree, candidate_uid=candidate_uid)
        _source_manifest_evidence, raw_source_manifest = read_protected_file(
            source.manifest_path,
            candidate_uid=candidate_uid,
            label="source snapshot manifest",
            expected_sha256=source.manifest_sha256,
            max_bytes=32 * 1024 * 1024,
        )
        source_payload = _load_manifest(raw_source_manifest)
        source_map = {
            entry["path"]: (entry["mode"], entry["size"], entry["sha256"])
            for entry in source_payload["files"]
        }
        actual_map = {
            entry["path"]: (entry["mode"], entry["size"], entry["sha256"])
            for entry in actual_entries
        }
        changed = {
            path
            for path in source_map.keys() | actual_map.keys()
            if source_map.get(path) != actual_map.get(path)
        }
        if (
            not changed
            or not changed <= set(exact_test_paths)
            or not changed <= declared_patch_paths
        ):
            raise SnapshotError("actual overlay changes must be a non-empty subset of test_paths")
        frozen = _freeze_staging_tree(
            staging=staging,
            destination=destination,
            commit_sha=source.commit_sha,
            commit_tree_sha=source.commit_tree_sha,
            manifest_entries=actual_entries,
            candidate_uid=candidate_uid,
            excluded_paths=source.excluded_paths,
        )
        return TddOverlayEvidence(
            phase=phase,
            source_snapshot_sha256=source.snapshot_sha256,
            test_patch_sha256=patch_evidence.sha256,
            test_paths=exact_test_paths,
            snapshot=frozen,
        )
    except SnapshotError:
        raise
    except (OSError, ValueError) as exc:
        raise SnapshotError("failed to construct TDD overlay snapshot") from exc
    finally:
        if staging.exists():
            shutil.rmtree(staging, ignore_errors=True)


def verify_readonly_snapshot(snapshot_root: Path, *, candidate_uid: int) -> SnapshotEvidence:
    """Re-hash one frozen tree and reject extras, links, hardlinks, or writable content."""

    try:
        ensure_separate_candidate_uid(candidate_uid)
        root = assert_candidate_cannot_mutate(snapshot_root, candidate_uid=candidate_uid)
        manifest_evidence, raw_manifest = read_protected_file(
            root / "manifest.json",
            candidate_uid=candidate_uid,
            label="snapshot manifest",
            max_bytes=32 * 1024 * 1024,
        )
    except PreflightError as exc:
        raise SnapshotError(str(exc)) from exc
    if not root.is_dir() or stat.S_IMODE(root.stat().st_mode) != 0o555:
        raise SnapshotError("snapshot root must be a read-only directory")
    root_device = os.lstat(root).st_dev
    tree = root / "tree"
    if not tree.is_dir() or tree.is_symlink() or stat.S_IMODE(tree.stat().st_mode) != 0o555:
        raise SnapshotError("snapshot tree must be a read-only directory")
    if os.lstat(tree).st_dev != root_device or manifest_evidence.device != root_device:
        raise SnapshotError("snapshot must not cross a nested filesystem mount")
    payload = _load_manifest(raw_manifest)
    digest_payload = {
        "schema_version": payload["schema_version"],
        "commit_sha": payload["commit_sha"],
        "commit_tree_sha": payload["commit_tree_sha"],
        "excluded_paths": payload["excluded_paths"],
        "files": payload["files"],
    }
    snapshot_sha256 = hashlib.sha256(_canonical_json(digest_payload)).hexdigest()
    if snapshot_sha256 != payload["snapshot_sha256"] or root.name != snapshot_sha256:
        raise SnapshotError("snapshot manifest digest does not match its content-addressed root")

    expected_paths: set[str] = set()
    expected_directories: set[str] = set()
    previous_path = ""
    verified_total_bytes = 0
    if len(payload["files"]) > 100_000:
        raise SnapshotError("snapshot manifest exceeds the file count limit")
    for entry in payload["files"]:
        if not isinstance(entry, dict) or set(entry) != {"mode", "path", "sha256", "size"}:
            raise SnapshotError("snapshot file manifest entry is invalid")
        mode = entry["mode"]
        relative = entry["path"]
        if (
            mode not in ALLOWED_GIT_MODES
            or not isinstance(relative, str)
            or relative <= previous_path
            or PurePosixPath(relative).is_absolute()
            or any(part in {"", ".", ".."} for part in PurePosixPath(relative).parts)
            or not isinstance(entry["size"], int)
            or isinstance(entry["size"], bool)
            or entry["size"] < 0
            or not isinstance(entry["sha256"], str)
            or SHA256_RE.fullmatch(entry["sha256"]) is None
        ):
            raise SnapshotError("snapshot file manifest entry is unsafe")
        previous_path = relative
        reason = _sensitive_tree_reason(relative)
        if reason is not None:
            raise SnapshotError(f"snapshot manifest contains {reason}: {relative}")
        expected_paths.add(relative)
        parents = PurePosixPath(relative).parents
        expected_directories.update(
            parent.as_posix() for parent in parents if parent != PurePosixPath(".")
        )
        if entry["size"] > MAX_FILE_BYTES:
            raise SnapshotError("snapshot file exceeds the byte limit")
        verified_total_bytes += entry["size"]
        if verified_total_bytes > MAX_TOTAL_BYTES:
            raise SnapshotError("snapshot manifest exceeds the total byte limit")
        try:
            file_evidence, _content = read_protected_file(
                tree.joinpath(*PurePosixPath(relative).parts),
                candidate_uid=candidate_uid,
                label=f"snapshot file {relative}",
                expected_sha256=entry["sha256"],
                max_bytes=MAX_FILE_BYTES,
            )
        except PreflightError as exc:
            raise SnapshotError(str(exc)) from exc
        if file_evidence.device != root_device:
            raise SnapshotError("snapshot must not cross a nested filesystem mount")
        expected_mode = 0o555 if mode == "100755" else 0o444
        if file_evidence.mode != expected_mode or file_evidence.size != entry["size"]:
            raise SnapshotError(f"snapshot file metadata does not match manifest: {relative}")

    actual_paths: set[str] = set()
    actual_directories: set[str] = set()
    for directory, directories, filenames in os.walk(tree, followlinks=False):
        directory_path = Path(directory)
        if os.lstat(directory_path).st_dev != root_device:
            raise SnapshotError("snapshot must not cross a nested filesystem mount")
        if directory_path.is_symlink() or stat.S_IMODE(directory_path.stat().st_mode) != 0o555:
            raise SnapshotError("snapshot tree contains a symlink or writable directory")
        for name in directories:
            child = directory_path / name
            if child.is_symlink():
                raise SnapshotError("snapshot tree must not contain symlinks")
            if os.lstat(child).st_dev != root_device:
                raise SnapshotError("snapshot must not cross a nested filesystem mount")
            actual_directories.add(child.relative_to(tree).as_posix())
        for name in filenames:
            child = directory_path / name
            if child.is_symlink():
                raise SnapshotError("snapshot tree must not contain symlinks")
            actual_paths.add(child.relative_to(tree).as_posix())
    if actual_paths != expected_paths:
        raise SnapshotError("snapshot tree contains missing or unmanifested files")
    if actual_directories != expected_directories:
        raise SnapshotError("snapshot tree contains missing or unmanifested directories")

    return SnapshotEvidence(
        root=root,
        tree=tree,
        manifest_path=manifest_evidence.path,
        manifest_sha256=manifest_evidence.sha256,
        snapshot_sha256=snapshot_sha256,
        commit_sha=payload["commit_sha"],
        commit_tree_sha=payload["commit_tree_sha"],
        candidate_uid=candidate_uid,
        excluded_paths=tuple(payload["excluded_paths"]),
    )
