from __future__ import annotations

import hashlib
import hmac
import os
import re
import shutil
import stat
import subprocess
from dataclasses import dataclass
from pathlib import Path
from pathlib import PurePosixPath

from tools.ai_review.models import DiffFile
from tools.ai_review.models import PolicyReport
from tools.ai_review.models import TaskSpec
from tools.ai_review.sensitive_paths import sensitive_path_reason
from tools.ai_review.sensitive_paths import validate_empty_env_example


PROTECTED_PATTERNS = (
    ".streamlit/secrets.toml",
    "**/.streamlit/secrets.toml",
    ".git/**",
    "cache/**",
)
REF_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/@{}^~+-]*$")
ALLOWED_STATUSES = {"A", "M"}
ALLOWED_FILE_MODES = {"100644", "100755"}
GIT_TIMEOUT_SECONDS = 30
MAX_TRACKED_FILES = 2_000
MAX_TRACKED_FILE_BYTES = 100_000_000
MAX_TRACKED_TOTAL_BYTES = 500_000_000
MAX_WORKTREE_ENTRIES = 20_000
MAX_GIT_METADATA_ENTRIES = 50_000
GIT_EXECUTABLE = shutil.which("git", path=os.defpath)
if GIT_EXECUTABLE is None:
    raise RuntimeError("trusted system Git executable was not found")
GIT_ENVIRONMENT = {
    "GIT_ATTR_NOSYSTEM": "1",
    "GIT_CONFIG_GLOBAL": os.devnull,
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_CONFIG_SYSTEM": os.devnull,
    "GIT_NO_LAZY_FETCH": "1",
    "GIT_OPTIONAL_LOCKS": "0",
    "GIT_TERMINAL_PROMPT": "0",
    "LANG": "C",
    "LC_ALL": "C",
    "PATH": os.defpath,
}
GIT_GLOBAL_ARGUMENTS = (
    "--no-pager",
    "--no-replace-objects",
    "-c",
    "color.ui=false",
    "-c",
    "core.attributesFile=/dev/null",
    "-c",
    "core.fsmonitor=false",
    "-c",
    "core.fileMode=true",
    "-c",
    "diff.external=",
    "-c",
    "diff.ignoreSubmodules=none",
    "-c",
    "diff.renameLimit=0",
)


class GitInspectionError(RuntimeError):
    """Raised when deterministic Git evidence cannot be collected."""


@dataclass(frozen=True)
class GitFileMetadata:
    status: str
    old_mode: str
    new_mode: str
    old_blob: str
    new_blob: str


def _git(repo: Path, *arguments: str) -> bytes:
    try:
        result = subprocess.run(
            [GIT_EXECUTABLE, *GIT_GLOBAL_ARGUMENTS, *arguments],
            cwd=repo,
            check=False,
            capture_output=True,
            env=GIT_ENVIRONMENT,
            shell=False,
            timeout=GIT_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise GitInspectionError(f"isolated Git command failed: {type(error).__name__}") from error
    if result.returncode != 0:
        message = result.stderr.decode("utf-8", errors="replace").strip()
        raise GitInspectionError(message or f"git {' '.join(arguments)} failed")
    return result.stdout


def _resolve_commit(repo: Path, reference: str) -> str:
    if not REF_PATTERN.fullmatch(reference) or ".." in reference:
        raise GitInspectionError("invalid Git reference")
    value = _git(repo, "rev-parse", "--verify", f"{reference}^{{commit}}")
    resolved = value.decode("ascii", errors="strict").strip()
    if not re.fullmatch(r"[0-9a-f]{40}", resolved):
        raise GitInspectionError("Git did not return a full commit SHA")
    return resolved


def _verified_object_content(repo: Path, object_type: str, object_id: str) -> bytes:
    if re.fullmatch(r"[0-9a-f]{40}", object_id) is None:
        raise GitInspectionError("Git object id must be a full SHA-1")
    content = _git(repo, "cat-file", object_type, object_id)
    header = f"{object_type} {len(content)}\0".encode("ascii")
    actual_object_id = hashlib.sha1(header + content, usedforsecurity=False).hexdigest()
    if not hmac.compare_digest(actual_object_id, object_id):
        raise GitInspectionError(f"Git {object_type} content does not match its object id")
    return content


def _commit_tree_id(commit_content: bytes) -> str:
    tree_headers = [
        line.removeprefix(b"tree ")
        for line in commit_content.split(b"\n\n", 1)[0].splitlines()
        if line.startswith(b"tree ")
    ]
    if len(tree_headers) != 1:
        raise GitInspectionError("Git commit must contain exactly one tree header")
    try:
        tree_id = tree_headers[0].decode("ascii", errors="strict")
    except UnicodeDecodeError as error:
        raise GitInspectionError("Git commit tree id must be ASCII") from error
    if re.fullmatch(r"[0-9a-f]{40}", tree_id) is None:
        raise GitInspectionError("Git commit tree id must be a full SHA-1")
    return tree_id


def _verify_tree_graph(repo: Path, root_tree_id: str) -> None:
    pending = [root_tree_id]
    seen: set[str] = set()
    entry_count = 0
    while pending:
        tree_id = pending.pop()
        if tree_id in seen:
            continue
        seen.add(tree_id)
        content = _verified_object_content(repo, "tree", tree_id)
        offset = 0
        while offset < len(content):
            space = content.find(b" ", offset)
            nul = content.find(b"\0", space + 1)
            object_end = nul + 21
            if space <= offset or nul <= space + 1 or object_end > len(content):
                raise GitInspectionError("Git tree contains a malformed entry")
            mode = content[offset:space]
            name = content[space + 1 : nul]
            if b"/" in name or name in {b"", b".", b".."}:
                raise GitInspectionError("Git tree contains an unsafe entry name")
            object_id = content[nul + 1 : object_end].hex()
            entry_count += 1
            if entry_count > MAX_WORKTREE_ENTRIES:
                raise GitInspectionError(
                    f"candidate Git trees have more than {MAX_WORKTREE_ENTRIES} entries"
                )
            if mode in {b"40000", b"040000"}:
                pending.append(object_id)
            offset = object_end


def _verify_commit_and_tree_graph(repo: Path, commit_id: str) -> None:
    commit_content = _verified_object_content(repo, "commit", commit_id)
    _verify_tree_graph(repo, _commit_tree_id(commit_content))


def _safe_repo_path(path: str) -> bool:
    if not path or path.startswith(("/", "\\")) or "\\" in path:
        return False
    if any(part in {"", ".."} for part in PurePosixPath(path).parts):
        return False
    return not any(ord(character) < 32 for character in path)


def _glob_regex(pattern: str) -> re.Pattern[str]:
    """Compile a small POSIX glob where '*' never crosses a slash and '**' may."""

    expression = ""
    index = 0
    while index < len(pattern):
        if pattern.startswith("**/", index):
            expression += "(?:.*/)?"
            index += 3
        elif pattern.startswith("**", index):
            expression += ".*"
            index += 2
        elif pattern[index] == "*":
            expression += "[^/]*"
            index += 1
        elif pattern[index] == "?":
            expression += "[^/]"
            index += 1
        else:
            expression += re.escape(pattern[index])
            index += 1
    return re.compile(f"^{expression}$")


def _matches(
    path: str,
    patterns: list[str] | tuple[str, ...],
    *,
    case_sensitive: bool = True,
) -> bool:
    candidate = path if case_sensitive else path.casefold()
    return any(
        _glob_regex(pattern if case_sensitive else pattern.casefold()).fullmatch(candidate)
        is not None
        for pattern in patterns
    )


def _is_protected_path(path: str) -> bool:
    return sensitive_path_reason(path) is not None or _matches(
        path, PROTECTED_PATTERNS, case_sensitive=False
    )


def _diff_metadata(repo: Path, base_sha: str, head_sha: str) -> dict[str, GitFileMetadata]:
    raw = _git(
        repo,
        "diff",
        "--no-ext-diff",
        "--no-textconv",
        "--no-renames",
        "--ignore-submodules=none",
        "--abbrev=40",
        "--raw",
        "-z",
        base_sha,
        head_sha,
        "--",
    )
    try:
        fields = raw.decode("utf-8", errors="strict").split("\0")
    except UnicodeDecodeError as error:
        raise GitInspectionError("Git paths must be valid UTF-8") from error
    metadata: dict[str, GitFileMetadata] = {}
    populated_fields = [field for field in fields if field]
    if len(populated_fields) % 2:
        raise GitInspectionError("unexpected git raw diff output")
    for index in range(0, len(populated_fields), 2):
        header = populated_fields[index]
        path = populated_fields[index + 1]
        parts = header.split()
        if len(parts) != 5 or not parts[0].startswith(":"):
            raise GitInspectionError("unexpected git raw diff header")
        old_mode = parts[0][1:]
        new_mode = parts[1]
        old_blob = parts[2]
        new_blob = parts[3]
        status = parts[4]
        metadata[path] = GitFileMetadata(
            status=status,
            old_mode=old_mode,
            new_mode=new_mode,
            old_blob=old_blob,
            new_blob=new_blob,
        )
    return metadata


def _base_blob_paths(repo: Path, base_sha: str) -> dict[str, list[str]]:
    raw = _git(repo, "ls-tree", "-r", "-z", base_sha, "--")
    try:
        fields = [field for field in raw.decode("utf-8", errors="strict").split("\0") if field]
    except UnicodeDecodeError as error:
        raise GitInspectionError("Git paths must be valid UTF-8") from error
    blobs: dict[str, list[str]] = {}
    for field in fields:
        try:
            header, path = field.split("\t", 1)
            _mode, _object_type, object_id = header.split(" ", 2)
        except ValueError as error:
            raise GitInspectionError("unexpected git ls-tree output") from error
        blobs.setdefault(object_id, []).append(path)
    return blobs


def _detected_renames_and_copies(
    metadata: dict[str, GitFileMetadata],
    base_blobs: dict[str, list[str]],
) -> list[tuple[str, str, str]]:
    detected: list[tuple[str, str, str]] = []
    deleted_by_blob = {item.old_blob: path for path, item in metadata.items() if item.status == "D"}
    for new_path, item in metadata.items():
        if item.status != "A":
            continue
        old_path = deleted_by_blob.get(item.new_blob)
        if old_path is not None:
            detected.append(("R", old_path, new_path))
            continue
        source_paths = [path for path in base_blobs.get(item.new_blob, []) if path != new_path]
        if source_paths:
            detected.append(("C", sorted(source_paths)[0], new_path))
    return detected


def _numstat(
    repo: Path,
    base_sha: str,
    head_sha: str,
    paths: list[str],
) -> dict[str, tuple[int | None, int | None]]:
    if not paths:
        return {}
    raw = _git(
        repo,
        "diff",
        "--no-ext-diff",
        "--no-textconv",
        "--no-renames",
        "--ignore-submodules=none",
        "--numstat",
        "-z",
        base_sha,
        head_sha,
        "--",
        *paths,
    )
    try:
        fields = raw.decode("utf-8", errors="strict").split("\0")
    except UnicodeDecodeError as error:
        raise GitInspectionError("Git paths must be valid UTF-8") from error
    stats: dict[str, tuple[int | None, int | None]] = {}
    for field in fields:
        if not field:
            continue
        try:
            added, deleted, path = field.split("\t", 2)
        except ValueError as error:
            raise GitInspectionError("unexpected git numstat output") from error
        stats[path] = (
            None if added == "-" else int(added),
            None if deleted == "-" else int(deleted),
        )
    return stats


def _canonical_diff_hash(
    base_sha: str,
    head_sha: str,
    metadata: dict[str, GitFileMetadata],
) -> str:
    digest = hashlib.sha256()
    digest.update(b"amazon-explorer-ai-review-diff-v1\0")
    for value in (base_sha, head_sha):
        encoded = value.encode("ascii")
        digest.update(len(encoded).to_bytes(4, "big"))
        digest.update(encoded)
    for path in sorted(metadata):
        item = metadata[path]
        for value in (
            path,
            item.status,
            item.old_mode,
            item.new_mode,
            item.old_blob,
            item.new_blob,
        ):
            encoded = value.encode("utf-8")
            digest.update(len(encoded).to_bytes(4, "big"))
            digest.update(encoded)
    return digest.hexdigest()


def _reject_replace_refs(repo: Path) -> None:
    refs = _git(repo, "for-each-ref", "--format=%(refname)", "refs/replace")
    if refs.strip():
        raise GitInspectionError("repository contains a replace ref")


def _parse_index(repo: Path) -> dict[str, tuple[str, str]]:
    raw = _git(repo, "ls-files", "--stage", "-z")
    try:
        fields = [field for field in raw.decode("utf-8", errors="strict").split("\0") if field]
    except UnicodeDecodeError as error:
        raise GitInspectionError("Git index paths must be valid UTF-8") from error
    if len(fields) > MAX_TRACKED_FILES:
        raise GitInspectionError(f"candidate has more than {MAX_TRACKED_FILES} tracked files")
    entries: dict[str, tuple[str, str]] = {}
    for field in fields:
        try:
            header, path = field.split("\t", 1)
            mode, object_id, stage = header.split(" ", 2)
        except ValueError as error:
            raise GitInspectionError("unexpected Git index output") from error
        if stage != "0" or path in entries or not _safe_repo_path(path):
            raise GitInspectionError("candidate index contains an unsupported entry")
        entries[path] = (mode, object_id)
    return entries


def _parse_head_tree(repo: Path) -> dict[str, tuple[str, str]]:
    raw = _git(repo, "ls-tree", "-r", "-z", "HEAD", "--")
    try:
        fields = [field for field in raw.decode("utf-8", errors="strict").split("\0") if field]
    except UnicodeDecodeError as error:
        raise GitInspectionError("Git tree paths must be valid UTF-8") from error
    entries: dict[str, tuple[str, str]] = {}
    for field in fields:
        try:
            header, path = field.split("\t", 1)
            mode, object_type, object_id = header.split(" ", 2)
        except ValueError as error:
            raise GitInspectionError("unexpected Git tree output") from error
        if object_type not in {"blob", "commit"} or path in entries or not _safe_repo_path(path):
            raise GitInspectionError("candidate HEAD contains an unsupported entry")
        entries[path] = (mode, object_id)
    return entries


def _reject_untracked_paths(repo: Path, tracked_paths: set[str]) -> None:
    tracked_directories = {
        parent.as_posix()
        for path in tracked_paths
        for parent in PurePosixPath(path).parents
        if parent.as_posix() != "."
    }
    entry_count = 0
    for root, directories, filenames in os.walk(repo, followlinks=False):
        root_path = Path(root)
        if root_path == repo and ".git" in directories:
            directories.remove(".git")
        for name in [*directories, *filenames]:
            entry_count += 1
            if entry_count > MAX_WORKTREE_ENTRIES:
                raise GitInspectionError(
                    f"candidate worktree has more than {MAX_WORKTREE_ENTRIES} entries"
                )
            candidate_path = root_path / name
            if stat.S_ISLNK(candidate_path.lstat().st_mode):
                raise GitInspectionError(
                    "candidate worktree must not contain symlinks: "
                    + candidate_path.relative_to(repo).as_posix()
                )
            relative = candidate_path.relative_to(repo).as_posix()
            if relative not in tracked_paths and relative not in tracked_directories:
                raise GitInspectionError(
                    "candidate worktree must not contain untracked or ignored paths: " + relative
                )


def _reject_git_layout(repo: Path) -> None:
    git_directory = repo / ".git"
    try:
        git_stat = git_directory.lstat()
    except FileNotFoundError as error:
        raise GitInspectionError("candidate must use a standalone .git directory") from error
    if not stat.S_ISDIR(git_stat.st_mode) or git_directory.is_symlink():
        raise GitInspectionError("candidate must use a standalone .git directory")
    for forbidden_metadata in (
        git_directory / "commondir",
        git_directory / "info" / "attributes",
        git_directory / "objects" / "info" / "alternates",
        git_directory / "objects" / "info" / "http-alternates",
        git_directory / "worktrees",
    ):
        if forbidden_metadata.exists() or forbidden_metadata.is_symlink():
            raise GitInspectionError(
                "candidate Git metadata contains unsupported shared or external metadata"
            )

    entry_count = 0
    for root, directories, filenames in os.walk(git_directory, followlinks=False):
        root_path = Path(root)
        for name in [*directories, *filenames]:
            entry_count += 1
            if entry_count > MAX_GIT_METADATA_ENTRIES:
                raise GitInspectionError(
                    f"candidate Git metadata has more than {MAX_GIT_METADATA_ENTRIES} entries"
                )
            metadata_path = root_path / name
            metadata_stat = metadata_path.lstat()
            relative = metadata_path.relative_to(git_directory).as_posix()
            if stat.S_ISLNK(metadata_stat.st_mode):
                raise GitInspectionError(
                    "candidate Git metadata must not contain symlinks: " + relative
                )
            if os.path.ismount(metadata_path):
                raise GitInspectionError(
                    "candidate Git metadata must not contain nested mount points: " + relative
                )
            if not (stat.S_ISDIR(metadata_stat.st_mode) or stat.S_ISREG(metadata_stat.st_mode)):
                raise GitInspectionError(
                    "candidate Git metadata contains an unsupported filesystem entry: " + relative
                )
            if stat.S_ISREG(metadata_stat.st_mode) and metadata_stat.st_nlink != 1:
                raise GitInspectionError(
                    "candidate Git metadata files must not be hardlinks: " + relative
                )
            if hasattr(os, "getuid") and metadata_stat.st_uid != os.getuid():
                raise GitInspectionError(
                    "candidate Git metadata must be owned by the coordinator user: " + relative
                )
            if stat.S_IMODE(metadata_stat.st_mode) & 0o022:
                raise GitInspectionError(
                    "candidate Git metadata must not be group- or world-writable: " + relative
                )

    expected_git_directory = git_directory.resolve(strict=True)
    for argument, label in (
        ("--git-dir", "Git directory"),
        ("--git-common-dir", "Git common directory"),
    ):
        raw_path = _git(repo, "rev-parse", "--path-format=absolute", argument)
        try:
            reported_path = Path(raw_path.decode("utf-8", errors="strict").strip()).resolve(
                strict=True
            )
        except (OSError, UnicodeDecodeError) as error:
            raise GitInspectionError(f"{label} must be a valid local path") from error
        if reported_path != expected_git_directory:
            raise GitInspectionError(f"{label} must equal the standalone .git directory")
    object_format = _git(repo, "rev-parse", "--show-object-format")
    if object_format.decode("ascii", errors="strict").strip() != "sha1":
        raise GitInspectionError("candidate repository must use the SHA-1 Git object format")


def _reject_dirty_worktree(repo: Path) -> None:
    _reject_git_layout(repo)

    raw_index = _git(repo, "ls-files", "-v", "-z")
    try:
        index_entries = [
            entry for entry in raw_index.decode("utf-8", errors="strict").split("\0") if entry
        ]
    except UnicodeDecodeError as error:
        raise GitInspectionError("Git index paths must be valid UTF-8") from error
    if any(len(entry) < 3 or entry[0] != "H" or entry[1] != " " for entry in index_entries):
        raise GitInspectionError(
            "candidate index flags or state can hide worktree changes; require normal tracked entries"
        )

    index_entries = _parse_index(repo)
    if index_entries != _parse_head_tree(repo):
        raise GitInspectionError("candidate index must match HEAD exactly")
    _reject_untracked_paths(repo, set(index_entries))
    total_worktree_bytes = 0
    for path, (mode, object_id) in index_entries.items():
        if _is_protected_path(path) and PurePosixPath(path).name.casefold() != ".env.example":
            raise GitInspectionError(f"candidate HEAD contains a protected tracked path: {path}")
        if mode not in ALLOWED_FILE_MODES:
            raise GitInspectionError(f"candidate tracked file mode is unsupported: {path}")
        worktree_path = repo / path
        try:
            worktree_stat = worktree_path.lstat()
        except FileNotFoundError as error:
            raise GitInspectionError(f"candidate tracked file is missing: {path}") from error
        if not stat.S_ISREG(worktree_stat.st_mode):
            raise GitInspectionError(f"candidate tracked path is not a regular file: {path}")
        if worktree_stat.st_nlink != 1:
            raise GitInspectionError(f"candidate tracked file must not be a hardlink: {path}")
        expected_executable = mode == "100755"
        actual_executable = bool(stat.S_IMODE(worktree_stat.st_mode) & 0o111)
        if expected_executable != actual_executable:
            raise GitInspectionError(f"candidate tracked file mode differs from HEAD: {path}")
        if worktree_stat.st_size > MAX_TRACKED_FILE_BYTES:
            raise GitInspectionError(
                f"candidate tracked file exceeds {MAX_TRACKED_FILE_BYTES} bytes: {path}"
            )
        total_worktree_bytes += worktree_stat.st_size
        if total_worktree_bytes > MAX_TRACKED_TOTAL_BYTES:
            raise GitInspectionError(
                f"candidate tracked files exceed {MAX_TRACKED_TOTAL_BYTES} total bytes"
            )
        raw_hash = _git(repo, "hash-object", "--no-filters", "--", path)
        try:
            worktree_object_id = raw_hash.decode("ascii", errors="strict").strip()
        except UnicodeDecodeError as error:
            raise GitInspectionError("Git returned an invalid worktree blob id") from error
        if worktree_object_id != object_id:
            raise GitInspectionError(f"candidate worktree content differs from HEAD: {path}")
        if path == ".env.example":
            try:
                validate_empty_env_example(_verified_object_content(repo, "blob", object_id))
            except ValueError as exc:
                raise GitInspectionError(
                    "tracked .env.example is not a safe empty template"
                ) from exc


def _parse_identity(value: str, field: str) -> tuple[str, str, int, str]:
    identity, separator, timezone = value.rpartition(" ")
    if not separator:
        raise GitInspectionError(f"candidate commit has malformed {field} metadata")
    identity, separator, timestamp = identity.rpartition(" ")
    if not separator or not identity.endswith(">") or " <" not in identity:
        raise GitInspectionError(f"candidate commit has malformed {field} metadata")
    if not re.fullmatch(r"-?[0-9]+", timestamp) or not re.fullmatch(
        r"[+-](?:0[0-9]|1[0-4])[0-5][0-9]", timezone
    ):
        raise GitInspectionError(f"candidate commit has malformed {field} timestamp")
    name, email = identity[:-1].rsplit(" <", 1)
    return name, email, int(timestamp), timezone


def _inspect_candidate_commit(
    repo: Path,
    task: TaskSpec,
    base_sha: str,
    head_sha: str,
) -> list[str]:
    raw = _verified_object_content(repo, "commit", head_sha)
    try:
        header_bytes, message_bytes = raw.split(b"\n\n", 1)
        headers = header_bytes.decode("utf-8", errors="strict").splitlines()
        message = message_bytes.decode("utf-8", errors="strict")
    except (UnicodeDecodeError, ValueError) as error:
        raise GitInspectionError("candidate commit metadata must be valid UTF-8") from error

    parsed: dict[str, list[str]] = {}
    for header in headers:
        if header.startswith(" "):
            raise GitInspectionError("candidate commit contains a multiline metadata header")
        key, separator, value = header.partition(" ")
        if not separator:
            raise GitInspectionError("candidate commit contains malformed metadata")
        parsed.setdefault(key, []).append(value)

    parents = parsed.get("parent", [])
    if parents != [base_sha]:
        raise GitInspectionError(
            "candidate must be a single squash commit whose only parent is the task base"
        )
    if set(parsed) != {"tree", "parent", "author", "committer"}:
        raise GitInspectionError("candidate commit contains unsupported metadata headers")
    if any(len(parsed[key]) != 1 for key in parsed):
        raise GitInspectionError("candidate commit contains duplicate metadata headers")

    author_name, author_email, author_timestamp, author_timezone = _parse_identity(
        parsed["author"][0], "author"
    )
    committer_name, committer_email, committer_timestamp, committer_timezone = _parse_identity(
        parsed["committer"][0], "committer"
    )
    expected = task.candidate_commit
    violations: list[str] = []
    if message != expected.message + "\n":
        violations.append("candidate commit message does not match the task contract")
    if (author_name, author_email) != (expected.author_name, expected.author_email):
        violations.append("candidate commit author does not match the task contract")
    if (committer_name, committer_email) != (expected.author_name, expected.author_email):
        violations.append("candidate commit committer does not match the task contract")
    if (author_timestamp, author_timezone) != (expected.timestamp, expected.timezone):
        violations.append("candidate commit author timestamp does not match the task contract")
    if (committer_timestamp, committer_timezone) != (expected.timestamp, expected.timezone):
        violations.append("candidate commit committer timestamp does not match the task contract")
    return violations


def _blob_size(repo: Path, object_id: str) -> int:
    raw_size = _git(repo, "cat-file", "-s", object_id)
    try:
        size = int(raw_size.decode("ascii", errors="strict").strip())
    except (UnicodeDecodeError, ValueError) as error:
        raise GitInspectionError("Git returned an invalid blob size") from error
    return size


def _blob_content(repo: Path, object_id: str, expected_size: int) -> bytes:
    content = _verified_object_content(repo, "blob", object_id)
    if len(content) != expected_size:
        raise GitInspectionError("Git blob size changed during inspection")
    return content


def inspect_git_diff(
    repo: Path,
    task: TaskSpec,
    *,
    task_sha256: str,
    head: str = "HEAD",
    expected_patch_sha256: str | None = None,
) -> PolicyReport:
    """Inspect metadata first and never read a protected file's patch contents."""

    repo = repo.resolve(strict=True)
    _reject_git_layout(repo)
    _reject_replace_refs(repo)
    top_level = _git(repo, "rev-parse", "--show-toplevel")
    try:
        resolved_top_level = Path(top_level.decode("utf-8", errors="strict").strip()).resolve()
    except UnicodeDecodeError as error:
        raise GitInspectionError("repository root must be valid UTF-8") from error
    if resolved_top_level != repo:
        raise GitInspectionError("repository path must be the Git worktree root")
    base_sha = _resolve_commit(repo, task.base_sha)
    head_sha = _resolve_commit(repo, head)
    current_head_sha = _resolve_commit(repo, "HEAD")
    if head_sha != current_head_sha:
        raise GitInspectionError("policy must inspect the candidate repository's current HEAD")
    _verify_commit_and_tree_graph(repo, base_sha)
    _verify_commit_and_tree_graph(repo, head_sha)
    commit_violations = _inspect_candidate_commit(repo, task, base_sha, head_sha)
    metadata = _diff_metadata(repo, base_sha, head_sha)
    paths = sorted(metadata)
    violations = list(commit_violations)
    files: list[DiffFile] = []
    content_blocked = False
    clean_snapshot_checked = False

    if not paths:
        violations.append("candidate has no committed changes")
    if len(paths) > task.limits.max_changed_files:
        violations.append(
            f"changed file count {len(paths)} exceeds {task.limits.max_changed_files}"
        )
        content_blocked = True

    inspectable_paths: list[str] = []
    for path in paths:
        item = metadata[path]
        path_blocked = False
        if not _safe_repo_path(path):
            violations.append(f"unsafe repository path: {path!r}")
            path_blocked = True
        if _is_protected_path(path):
            violations.append(f"protected path changed: {path}")
            path_blocked = True
        if _matches(path, task.denied_paths, case_sensitive=False):
            violations.append(f"denied path changed: {path}")
            path_blocked = True
        if not _matches(path, task.allowed_paths):
            violations.append(f"path is outside allowed_paths: {path}")
            path_blocked = True
        if item.status not in ALLOWED_STATUSES:
            violations.append(f"unsupported Git status {item.status}: {path}")
            path_blocked = True
        if item.new_mode not in ALLOWED_FILE_MODES:
            violations.append(f"unsupported Git file mode {item.new_mode}: {path}")
            path_blocked = True
        if item.status == "M" and item.old_mode != item.new_mode:
            violations.append(f"file mode changes are not supported: {path}")
            path_blocked = True
        if path_blocked:
            content_blocked = True
        else:
            inspectable_paths.append(path)

    if violations:
        content_blocked = True
    if not content_blocked:
        base_blobs = _base_blob_paths(repo, base_sha)
        detected_operations = set(_detected_renames_and_copies(metadata, base_blobs))
        restricted_by_copy_or_rename: set[str] = set()
        for status, old_path, new_path in sorted(detected_operations):
            operation = "rename" if status.startswith("R") else "copy"
            violations.append(f"Git {operation} is not supported: {old_path} -> {new_path}")
            restricted_by_copy_or_rename.update((old_path, new_path))
        if restricted_by_copy_or_rename:
            inspectable_paths = [
                path for path in inspectable_paths if path not in restricted_by_copy_or_rename
            ]
            content_blocked = True
    if not content_blocked:
        _reject_dirty_worktree(repo)
        clean_snapshot_checked = True

    text_paths: list[str] = []
    binary_paths: set[str] = set()
    content_sha256_by_path: dict[str, str] = {}
    total_bytes = 0
    for path in inspectable_paths if not content_blocked else []:
        item = metadata[path]
        if item.status == "M":
            old_size = _blob_size(repo, item.old_blob)
            if old_size > task.limits.max_file_bytes:
                violations.append(
                    f"base file size {old_size} exceeds {task.limits.max_file_bytes}: {path}"
                )
                content_blocked = True
                break
            total_bytes += old_size
            if total_bytes > task.limits.max_total_bytes:
                violations.append(
                    f"total inspected blob size {total_bytes} exceeds {task.limits.max_total_bytes}"
                )
                content_blocked = True
                break
            _blob_content(repo, item.old_blob, old_size)
        size = _blob_size(repo, item.new_blob)
        total_bytes += size
        if size > task.limits.max_file_bytes:
            violations.append(f"file size {size} exceeds {task.limits.max_file_bytes}: {path}")
            content_blocked = True
            break
        if total_bytes > task.limits.max_total_bytes:
            violations.append(
                f"total inspected blob size {total_bytes} exceeds {task.limits.max_total_bytes}"
            )
            content_blocked = True
            break
        content = _blob_content(repo, item.new_blob, size)
        try:
            content.decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            binary_paths.add(path)
        if b"\x00" in content:
            binary_paths.add(path)
        if path in binary_paths:
            violations.append(f"binary diff is not supported: {path}")
            content_blocked = True
        else:
            text_paths.append(path)
            content_sha256_by_path[path] = hashlib.sha256(content).hexdigest()

    stats = {} if content_blocked else _numstat(repo, base_sha, head_sha, text_paths)
    for path in paths:
        item = metadata[path]
        additions, deletions = stats.get(path, (None, None))
        binary = path in binary_paths
        files.append(
            DiffFile(
                path=path,
                status=item.status,
                additions=additions,
                deletions=deletions,
                binary=binary,
                content_sha256=content_sha256_by_path.get(path),
            )
        )
        if path in text_paths and (additions is None or deletions is None):
            violations.append(f"Git did not return text statistics for: {path}")
            content_blocked = True

    total_added_lines = sum(item.additions or 0 for item in files)
    if total_added_lines > task.limits.max_added_lines:
        violations.append(
            f"added line count {total_added_lines} exceeds {task.limits.max_added_lines}"
        )

    patch_sha256 = None
    if not content_blocked:
        patch_sha256 = _canonical_diff_hash(base_sha, head_sha, metadata)
        if expected_patch_sha256 is not None and patch_sha256 != expected_patch_sha256:
            violations.append("patch SHA-256 does not match the expected value")
    elif expected_patch_sha256 is not None:
        violations.append("patch SHA-256 was not computed because restricted content changed")

    if clean_snapshot_checked:
        if _resolve_commit(repo, "HEAD") != head_sha:
            raise GitInspectionError("candidate HEAD changed during policy inspection")
        _reject_replace_refs(repo)
        _reject_dirty_worktree(repo)
        if _resolve_commit(repo, "HEAD") != head_sha:
            raise GitInspectionError("candidate HEAD changed during policy inspection")
        _verify_commit_and_tree_graph(repo, base_sha)
        _verify_commit_and_tree_graph(repo, head_sha)

    return PolicyReport(
        task_id=task.task_id,
        task_sha256=task_sha256,
        passed=not violations,
        trusted_harness_sha256=task.trusted_harness_sha256,
        base_sha=base_sha,
        head_sha=head_sha,
        patch_sha256=patch_sha256,
        changed_files=files,
        total_added_lines=total_added_lines,
        violations=violations,
    )
