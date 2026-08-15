from __future__ import annotations

import hashlib
import hmac
import difflib
import json
import re
import shlex
from dataclasses import dataclass
from pathlib import Path
from pathlib import PurePosixPath
from typing import Any
from typing import Literal
from typing import Mapping
from typing import Sequence

from pydantic import BaseModel
from pydantic import ConfigDict
from pydantic import Field
from pydantic import model_validator

from tools.ai_review.models import GateResult
from tools.ai_review.models import PolicyReport
from tools.ai_review.models import TaskSpec
from tools.ai_review.models import TddEvidence
from tools.ai_review.judge import build_test_manifest_sha256
from tools.ai_review.preflight import PreflightError
from tools.ai_review.preflight import read_protected_file
from tools.ai_review.snapshot import MAX_FILE_BYTES
from tools.ai_review.snapshot import SnapshotError
from tools.ai_review.snapshot import SnapshotEvidence
from tools.ai_review.snapshot import verify_readonly_snapshot
from tools.ai_review.sensitive_paths import sensitive_path_reason


SHA256_PATTERN = r"^[0-9a-f]{64}$"
_SHA256_RE = re.compile(SHA256_PATTERN)
_PROTECTED_PATTERNS = (
    ".streamlit/secrets.toml",
    "**/.streamlit/secrets.toml",
    ".git",
    ".git/**",
    "cache",
    "cache/**",
)
_CREDENTIAL_PATTERNS = (
    re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"),
    re.compile(r"(?<![A-Z0-9])AKIA[A-Z0-9]{16}(?![A-Z0-9])"),
    re.compile(r"(?<![A-Za-z0-9])gh(?:p|o|u|s|r)_[A-Za-z0-9]{20,}"),
    re.compile(r"(?<![A-Za-z0-9])github_pat_[A-Za-z0-9_]{20,}"),
    re.compile(r"(?<![A-Za-z0-9])glpat-[A-Za-z0-9_-]{20,}"),
    re.compile(r"(?<![A-Za-z0-9])xox(?:a|b|p|r|s)-[A-Za-z0-9-]{20,}"),
    re.compile(r"(?<![A-Za-z0-9])sk-(?:proj-)?[A-Za-z0-9_-]{20,}"),
    re.compile(r"(?<![A-Za-z0-9])(?:sk|rk)_live_[A-Za-z0-9]{16,}"),
    re.compile(r"(?<![A-Za-z0-9])AIza[A-Za-z0-9_-]{30,}"),
    re.compile(r"(?<![A-Za-z0-9])npm_[A-Za-z0-9]{20,}"),
    re.compile(r"(?<![A-Za-z0-9])pypi-[A-Za-z0-9_-]{30,}"),
    re.compile(
        r"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\."
        r"[A-Za-z0-9_-]{16,}(?![A-Za-z0-9_-])"
    ),
    re.compile(r"(?i)(?:authorization\s*:\s*bearer\s+)[A-Za-z0-9._~+/=-]{12,}"),
    re.compile(
        r"(?i)\b[a-z][a-z0-9+.-]{1,31}://[^\s/:@]+:[^\s/@]{3,}@"
        r"[^\s/]+"
    ),
)
_SECRET_ASSIGNMENT_RE = re.compile(
    r"""
    (?<![A-Za-z0-9_])
    (?P<key_quote>["']?)
    (?P<key>[A-Za-z][A-Za-z0-9_]*)
    (?P=key_quote)
    [ \t]*(?P<delimiter>[:=])[ \t]*
    (?P<value>
        "(?:\\.|[^"\\])*"
        | '(?:\\.|[^'\\])*'
        | [^\s,;}\]"']+
    )
    """,
    re.IGNORECASE | re.VERBOSE,
)
_SENSITIVE_KEY_RE = re.compile(
    r"(?:^|_)(?:TOKEN|SECRET|PASSWORD|PASSWD|PASSPHRASE|CREDENTIALS?|"
    r"AUTHORIZATION|BEARER)(?:_|$)"
    r"|(?:^|_)(?:API|ACCESS|PRIVATE|SIGNING|SESSION)_KEY(?:_|$)"
    r"|(?:^|_)CLIENT_SECRET(?:_|$)"
    r"|(?:^|_)(?:DATABASE|DB)_URL(?:_|$)"
    r"|(?:^|_)CONNECTION_STRING(?:_|$)"
    r"|(?:^|_)DSN(?:_|$)",
    re.IGNORECASE,
)
_PLACEHOLDER_VALUES = frozenset(
    {
        "changeme",
        "dummy",
        "example",
        "fake",
        "n/a",
        "none",
        "not-set",
        "null",
        "placeholder",
        "redacted",
        "replace-me",
        "replace_me",
        "sample",
        "tbd",
        "test",
        "unset",
    }
)
_PLACEHOLDER_PREFIXES = (
    "dummy-",
    "dummy_",
    "example-",
    "example_",
    "fake-",
    "fake_",
    "placeholder-",
    "placeholder_",
    "redacted-",
    "redacted_",
    "replace-",
    "replace_",
    "sample-",
    "sample_",
    "test-",
    "test_",
    "your-",
    "your_",
)
_RUNTIME_REFERENCE_PREFIXES = (
    "$",
    "%",
    "config.",
    "env.",
    "getenv(",
    "os.",
    "process.env",
    "secrets.",
    "self.",
    "settings.",
    "st.secrets",
)


@dataclass(frozen=True)
class ReviewPacketLimits:
    """Hard byte and item bounds applied before a packet leaves the coordinator."""

    max_packet_bytes: int = 1_000_000
    max_diff_bytes: int = 500_000
    max_context_files: int = 24
    max_context_file_bytes: int = 100_000
    max_context_total_bytes: int = 400_000
    max_task_bytes: int = 100_000
    max_policy_bytes: int = 300_000
    max_gate_results: int = 100
    max_gate_bytes: int = 200_000
    max_tdd_evidence: int = 100
    max_tdd_bytes: int = 300_000

    def __post_init__(self) -> None:
        for name, value in vars(self).items():
            if isinstance(value, bool) or not isinstance(value, int) or value < 1:
                raise ValueError(f"{name} must be a positive integer")
        if self.max_context_total_bytes < self.max_context_file_bytes:
            raise ValueError("max_context_total_bytes must cover one maximum-size context file")


@dataclass(frozen=True)
class SnapshotReviewMaterial:
    """Text review material re-measured from two immutable snapshot trees."""

    base_snapshot: SnapshotEvidence
    candidate_snapshot: SnapshotEvidence
    trusted_diff: str
    trusted_diff_binding: TrustedDiffBinding
    context: Mapping[str, str]


class PacketModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)


class ReviewContextFile(PacketModel):
    path: str = Field(min_length=1, max_length=4096)
    content: str
    content_sha256: str = Field(pattern=SHA256_PATTERN)


class TrustedDiffBinding(PacketModel):
    """Coordinator attestation binding text diff bytes to one immutable snapshot."""

    task_sha256: str = Field(pattern=SHA256_PATTERN)
    base_sha: str = Field(pattern=r"^[0-9a-f]{40}$")
    head_sha: str = Field(pattern=r"^[0-9a-f]{40}$")
    candidate_digest_sha256: str = Field(pattern=SHA256_PATTERN)
    trusted_diff_sha256: str = Field(pattern=SHA256_PATTERN)
    snapshot_manifest_sha256: str = Field(pattern=SHA256_PATTERN)
    coordinator_attestation_sha256: str = Field(pattern=SHA256_PATTERN)


class ReviewArtifactDigests(PacketModel):
    task_sha256: str = Field(pattern=SHA256_PATTERN)
    policy_sha256: str = Field(pattern=SHA256_PATTERN)
    trusted_diff_sha256: str = Field(pattern=SHA256_PATTERN)
    context_manifest_sha256: str = Field(pattern=SHA256_PATTERN)
    gates_sha256: str = Field(pattern=SHA256_PATTERN)
    tdd_evidence_sha256: str = Field(pattern=SHA256_PATTERN)


class ReviewPacket(PacketModel):
    """Canonical text-only review input with no candidate filesystem handle."""

    schema_version: Literal["1.0"] = "1.0"
    task_sha256: str = Field(pattern=SHA256_PATTERN)
    task: TaskSpec
    policy: PolicyReport
    candidate_digest_sha256: str = Field(pattern=SHA256_PATTERN)
    trusted_diff: str
    trusted_diff_binding: TrustedDiffBinding
    context: tuple[ReviewContextFile, ...]
    gates: tuple[GateResult, ...]
    tdd_evidence: tuple[TddEvidence, ...]
    artifact_digests: ReviewArtifactDigests
    packet_sha256: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def validate_integrity(self) -> ReviewPacket:
        if not hmac.compare_digest(self.packet_sha256, compute_packet_sha256(self)):
            raise ValueError("packet SHA-256 does not match its canonical content")
        if self.artifact_digests.task_sha256 != self.task_sha256:
            raise ValueError("artifact task SHA-256 does not match packet binding")
        if self.trusted_diff_binding.candidate_digest_sha256 != self.candidate_digest_sha256:
            raise ValueError("trusted diff binding does not match candidate digest")
        if (
            self.artifact_digests.trusted_diff_sha256
            != self.trusted_diff_binding.trusted_diff_sha256
        ):
            raise ValueError("artifact diff SHA-256 does not match trusted diff binding")
        return self


def _canonical_json_bytes(value: Any) -> bytes:
    def jsonable(item: Any) -> Any:
        if isinstance(item, BaseModel):
            return item.model_dump(mode="json")
        if isinstance(item, Mapping):
            return {key: jsonable(nested) for key, nested in item.items()}
        if isinstance(item, (list, tuple)):
            return [jsonable(nested) for nested in item]
        return item

    return json.dumps(
        jsonable(value),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _sha256_canonical(value: Any) -> str:
    return hashlib.sha256(_canonical_json_bytes(value)).hexdigest()


def _glob_regex(pattern: str) -> re.Pattern[str]:
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


def _matches(path: str, patterns: Sequence[str]) -> bool:
    candidate = path.casefold()
    return any(_glob_regex(pattern.casefold()).fullmatch(candidate) for pattern in patterns)


def _safe_repo_path(path: str) -> bool:
    if not path or path.startswith(("/", "\\")) or "\\" in path:
        return False
    parts = PurePosixPath(path).parts
    return not any(part in {"", ".", ".."} for part in parts) and not any(
        ord(character) < 32 for character in path
    )


def _is_protected_path(path: str, denied_paths: Sequence[str]) -> bool:
    return (
        sensitive_path_reason(path) is not None
        or _matches(path, _PROTECTED_PATTERNS)
        or _matches(path, denied_paths)
    )


def _placeholder_or_runtime_reference(raw_value: str) -> bool:
    quoted = len(raw_value) >= 2 and raw_value[0] in {'"', "'"} and raw_value[-1] == raw_value[0]
    value = raw_value[1:-1] if quoted else raw_value
    normalized = value.strip().casefold()
    if not normalized:
        return True
    if normalized in _PLACEHOLDER_VALUES or normalized.startswith(_PLACEHOLDER_PREFIXES):
        return True
    if (
        (normalized.startswith("<") and normalized.endswith(">"))
        or (normalized.startswith("${") and normalized.endswith("}"))
        or (normalized.startswith("${{") and normalized.endswith("}}"))
        or (normalized.startswith("%") and normalized.endswith("%"))
        or re.fullmatch(r"[x*._-]{3,}", normalized) is not None
    ):
        return True
    if not quoted and (
        normalized.startswith(_RUNTIME_REFERENCE_PREFIXES) or "(" in normalized or "[" in normalized
    ):
        return True
    return False


def _reject_credentials(text: str, *, label: str) -> None:
    if "\x00" in text:
        raise ValueError(f"{label} contains a NUL byte")
    if any(pattern.search(text) for pattern in _CREDENTIAL_PATTERNS):
        raise ValueError(f"{label} contains credential-like content")
    for assignment in _SECRET_ASSIGNMENT_RE.finditer(text):
        if _SENSITIVE_KEY_RE.search(assignment.group("key")) and not (
            _placeholder_or_runtime_reference(assignment.group("value"))
        ):
            raise ValueError(f"{label} contains credential-like content")


def ensure_sanitized_text(text: str, *, label: str) -> None:
    """Reject NUL bytes and high-confidence credential material in broker text."""

    if not isinstance(text, str):
        raise ValueError(f"{label} must be text")
    _reject_credentials(text, label=label)


def _bounded_serialized(value: Any, maximum: int, *, label: str) -> None:
    size = len(_canonical_json_bytes(value))
    if size > maximum:
        raise ValueError(f"{label} size {size} exceeds limit {maximum}")


def _validate_base_bindings(task: TaskSpec, task_sha256: str, policy: PolicyReport) -> str:
    if _SHA256_RE.fullmatch(task_sha256) is None:
        raise ValueError("task SHA-256 must be 64 lowercase hexadecimal characters")
    if not hmac.compare_digest(task_sha256, policy.task_sha256):
        raise ValueError("task SHA-256 does not match policy evidence")
    if task.task_id != policy.task_id:
        raise ValueError("task ID does not match policy evidence")
    if task.base_sha != policy.base_sha:
        raise ValueError("task base SHA does not match policy evidence")
    if task.trusted_harness_sha256 != policy.trusted_harness_sha256:
        raise ValueError("trusted harness SHA does not match policy evidence")
    if not policy.passed:
        raise ValueError("review packet requires a passing policy")
    if policy.patch_sha256 is None:
        raise ValueError("passing policy has no canonical candidate digest")
    return policy.patch_sha256


def _validate_policy_paths(task: TaskSpec, policy: PolicyReport) -> None:
    for changed_file in policy.changed_files:
        if not _safe_repo_path(changed_file.path):
            raise ValueError("policy contains an unsafe repository-relative path")
        if _is_protected_path(changed_file.path, task.denied_paths):
            raise ValueError(f"policy contains protected path: {changed_file.path}")


def _validate_diff_paths(task: TaskSpec, policy: PolicyReport, trusted_diff: str) -> None:
    paths: list[str] = []
    for line in trusted_diff.splitlines():
        if not line.startswith("diff --git "):
            continue
        try:
            fields = shlex.split(line)
        except ValueError as exc:
            raise ValueError("trusted diff contains an unparseable path header") from exc
        if len(fields) != 4 or fields[:2] != ["diff", "--git"]:
            raise ValueError("trusted diff contains an invalid path header")
        old_path, new_path = fields[2:]
        if not old_path.startswith("a/") or not new_path.startswith("b/"):
            raise ValueError("trusted diff path headers must use a/ and b/ prefixes")
        old_path = old_path[2:]
        new_path = new_path[2:]
        if old_path != new_path:
            raise ValueError("trusted diff rename/copy path headers are not supported")
        if not _safe_repo_path(new_path):
            raise ValueError("trusted diff contains an unsafe repository-relative path")
        if _is_protected_path(new_path, task.denied_paths):
            raise ValueError(f"trusted diff contains protected path: {new_path}")
        paths.append(new_path)
    if not paths or len(paths) != len(set(paths)):
        raise ValueError("trusted diff must contain unique path headers")
    policy_paths = {item.path for item in policy.changed_files}
    if set(paths) != policy_paths:
        raise ValueError("trusted diff paths do not match the passing policy")


def _validate_trusted_diff_binding(
    binding: TrustedDiffBinding,
    *,
    task: TaskSpec,
    task_sha256: str,
    policy: PolicyReport,
    trusted_diff_sha256: str,
) -> None:
    if (
        binding.task_sha256 != task_sha256
        or binding.base_sha != task.base_sha
        or binding.head_sha != policy.head_sha
        or binding.candidate_digest_sha256 != policy.patch_sha256
        or binding.trusted_diff_sha256 != trusted_diff_sha256
    ):
        raise ValueError(
            "trusted diff binding does not match the task, candidate, snapshot, and diff bytes"
        )


def _validate_gates(
    task: TaskSpec,
    task_sha256: str,
    policy: PolicyReport,
    gates: Sequence[GateResult],
) -> tuple[GateResult, ...]:
    if not gates:
        raise ValueError("review packet requires deterministic gate evidence")
    expected = {acceptance.id: acceptance for acceptance in task.acceptance_tests}
    by_id: dict[str, GateResult] = {}
    for gate in gates:
        if gate.acceptance_test_id in by_id:
            raise ValueError("gate evidence IDs must be unique")
        by_id[gate.acceptance_test_id] = gate
        acceptance = expected.get(gate.acceptance_test_id)
        if acceptance is None:
            raise ValueError("gate evidence references an unknown acceptance test")
        if not gate.passed:
            raise ValueError("every deterministic gate must pass before AI review")
        if (
            gate.task_id != task.task_id
            or gate.task_sha256 != task_sha256
            or gate.head_sha != policy.head_sha
            or gate.patch_sha256 != policy.patch_sha256
        ):
            raise ValueError("gate evidence is not bound to this task and candidate")
        if (
            gate.command != acceptance.command
            or gate.expected_exit_code != acceptance.expected_exit_code
        ):
            raise ValueError("gate command does not match the TaskSpec acceptance test")
    if set(by_id) != set(expected):
        raise ValueError("gate evidence must cover every TaskSpec acceptance test")
    return tuple(by_id[key] for key in sorted(by_id))


def _validate_tdd(
    task: TaskSpec,
    task_sha256: str,
    policy: PolicyReport,
    evidence: Sequence[TddEvidence],
) -> tuple[TddEvidence, ...]:
    expected = {
        acceptance.id: acceptance
        for acceptance in task.acceptance_tests
        if acceptance.kind == "test"
    }
    by_id: dict[str, TddEvidence] = {}
    for item in evidence:
        if item.acceptance_test_id in by_id:
            raise ValueError("TDD evidence IDs must be unique")
        by_id[item.acceptance_test_id] = item
        acceptance = expected.get(item.acceptance_test_id)
        if acceptance is None:
            raise ValueError("TDD evidence references an unknown test acceptance")
        if (
            item.task_id != task.task_id
            or item.task_sha256 != task_sha256
            or item.base_sha != task.base_sha
            or item.head_sha != policy.head_sha
            or item.patch_sha256 != policy.patch_sha256
        ):
            raise ValueError("TDD evidence is not bound to this task and candidate")
        if item.command != acceptance.command:
            raise ValueError("TDD command does not match the TaskSpec acceptance test")
        if task.schema_version == "2.0" and item.test_paths != acceptance.test_paths:
            raise ValueError("TDD test paths do not match the TaskSpec acceptance test")
        if item.red.exit_code not in acceptance.expected_red_exit_codes:
            raise ValueError("TDD RED exit code is not allowed by the TaskSpec")
        if item.red.failure_fingerprint_sha256 != acceptance.expected_red_fingerprint_sha256:
            raise ValueError("TDD RED fingerprint does not match the TaskSpec")
        if item.green.exit_code != acceptance.expected_exit_code:
            raise ValueError("TDD GREEN exit code does not match the TaskSpec")
        if not (
            item.test_patch_sha256 == item.red.test_patch_sha256 == item.green.test_patch_sha256
        ):
            raise ValueError("TDD RED and GREEN must use the same test patch")
        expected_manifest = build_test_manifest_sha256(policy, item.test_paths)
        if expected_manifest is None or item.test_manifest_sha256 != expected_manifest:
            raise ValueError("TDD test manifest is not derived from policy content")
    if set(by_id) != set(expected):
        raise ValueError("TDD evidence must cover every test acceptance")
    return tuple(by_id[key] for key in sorted(by_id))


def _build_context(
    task: TaskSpec,
    context: Mapping[str, str],
    limits: ReviewPacketLimits,
) -> tuple[ReviewContextFile, ...]:
    if len(context) > limits.max_context_files:
        raise ValueError(
            f"context file count {len(context)} exceeds limit {limits.max_context_files}"
        )
    result: list[ReviewContextFile] = []
    total_bytes = 0
    for path in sorted(context):
        content = context[path]
        if not isinstance(path, str) or not _safe_repo_path(path):
            raise ValueError("context path must be a safe repository-relative POSIX path")
        if _is_protected_path(path, task.denied_paths):
            raise ValueError(f"context contains protected path: {path}")
        if not isinstance(content, str):
            raise ValueError("context content must be text")
        _reject_credentials(content, label=f"context file {path}")
        encoded = content.encode("utf-8", errors="strict")
        if len(encoded) > limits.max_context_file_bytes:
            raise ValueError(
                f"context file {path} size {len(encoded)} exceeds limit "
                f"{limits.max_context_file_bytes}"
            )
        total_bytes += len(encoded)
        if total_bytes > limits.max_context_total_bytes:
            raise ValueError(
                f"context total size {total_bytes} exceeds limit {limits.max_context_total_bytes}"
            )
        result.append(
            ReviewContextFile(
                path=path,
                content=content,
                content_sha256=hashlib.sha256(encoded).hexdigest(),
            )
        )
    return tuple(result)


def _snapshot_manifest_entries(
    snapshot: SnapshotEvidence,
    *,
    candidate_uid: int,
) -> dict[str, dict[str, Any]]:
    try:
        _manifest_evidence, raw = read_protected_file(
            snapshot.manifest_path,
            candidate_uid=candidate_uid,
            label="review snapshot manifest",
            expected_sha256=snapshot.manifest_sha256,
            max_bytes=32 * 1024 * 1024,
        )
        payload = json.loads(raw.decode("utf-8", errors="strict"), object_pairs_hook=_reject_pairs)
    except (PreflightError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("review snapshot manifest could not be re-measured") from exc
    if not isinstance(payload, dict) or not isinstance(payload.get("files"), list):
        raise ValueError("review snapshot manifest is invalid")
    entries: dict[str, dict[str, Any]] = {}
    for entry in payload["files"]:
        if not isinstance(entry, dict) or set(entry) != {"mode", "path", "sha256", "size"}:
            raise ValueError("review snapshot manifest entry is invalid")
        path = entry["path"]
        if not isinstance(path, str) or path in entries:
            raise ValueError("review snapshot manifest paths are invalid")
        entries[path] = entry
    return entries


def _reject_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("review snapshot manifest contains a duplicate JSON key")
        value[key] = item
    return value


def _read_snapshot_text(
    snapshot: SnapshotEvidence,
    entry: Mapping[str, Any],
    *,
    candidate_uid: int,
) -> tuple[bytes, str]:
    relative = entry["path"]
    try:
        _evidence, raw = read_protected_file(
            snapshot.tree.joinpath(*PurePosixPath(relative).parts),
            candidate_uid=candidate_uid,
            label=f"review snapshot file {relative}",
            expected_sha256=entry["sha256"],
            max_bytes=MAX_FILE_BYTES,
        )
        text = raw.decode("utf-8", errors="strict")
    except (PreflightError, UnicodeError) as exc:
        raise ValueError(f"review snapshot file is not verified UTF-8 text: {relative}") from exc
    if "\x00" in text:
        raise ValueError(f"review snapshot file contains a NUL byte: {relative}")
    return raw, text


def _render_snapshot_diff(
    *,
    task: TaskSpec,
    policy: PolicyReport,
    base_snapshot: SnapshotEvidence,
    candidate_snapshot: SnapshotEvidence,
    base_entries: Mapping[str, Mapping[str, Any]],
    candidate_entries: Mapping[str, Mapping[str, Any]],
    candidate_uid: int,
) -> str:
    actual: dict[str, str] = {}
    for path in sorted(set(base_entries) | set(candidate_entries)):
        old = base_entries.get(path)
        new = candidate_entries.get(path)
        if old == new:
            continue
        if new is None:
            raise ValueError("snapshot-derived review diff does not support deleted files")
        if old is None:
            actual[path] = "A"
        else:
            if old["mode"] != new["mode"]:
                raise ValueError("snapshot-derived review diff does not support mode changes")
            actual[path] = "M"

    expected = {item.path: item for item in policy.changed_files}
    if set(actual) != set(expected):
        raise ValueError("snapshot changes do not match the passing policy paths")
    sections: list[str] = []
    for path in sorted(actual):
        policy_file = expected[path]
        candidate_entry = candidate_entries[path]
        if policy_file.status != actual[path]:
            raise ValueError("snapshot change status does not match the passing policy")
        if policy_file.content_sha256 != candidate_entry["sha256"]:
            raise ValueError("snapshot content does not match the passing policy digest")
        if _is_protected_path(path, task.denied_paths):
            raise ValueError(f"snapshot-derived review diff contains protected path: {path}")

        old_entry = base_entries.get(path)
        old_raw = b""
        old_text = ""
        if old_entry is not None:
            old_raw, old_text = _read_snapshot_text(
                base_snapshot,
                old_entry,
                candidate_uid=candidate_uid,
            )
        new_raw, new_text = _read_snapshot_text(
            candidate_snapshot,
            candidate_entry,
            candidate_uid=candidate_uid,
        )
        old_final_newline = str(old_raw.endswith(bytes((10,)))).lower()
        new_final_newline = str(new_raw.endswith(bytes((10,)))).lower()
        old_label = f"a/{path}" if old_entry is not None else "/dev/null"
        new_label = f"b/{path}"
        header = [
            f"diff --git {shlex.quote(f'a/{path}')} {shlex.quote(new_label)}",
            f"status {actual[path]}",
            f"old-mode {old_entry['mode'] if old_entry is not None else '000000'}",
            f"new-mode {candidate_entry['mode']}",
            f"old-sha256 {old_entry['sha256'] if old_entry is not None else '0' * 64}",
            f"new-sha256 {candidate_entry['sha256']}",
            f"old-final-newline {old_final_newline}",
            f"new-final-newline {new_final_newline}",
        ]
        unified = list(
            difflib.unified_diff(
                old_text.splitlines(),
                new_text.splitlines(),
                fromfile=old_label,
                tofile=new_label,
                lineterm="",
                n=3,
            )
        )
        sections.append("\n".join([*header, *unified]) + "\n")
    if not sections:
        raise ValueError("snapshot-derived review diff is empty")
    return "".join(sections)


def derive_snapshot_review_material(
    *,
    task: TaskSpec,
    task_sha256: str,
    policy: PolicyReport,
    base_snapshot_root: Path,
    candidate_snapshot_root: Path,
    context_paths: Sequence[str],
    candidate_uid: int,
) -> SnapshotReviewMaterial:
    """Derive diff and context bytes only from re-verified immutable snapshots."""

    try:
        base = verify_readonly_snapshot(base_snapshot_root, candidate_uid=candidate_uid)
        candidate = verify_readonly_snapshot(candidate_snapshot_root, candidate_uid=candidate_uid)
    except SnapshotError as exc:
        raise ValueError("review snapshots failed immutable verification") from exc
    if base.commit_sha != task.base_sha or candidate.commit_sha != policy.head_sha:
        raise ValueError("review snapshots do not match the task base and policy head")
    candidate_digest = _validate_base_bindings(task, task_sha256, policy)
    base_entries = _snapshot_manifest_entries(base, candidate_uid=candidate_uid)
    candidate_entries = _snapshot_manifest_entries(candidate, candidate_uid=candidate_uid)
    trusted_diff = _render_snapshot_diff(
        task=task,
        policy=policy,
        base_snapshot=base,
        candidate_snapshot=candidate,
        base_entries=base_entries,
        candidate_entries=candidate_entries,
        candidate_uid=candidate_uid,
    )

    if len(context_paths) != len(set(context_paths)):
        raise ValueError("snapshot context paths must be unique")
    context: dict[str, str] = {}
    for path in sorted(context_paths):
        if not isinstance(path, str) or not _safe_repo_path(path):
            raise ValueError("snapshot context path is unsafe")
        if _is_protected_path(path, task.denied_paths):
            raise ValueError(f"snapshot context contains protected path: {path}")
        entry = candidate_entries.get(path)
        if entry is None:
            raise ValueError(f"snapshot context path is absent from the candidate: {path}")
        _raw, context[path] = _read_snapshot_text(
            candidate,
            entry,
            candidate_uid=candidate_uid,
        )

    diff_sha256 = hashlib.sha256(trusted_diff.encode("utf-8", errors="strict")).hexdigest()
    context_manifest = [
        {
            "path": path,
            "content_sha256": hashlib.sha256(content.encode("utf-8")).hexdigest(),
        }
        for path, content in sorted(context.items())
    ]
    material_binding = _sha256_canonical(
        {
            "domain": "amazon-explorer-snapshot-review-material-v1",
            "task_sha256": task_sha256,
            "base_snapshot_sha256": base.snapshot_sha256,
            "base_manifest_sha256": base.manifest_sha256,
            "base_commit_tree_sha": base.commit_tree_sha,
            "candidate_snapshot_sha256": candidate.snapshot_sha256,
            "candidate_manifest_sha256": candidate.manifest_sha256,
            "candidate_commit_tree_sha": candidate.commit_tree_sha,
            "candidate_digest_sha256": candidate_digest,
            "trusted_diff_sha256": diff_sha256,
            "context_manifest": context_manifest,
        }
    )
    binding = TrustedDiffBinding(
        task_sha256=task_sha256,
        base_sha=task.base_sha,
        head_sha=policy.head_sha,
        candidate_digest_sha256=candidate_digest,
        trusted_diff_sha256=diff_sha256,
        snapshot_manifest_sha256=candidate.manifest_sha256,
        coordinator_attestation_sha256=material_binding,
    )
    try:
        if verify_readonly_snapshot(base.root, candidate_uid=candidate_uid) != base:
            raise ValueError("base review snapshot changed during packet derivation")
        if verify_readonly_snapshot(candidate.root, candidate_uid=candidate_uid) != candidate:
            raise ValueError("candidate review snapshot changed during packet derivation")
    except SnapshotError as exc:
        raise ValueError("review snapshot changed during packet derivation") from exc
    return SnapshotReviewMaterial(
        base_snapshot=base,
        candidate_snapshot=candidate,
        trusted_diff=trusted_diff,
        trusted_diff_binding=binding,
        context=context,
    )


def build_review_packet_from_snapshots(
    *,
    task: TaskSpec,
    task_sha256: str,
    policy: PolicyReport,
    base_snapshot_root: Path,
    candidate_snapshot_root: Path,
    context_paths: Sequence[str],
    candidate_uid: int,
    gates: Sequence[GateResult],
    tdd_evidence: Sequence[TddEvidence],
    limits: ReviewPacketLimits = ReviewPacketLimits(),
) -> ReviewPacket:
    """Build a packet whose diff and context are measured, not caller-supplied text."""

    material = derive_snapshot_review_material(
        task=task,
        task_sha256=task_sha256,
        policy=policy,
        base_snapshot_root=base_snapshot_root,
        candidate_snapshot_root=candidate_snapshot_root,
        context_paths=context_paths,
        candidate_uid=candidate_uid,
    )
    return build_review_packet(
        task=task,
        task_sha256=task_sha256,
        policy=policy,
        trusted_diff=material.trusted_diff,
        trusted_diff_binding=material.trusted_diff_binding,
        context=material.context,
        gates=gates,
        tdd_evidence=tdd_evidence,
        limits=limits,
    )


def build_review_packet(
    *,
    task: TaskSpec,
    task_sha256: str,
    policy: PolicyReport,
    trusted_diff: str,
    trusted_diff_binding: TrustedDiffBinding,
    context: Mapping[str, str],
    gates: Sequence[GateResult],
    tdd_evidence: Sequence[TddEvidence],
    limits: ReviewPacketLimits = ReviewPacketLimits(),
) -> ReviewPacket:
    """Build a deterministic packet exclusively from coordinator-supplied text evidence."""

    candidate_digest = _validate_base_bindings(task, task_sha256, policy)
    _validate_policy_paths(task, policy)
    _reject_credentials(
        _canonical_json_bytes(task).decode("utf-8", errors="strict"),
        label="TaskSpec",
    )
    _reject_credentials(
        _canonical_json_bytes(policy).decode("utf-8", errors="strict"),
        label="PolicyReport",
    )
    _bounded_serialized(task, limits.max_task_bytes, label="TaskSpec")
    _bounded_serialized(policy, limits.max_policy_bytes, label="PolicyReport")

    if not isinstance(trusted_diff, str) or not trusted_diff:
        raise ValueError("trusted diff must be non-empty text")
    _reject_credentials(trusted_diff, label="trusted diff")
    _validate_diff_paths(task, policy, trusted_diff)
    diff_bytes = trusted_diff.encode("utf-8", errors="strict")
    if len(diff_bytes) > limits.max_diff_bytes:
        raise ValueError(
            f"trusted diff size {len(diff_bytes)} exceeds limit {limits.max_diff_bytes}"
        )
    trusted_diff_sha256 = hashlib.sha256(diff_bytes).hexdigest()
    _validate_trusted_diff_binding(
        trusted_diff_binding,
        task=task,
        task_sha256=task_sha256,
        policy=policy,
        trusted_diff_sha256=trusted_diff_sha256,
    )

    canonical_gates = _validate_gates(task, task_sha256, policy, gates)
    if len(canonical_gates) > limits.max_gate_results:
        raise ValueError("gate result count exceeds limit")
    _bounded_serialized(canonical_gates, limits.max_gate_bytes, label="gate evidence")
    _reject_credentials(
        _canonical_json_bytes(canonical_gates).decode("utf-8", errors="strict"),
        label="gate evidence",
    )

    canonical_tdd = _validate_tdd(task, task_sha256, policy, tdd_evidence)
    if len(canonical_tdd) > limits.max_tdd_evidence:
        raise ValueError("TDD evidence count exceeds limit")
    _bounded_serialized(canonical_tdd, limits.max_tdd_bytes, label="TDD evidence")
    _reject_credentials(
        _canonical_json_bytes(canonical_tdd).decode("utf-8", errors="strict"),
        label="TDD evidence",
    )

    canonical_context = _build_context(task, context, limits)
    context_manifest = [
        {"path": item.path, "content_sha256": item.content_sha256} for item in canonical_context
    ]
    artifacts = ReviewArtifactDigests(
        task_sha256=task_sha256,
        policy_sha256=_sha256_canonical(policy),
        trusted_diff_sha256=trusted_diff_sha256,
        context_manifest_sha256=_sha256_canonical(context_manifest),
        gates_sha256=_sha256_canonical(canonical_gates),
        tdd_evidence_sha256=_sha256_canonical(canonical_tdd),
    )
    body = {
        "schema_version": "1.0",
        "task_sha256": task_sha256,
        "task": task.model_dump(mode="json"),
        "policy": policy.model_dump(mode="json"),
        "candidate_digest_sha256": candidate_digest,
        "trusted_diff": trusted_diff,
        "trusted_diff_binding": trusted_diff_binding.model_dump(mode="json"),
        "context": tuple(item.model_dump(mode="json") for item in canonical_context),
        "gates": tuple(item.model_dump(mode="json") for item in canonical_gates),
        "tdd_evidence": tuple(item.model_dump(mode="json") for item in canonical_tdd),
        "artifact_digests": artifacts.model_dump(mode="json"),
    }
    packet = ReviewPacket.model_validate(
        {**body, "packet_sha256": hashlib.sha256(_canonical_json_bytes(body)).hexdigest()}
    )
    packet_size = len(canonical_packet_bytes(packet))
    if packet_size > limits.max_packet_bytes:
        raise ValueError(f"packet size {packet_size} exceeds limit {limits.max_packet_bytes}")
    return packet


def compute_packet_sha256(packet: ReviewPacket) -> str:
    body = packet.model_dump(mode="json", exclude={"packet_sha256"})
    return hashlib.sha256(_canonical_json_bytes(body)).hexdigest()


def canonical_packet_bytes(packet: ReviewPacket) -> bytes:
    if not hmac.compare_digest(packet.packet_sha256, compute_packet_sha256(packet)):
        raise ValueError("packet SHA-256 does not match its canonical content")
    return _canonical_json_bytes(packet) + b"\n"
