from __future__ import annotations

from pathlib import PurePosixPath
from typing import Literal

from pydantic import BaseModel
from pydantic import ConfigDict
from pydantic import Field
from pydantic import field_validator
from pydantic import model_validator


SHA256_PATTERN = r"^[0-9a-f]{64}$"
GIT_SHA_PATTERN = r"^[0-9a-f]{40}$"


class StrictModel(BaseModel):
    """Base contract that rejects unknown fields instead of guessing intent."""

    model_config = ConfigDict(extra="forbid", strict=True)


def _validate_repo_pattern(value: str) -> str:
    if not value or value.startswith(("/", "\\")) or "\\" in value:
        raise ValueError("path patterns must be non-empty repository-relative POSIX paths")
    if any(part == ".." for part in PurePosixPath(value).parts):
        raise ValueError("path patterns must not contain '..'")
    if any(ord(character) < 32 for character in value):
        raise ValueError("path patterns must not contain control characters")
    return value


class Requirement(StrictModel):
    id: str = Field(pattern=r"^[A-Z][A-Z0-9_-]{0,63}$")
    text: str = Field(min_length=1, max_length=2000)


class AcceptanceTest(StrictModel):
    id: str = Field(pattern=r"^[A-Z][A-Z0-9_-]{0,63}$")
    kind: Literal["test", "quality"]
    command: list[str] = Field(min_length=1, max_length=64)
    expected_exit_code: int = Field(default=0, ge=0, le=255)
    expected_red_exit_codes: list[int] = Field(default_factory=list, max_length=16)
    expected_red_fingerprint_sha256: str | None = Field(default=None, pattern=SHA256_PATTERN)
    test_paths: list[str] = Field(default_factory=list, max_length=100)

    @field_validator("command")
    @classmethod
    def validate_command(cls, value: list[str]) -> list[str]:
        if any(not argument or "\x00" in argument for argument in value):
            raise ValueError("command arguments must be non-empty and contain no NUL bytes")
        return value

    @field_validator("test_paths")
    @classmethod
    def validate_test_paths(cls, value: list[str]) -> list[str]:
        paths = [_validate_repo_pattern(path) for path in value]
        if len(paths) != len(set(paths)):
            raise ValueError("acceptance test paths must be unique")
        if any(PurePosixPath(path).parts[0].casefold() != "tests" for path in paths):
            raise ValueError("acceptance test paths must be below tests/")
        return sorted(paths)

    @model_validator(mode="after")
    def validate_tdd_contract(self) -> AcceptanceTest:
        if len(set(self.expected_red_exit_codes)) != len(self.expected_red_exit_codes):
            raise ValueError("expected RED exit codes must be unique")
        if any(code < 0 or code > 255 for code in self.expected_red_exit_codes):
            raise ValueError("expected RED exit codes must be between 0 and 255")
        if self.kind == "test":
            if not self.expected_red_exit_codes or self.expected_red_fingerprint_sha256 is None:
                raise ValueError(
                    "test acceptance requires RED exit codes and a failure fingerprint"
                )
            if self.expected_exit_code in self.expected_red_exit_codes:
                raise ValueError("GREEN exit code must not be an expected RED exit code")
        elif (
            self.expected_red_exit_codes
            or self.expected_red_fingerprint_sha256 is not None
            or self.test_paths
        ):
            raise ValueError("quality acceptance must not define RED evidence")
        return self


class ReviewPromptDigests(StrictModel):
    reviewer_sha256: str = Field(pattern=SHA256_PATTERN)
    adversary_sha256: str = Field(pattern=SHA256_PATTERN)


class CandidateCommitPolicy(StrictModel):
    message: str = Field(min_length=1, max_length=128, pattern=r"^[^\r\n]+$")
    author_name: str = Field(min_length=1, max_length=128, pattern=r"^[^<>\r\n]+$")
    author_email: str = Field(
        min_length=3,
        max_length=254,
        pattern=r"^[^<>\s@]+@[^<>\s@]+$",
    )
    timestamp: int = Field(ge=0, le=4_102_444_800)
    timezone: str = Field(pattern=r"^[+-](?:0[0-9]|1[0-4])[0-5][0-9]$")


class DiffLimits(StrictModel):
    max_changed_files: int = Field(ge=1, le=500)
    max_added_lines: int = Field(ge=0, le=100_000)
    max_file_bytes: int = Field(default=2_000_000, ge=1, le=100_000_000)
    max_total_bytes: int = Field(default=10_000_000, ge=1, le=500_000_000)

    @model_validator(mode="after")
    def validate_byte_limits(self) -> DiffLimits:
        if self.max_total_bytes < self.max_file_bytes:
            raise ValueError("max_total_bytes must be greater than or equal to max_file_bytes")
        return self


class TaskSpec(StrictModel):
    schema_version: Literal["1.0", "2.0"]
    task_id: str = Field(pattern=r"^[A-Z][A-Z0-9_-]{0,63}$")
    base_sha: str = Field(pattern=GIT_SHA_PATTERN)
    trusted_harness_sha256: str = Field(pattern=SHA256_PATTERN)
    objective: str = Field(min_length=1, max_length=4000)
    requirements: list[Requirement] = Field(min_length=1, max_length=100)
    review_prompts: ReviewPromptDigests
    candidate_commit: CandidateCommitPolicy
    acceptance_tests: list[AcceptanceTest] = Field(min_length=1, max_length=100)
    allowed_paths: list[str] = Field(min_length=1, max_length=100)
    denied_paths: list[str] = Field(min_length=1, max_length=100)
    limits: DiffLimits
    network_policy: Literal["deny"]
    out_of_scope: list[str] = Field(default_factory=list, max_length=100)

    @field_validator("allowed_paths", "denied_paths")
    @classmethod
    def validate_patterns(cls, value: list[str]) -> list[str]:
        patterns = [_validate_repo_pattern(pattern) for pattern in value]
        if len(set(patterns)) != len(patterns):
            raise ValueError("path patterns must be unique")
        return patterns

    @field_validator("out_of_scope")
    @classmethod
    def validate_out_of_scope(cls, value: list[str]) -> list[str]:
        if any(not item.strip() for item in value):
            raise ValueError("out_of_scope entries must not be blank")
        return value

    @model_validator(mode="after")
    def validate_unique_ids(self) -> TaskSpec:
        requirement_ids = [requirement.id for requirement in self.requirements]
        acceptance_ids = [test.id for test in self.acceptance_tests]
        if len(set(requirement_ids)) != len(requirement_ids):
            raise ValueError("requirement ids must be unique")
        if len(set(acceptance_ids)) != len(acceptance_ids):
            raise ValueError("acceptance test ids must be unique")
        if self.schema_version == "2.0":
            missing_paths = [
                acceptance.id
                for acceptance in self.acceptance_tests
                if acceptance.kind == "test" and not acceptance.test_paths
            ]
            if missing_paths:
                raise ValueError(
                    "TaskSpec v2 test acceptance requires exact test_paths: "
                    + ", ".join(missing_paths)
                )
        return self


class DiffFile(StrictModel):
    path: str = Field(min_length=1, max_length=4096)
    status: str = Field(pattern=r"^[A-Z?]+$")
    additions: int | None = Field(default=None, ge=0)
    deletions: int | None = Field(default=None, ge=0)
    binary: bool = False
    content_sha256: str | None = Field(default=None, pattern=SHA256_PATTERN)


class PolicyReport(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    task_id: str = Field(pattern=r"^[A-Z][A-Z0-9_-]{0,63}$")
    task_sha256: str = Field(pattern=SHA256_PATTERN)
    passed: bool
    trusted_harness_sha256: str = Field(pattern=SHA256_PATTERN)
    base_sha: str = Field(pattern=GIT_SHA_PATTERN)
    head_sha: str = Field(pattern=GIT_SHA_PATTERN)
    patch_sha256: str | None = Field(default=None, pattern=SHA256_PATTERN)
    changed_files: list[DiffFile]
    total_added_lines: int = Field(ge=0)
    violations: list[str]

    @model_validator(mode="after")
    def validate_result_consistency(self) -> PolicyReport:
        if self.passed and self.violations:
            raise ValueError("a passing policy report cannot contain violations")
        if self.passed and self.patch_sha256 is None:
            raise ValueError("a passing policy report requires a patch hash")
        if self.passed and not self.changed_files:
            raise ValueError("a passing policy report requires at least one changed file")
        if self.passed and any(item.content_sha256 is None for item in self.changed_files):
            raise ValueError("a passing policy report requires every changed content hash")
        if not self.passed and not self.violations:
            raise ValueError("a failing policy report requires at least one violation")
        return self


class Finding(StrictModel):
    id: str = Field(pattern=r"^[A-Z][A-Z0-9_-]{0,63}$")
    severity: Literal["critical", "high", "medium", "low"]
    requirement_id: str | None = Field(default=None, max_length=64)
    path: str | None = Field(default=None, max_length=4096)
    line: int | None = Field(default=None, ge=1)
    evidence: str = Field(min_length=1, max_length=4000)
    proposed_test: str | None = Field(default=None, max_length=4000)

    @field_validator("path")
    @classmethod
    def validate_path(cls, value: str | None) -> str | None:
        return None if value is None else _validate_repo_pattern(value)


class ReviewReport(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    task_id: str = Field(pattern=r"^[A-Z][A-Z0-9_-]{0,63}$")
    task_sha256: str = Field(pattern=SHA256_PATTERN)
    role: Literal["reviewer", "adversary"]
    reviewer_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
    session_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
    prompt_sha256: str = Field(pattern=SHA256_PATTERN)
    decision: Literal["accept", "changes_required", "blocked"]
    base_sha: str = Field(pattern=GIT_SHA_PATTERN)
    head_sha: str = Field(pattern=GIT_SHA_PATTERN)
    patch_sha256: str = Field(pattern=SHA256_PATTERN)
    summary: str = Field(min_length=1, max_length=4000)
    findings: list[Finding] = Field(default_factory=list, max_length=200)
    unverified: list[str] = Field(default_factory=list, max_length=100)
    external_calls: bool = Field(
        description=(
            "Whether reviewed repository code contacted an external service or tool; "
            "this does not describe the AI inference request itself."
        )
    )

    @model_validator(mode="after")
    def validate_review(self) -> ReviewReport:
        if self.external_calls:
            raise ValueError("external calls are forbidden in the MVP review harness")
        if self.decision == "accept" and any(
            finding.severity in {"critical", "high"} for finding in self.findings
        ):
            raise ValueError("an accepted review cannot contain a critical or high finding")
        if self.decision != "accept" and not self.findings:
            raise ValueError("a non-accepting review requires at least one finding")
        finding_ids = [finding.id for finding in self.findings]
        if len(set(finding_ids)) != len(finding_ids):
            raise ValueError("finding ids must be unique within a review")
        return self


class GateResult(StrictModel):
    task_id: str = Field(pattern=r"^[A-Z][A-Z0-9_-]{0,63}$")
    task_sha256: str = Field(pattern=SHA256_PATTERN)
    head_sha: str = Field(pattern=GIT_SHA_PATTERN)
    patch_sha256: str = Field(pattern=SHA256_PATTERN)
    acceptance_test_id: str = Field(pattern=r"^[A-Z][A-Z0-9_-]{0,63}$")
    command: list[str] = Field(min_length=1, max_length=64)
    expected_exit_code: int = Field(ge=0, le=255)
    passed: bool
    exit_code: int = Field(ge=0, le=255)
    evidence_sha256: str = Field(pattern=SHA256_PATTERN)

    @field_validator("command")
    @classmethod
    def validate_command(cls, value: list[str]) -> list[str]:
        if any(not argument or "\x00" in argument for argument in value):
            raise ValueError("command arguments must be non-empty and contain no NUL bytes")
        return value

    @model_validator(mode="after")
    def validate_exit_code(self) -> GateResult:
        if self.passed != (self.exit_code == self.expected_exit_code):
            raise ValueError("gate result contradicts its process exit code")
        return self


class RedEvidence(StrictModel):
    exit_code: int = Field(ge=0, le=255)
    log_sha256: str = Field(pattern=SHA256_PATTERN)
    failure_fingerprint_sha256: str = Field(pattern=SHA256_PATTERN)
    test_patch_sha256: str = Field(pattern=SHA256_PATTERN)


class GreenEvidence(StrictModel):
    exit_code: int = Field(ge=0, le=255)
    log_sha256: str = Field(pattern=SHA256_PATTERN)
    test_patch_sha256: str = Field(pattern=SHA256_PATTERN)


class TddEvidence(StrictModel):
    schema_version: Literal["1.0", "2.0"] = "1.0"
    task_id: str = Field(pattern=r"^[A-Z][A-Z0-9_-]{0,63}$")
    task_sha256: str = Field(pattern=SHA256_PATTERN)
    base_sha: str = Field(pattern=GIT_SHA_PATTERN)
    head_sha: str = Field(pattern=GIT_SHA_PATTERN)
    patch_sha256: str = Field(pattern=SHA256_PATTERN)
    acceptance_test_id: str = Field(pattern=r"^[A-Z][A-Z0-9_-]{0,63}$")
    command: list[str] = Field(min_length=1, max_length=64)
    test_paths: list[str] = Field(min_length=1, max_length=100)
    test_manifest_sha256: str = Field(pattern=SHA256_PATTERN)
    test_patch_sha256: str = Field(pattern=SHA256_PATTERN)
    red_snapshot_sha256: str | None = Field(default=None, pattern=SHA256_PATTERN)
    green_snapshot_sha256: str | None = Field(default=None, pattern=SHA256_PATTERN)
    red: RedEvidence
    green: GreenEvidence

    @field_validator("command")
    @classmethod
    def validate_command(cls, value: list[str]) -> list[str]:
        if any(not argument or "\x00" in argument for argument in value):
            raise ValueError("command arguments must be non-empty and contain no NUL bytes")
        return value

    @field_validator("test_paths")
    @classmethod
    def validate_test_paths(cls, value: list[str]) -> list[str]:
        paths = [_validate_repo_pattern(path) for path in value]
        if len(set(paths)) != len(paths):
            raise ValueError("test paths must be unique")
        return sorted(paths)

    @model_validator(mode="after")
    def validate_snapshot_bindings(self) -> TddEvidence:
        if self.schema_version == "1.0":
            if self.red_snapshot_sha256 is not None or self.green_snapshot_sha256 is not None:
                raise ValueError("TDD v1 must not claim v2 snapshot bindings")
            return self
        if self.red_snapshot_sha256 is None or self.green_snapshot_sha256 is None:
            raise ValueError("TDD v2 requires RED and GREEN snapshot bindings")
        if self.red_snapshot_sha256 == self.green_snapshot_sha256:
            raise ValueError("TDD v2 requires distinct measured RED and GREEN snapshots")
        return self


class Verdict(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    task_id: str = Field(pattern=r"^[A-Z][A-Z0-9_-]{0,63}$")
    task_sha256: str = Field(pattern=SHA256_PATTERN)
    trusted_harness_sha256: str = Field(pattern=SHA256_PATTERN)
    base_sha: str = Field(pattern=GIT_SHA_PATTERN)
    head_sha: str = Field(pattern=GIT_SHA_PATTERN)
    patch_sha256: str | None = Field(default=None, pattern=SHA256_PATTERN)
    status: Literal["pass", "fail", "human_review"]
    gates: list[GateResult]
    blocking_findings: list[str]
    reasons: list[str]
    human_approval_required: Literal[True]

    @model_validator(mode="after")
    def validate_verdict(self) -> Verdict:
        if self.status != "fail" and not self.gates:
            raise ValueError("a non-failing verdict requires at least one deterministic gate")
        if self.status == "pass" and (self.blocking_findings or self.reasons):
            raise ValueError("a passing verdict cannot contain blockers or reasons")
        if self.status == "pass" and self.patch_sha256 is None:
            raise ValueError("a passing verdict requires a patch hash")
        if self.status != "fail" and any(not gate.passed for gate in self.gates):
            raise ValueError("a failed gate requires a failing verdict")
        if self.status != "fail" and self.blocking_findings:
            raise ValueError("blocking findings require a failing verdict")
        if self.status != "pass" and not self.reasons:
            raise ValueError("a non-passing verdict requires reasons")
        return self
