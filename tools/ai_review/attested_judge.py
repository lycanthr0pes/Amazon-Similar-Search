from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from collections.abc import Callable
from collections.abc import Mapping
from collections.abc import Sequence
from pathlib import Path
from typing import Literal

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import ConfigDict
from pydantic import Field
from pydantic import field_validator
from pydantic import model_validator

from tools.ai_review.attestation import AttestationError
from tools.ai_review.attestation import AttestationExpectation
from tools.ai_review.attestation import NonceLedger
from tools.ai_review.attestation import SignedAttestation
from tools.ai_review.attestation import argv_sha256
from tools.ai_review.attestation import canonical_json_bytes
from tools.ai_review.attestation import canonical_sha256
from tools.ai_review.attestation import verify_attestation_set
from tools.ai_review.broker_result import BrokerResultError
from tools.ai_review.broker_result import ParsedBrokerReview
from tools.ai_review.broker_result import parse_broker_review
from tools.ai_review.broker_executor import BrokerExecutionError
from tools.ai_review.broker_executor import BrokerExecutionEvidence
from tools.ai_review.broker_executor import BrokerLedgerEvidence
from tools.ai_review.broker_executor import MAX_PACKET_RESERVED_TOKENS
from tools.ai_review.broker_executor import measure_broker_ledger
from tools.ai_review.broker_egress_provisioner import BrokerEgressProvisioningError
from tools.ai_review.broker_egress_provisioner import ProvisionedBrokerExecutionEvidence
from tools.ai_review.broker_egress_provisioner import (
    validate_provisioned_broker_execution_evidence,
)
from tools.ai_review.broker_phase_protocol import BrokerPhaseProtocolError
from tools.ai_review.broker_phase_protocol import PreparedBrokerBatch
from tools.ai_review.broker_phase_protocol import finalize_provisioned_broker_execution
from tools.ai_review.broker_executor import (
    validate_successful_broker_executions_against_final_ledger,
)
from tools.ai_review.codex_adapter import BrokerBoundaryEvidence
from tools.ai_review.codex_adapter import BrokerInferenceEvidence
from tools.ai_review.codex_adapter import CodexUsage
from tools.ai_review.codex_adapter import IsolatedBrokerInvocation
from tools.ai_review.codex_adapter import MAX_OUTPUT_TOKENS
from tools.ai_review.codex_adapter import MAX_USAGE_JSONL_LINES
from tools.ai_review.codex_adapter import TOKEN_HARD_LIMIT
from tools.ai_review.codex_adapter import TOKEN_WARNING_THRESHOLD
from tools.ai_review.codex_adapter import ToolFreeResponsesRequest
from tools.ai_review.codex_adapter import broker_boundary_evidence_sha256
from tools.ai_review.codex_adapter import validated_tool_free_request_bytes
from tools.ai_review.judge import judge
from tools.ai_review.models import GIT_SHA_PATTERN
from tools.ai_review.models import SHA256_PATTERN
from tools.ai_review.models import GateResult
from tools.ai_review.models import PolicyReport
from tools.ai_review.models import ReviewReport
from tools.ai_review.models import StrictModel
from tools.ai_review.models import TaskSpec
from tools.ai_review.models import TddEvidence
from tools.ai_review.models import Verdict
from tools.ai_review.offline_runner import OfflineRunEvidence
from tools.ai_review.offline_runner import OfflineRunnerError
from tools.ai_review.offline_runner import validate_offline_run_evidence
from tools.ai_review.pricing_policy import ABSOLUTE_PACKET_COST_LIMIT_MICROUSD
from tools.ai_review.review_packet import ReviewPacket
from tools.ai_review.review_packet import canonical_packet_bytes
from tools.ai_review.review_packet import derive_snapshot_review_material
from tools.ai_review.snapshot import RedTddSnapshotEvidence
from tools.ai_review.snapshot import SnapshotError
from tools.ai_review.snapshot import SnapshotEvidence
from tools.ai_review.snapshot import build_snapshot_test_manifest
from tools.ai_review.snapshot import verify_readonly_snapshot
from tools.ai_review.snapshot import verify_red_tdd_snapshot


ArtifactType = Literal["task", "policy", "gate", "tdd-red", "tdd-green", "review"]
RunKind = Literal["task", "policy", "gate", "tdd-red", "tdd-green", "review"]
SELF_REPORTED_REASON = "review provenance is self-reported until a trusted coordinator attests it"
_RUN_REQUEST_DOMAIN = b"amazon-explorer-attested-run-request-v1\0"
_BROKER_LOG_DOMAIN = b"amazon-explorer-attested-broker-log-v1\0"
_BROKER_RUNNER_DOMAIN = b"amazon-explorer-attested-broker-runner-v1\0"
_BROKER_EGRESS_SET_DOMAIN = b"amazon-explorer-attested-broker-egress-set-v1\0"


class AttestedJudgeError(ValueError):
    """Raised internally when trusted inputs do not describe the supplied artifacts exactly."""


class FrozenStrictModel(StrictModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)


class TrustedAttestationContext(FrozenStrictModel):
    """Values obtained from external preflight and immutable snapshot verification."""

    runtime_manifest_sha256: str = Field(pattern=SHA256_PATTERN)
    coordinator_image_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    offline_runner_image_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    broker_image_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    broker_gateway_image_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    broker_egress_boundary_sha256: str = Field(pattern=SHA256_PATTERN)
    broker_allowlist_policy_sha256: str = Field(pattern=SHA256_PATTERN)
    broker_ledger_identity_sha256: str = Field(pattern=SHA256_PATTERN)
    broker_packet_reservation_limit: int = Field(
        ge=MAX_OUTPUT_TOKENS,
        le=MAX_PACKET_RESERVED_TOKENS,
    )
    broker_pricing_policy_sha256: str = Field(pattern=SHA256_PATTERN)
    broker_packet_cost_limit_microusd: int = Field(
        ge=1,
        le=ABSOLUTE_PACKET_COST_LIMIT_MICROUSD,
    )
    base_snapshot_sha256: str = Field(pattern=SHA256_PATTERN)
    base_snapshot_manifest_sha256: str = Field(pattern=SHA256_PATTERN)
    base_commit_tree_sha: str = Field(pattern=GIT_SHA_PATTERN)
    candidate_snapshot_sha256: str = Field(pattern=SHA256_PATTERN)
    candidate_snapshot_manifest_sha256: str = Field(pattern=SHA256_PATTERN)
    candidate_commit_tree_sha: str = Field(pattern=GIT_SHA_PATTERN)
    review_packet_sha256: str = Field(pattern=SHA256_PATTERN)
    review_output_schema_sha256: str = Field(pattern=SHA256_PATTERN)


class TrustedRunRequest(FrozenStrictModel):
    """Semantic request measured by the trusted coordinator before one isolated run."""

    schema_version: Literal["1.0"] = "1.0"
    kind: RunKind
    task_sha256: str = Field(pattern=SHA256_PATTERN)
    source_sha: str = Field(pattern=GIT_SHA_PATTERN)
    source_snapshot_sha256: str = Field(pattern=SHA256_PATTERN)
    candidate_sha256: str | None = Field(default=None, pattern=SHA256_PATTERN)
    snapshot_sha256: str = Field(pattern=SHA256_PATTERN)
    acceptance_test_id: str | None = Field(
        default=None,
        pattern=r"^[A-Z][A-Z0-9_-]{0,63}$",
    )
    command: tuple[str, ...] = Field(default=(), max_length=64)
    test_patch_sha256: str | None = Field(default=None, pattern=SHA256_PATTERN)
    test_manifest_sha256: str | None = Field(default=None, pattern=SHA256_PATTERN)
    prompt_sha256: str | None = Field(default=None, pattern=SHA256_PATTERN)
    input_sha256: str = Field(pattern=SHA256_PATTERN)
    provider: Literal["openai"] | None = None
    model: Literal["gpt-5.6-sol"] | None = None
    effort: Literal["high", "xhigh"] | None = None
    attempt: int | None = Field(default=None, ge=1, le=2)
    review_role: Literal["reviewer", "adversary"] | None = None

    @field_validator("command")
    @classmethod
    def validate_command(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if any(not argument or "\x00" in argument for argument in value):
            raise ValueError("run request arguments must be non-empty and contain no NUL bytes")
        return value

    @model_validator(mode="after")
    def validate_provider_fields(self) -> TrustedRunRequest:
        provider_values = (
            self.provider,
            self.model,
            self.effort,
            self.attempt,
            self.review_role,
        )
        if self.kind == "review" and any(value is None for value in provider_values):
            raise ValueError("review request requires provider, model, effort, attempt, and role")
        if self.kind != "review" and any(value is not None for value in provider_values):
            raise ValueError("non-review request must not claim model provider fields")
        tdd_values = (self.test_patch_sha256, self.test_manifest_sha256)
        if self.kind in {"tdd-red", "tdd-green"} and any(value is None for value in tdd_values):
            raise ValueError("TDD request requires test patch and test manifest SHA-256")
        if self.kind not in {"tdd-red", "tdd-green"} and any(
            value is not None for value in tdd_values
        ):
            raise ValueError("non-TDD request must not claim test patch or manifest evidence")
        return self


class TrustedRunBinding(FrozenStrictModel):
    """Coordinator-owned evidence; it must never be reconstructed from a signed statement."""

    role: str = Field(pattern=r"^[A-Za-z][A-Za-z0-9_.:-]{0,127}$")
    artifact_type: ArtifactType
    session_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
    runner_sha256: str = Field(pattern=SHA256_PATTERN)
    argv: tuple[str, ...] = Field(min_length=1, max_length=320)
    log_sha256: str = Field(pattern=SHA256_PATTERN)
    request: TrustedRunRequest
    request_sha256: str = Field(pattern=SHA256_PATTERN)
    response_sha256: str = Field(pattern=SHA256_PATTERN)

    @field_validator("argv")
    @classmethod
    def validate_argv(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if any(not argument or "\x00" in argument for argument in value):
            raise ValueError("run argv must be non-empty and contain no NUL bytes")
        return value

    @model_validator(mode="after")
    def validate_kind(self) -> TrustedRunBinding:
        if self.request.kind != self.artifact_type:
            raise ValueError("run request kind must match its artifact type")
        return self


class TrustedBrokerArtifacts(FrozenStrictModel):
    """Raw broker outputs held by the coordinator, never reconstructed from digest claims."""

    role: Literal["reviewer", "adversary"]
    canonical_request: bytes = Field(min_length=2, max_length=1_000_000)
    canonical_envelope: bytes = Field(min_length=2, max_length=6_000_000)


def run_request_sha256(request: TrustedRunRequest) -> str:
    return hashlib.sha256(_RUN_REQUEST_DOMAIN + canonical_json_bytes(request)).hexdigest()


def _broker_execution_log_sha256(evidence: BrokerExecutionEvidence) -> str:
    return hashlib.sha256(
        _BROKER_LOG_DOMAIN
        + canonical_json_bytes(
            {
                "exit_code": evidence.exit_code,
                "stderr_bytes": len(evidence.stderr),
                "stderr_sha256": evidence.stderr_sha256,
                "stdout_bytes": len(evidence.stdout),
                "stdout_sha256": evidence.stdout_sha256,
            }
        )
    ).hexdigest()


def broker_egress_boundary_set_sha256(
    executions: Sequence[ProvisionedBrokerExecutionEvidence],
) -> str:
    """Return one packet-wide digest for both role-specific internal networks."""

    if any(type(item) is not ProvisionedBrokerExecutionEvidence for item in executions):
        raise ValueError("broker egress evidence contains an unsupported value")
    by_role = {
        item.execution.role: (item.execution.broker_egress_boundary.broker_egress_boundary_sha256)
        for item in executions
    }
    if len(executions) != 2 or set(by_role) != {"reviewer", "adversary"}:
        raise ValueError("broker egress evidence must exactly cover reviewer and adversary")
    return hashlib.sha256(_BROKER_EGRESS_SET_DOMAIN + canonical_json_bytes(by_role)).hexdigest()


def _broker_runner_sha256(
    provisioned: ProvisionedBrokerExecutionEvidence,
    *,
    boundary_evidence_sha256: str,
    egress_boundary_set_sha256: str,
    packet_reservation_limit: int,
    packet_cost_limit_microusd: int,
    pricing_policy_sha256: str,
    final_ledger_records_sha256: str,
    final_cumulative_reserved_tokens: int,
    final_cumulative_reserved_cost_microusd: int,
) -> str:
    """Bind the measured runtime, isolation boundary, and durable execution record."""

    evidence = provisioned.execution
    return hashlib.sha256(
        _BROKER_RUNNER_DOMAIN
        + canonical_json_bytes(
            {
                "boundary_evidence_sha256": boundary_evidence_sha256,
                "evidence_sha256": evidence.evidence_sha256,
                "provisioned_evidence_sha256": provisioned.evidence_sha256,
                "broker_egress_lifecycle_sha256": (provisioned.broker_egress_lifecycle_sha256),
                "broker_gateway_image_digest": (
                    provisioned.egress_lifecycle.broker_gateway_image_digest
                ),
                "broker_allowlist_policy_sha256": (
                    provisioned.egress_lifecycle.broker_allowlist_policy_sha256
                ),
                "broker_egress_boundary_sha256": evidence.broker_egress_boundary_sha256,
                "egress_boundary_set_sha256": egress_boundary_set_sha256,
                "final_ledger_records_sha256": final_ledger_records_sha256,
                "broker_ledger_identity_sha256": evidence.broker_ledger_identity_sha256,
                "packet_reservation_limit": packet_reservation_limit,
                "packet_cost_limit_microusd": packet_cost_limit_microusd,
                "pricing_policy_sha256": pricing_policy_sha256,
                "final_cumulative_reserved_tokens": final_cumulative_reserved_tokens,
                "final_cumulative_reserved_cost_microusd": (
                    final_cumulative_reserved_cost_microusd
                ),
                "runtime_executable": str(evidence.runtime_executable),
                "runtime_name": evidence.runtime_name,
                "runtime_rootless": evidence.runtime_rootless,
                "runtime_seccomp_profile": evidence.runtime_seccomp_profile,
                "runtime_security_sha256": evidence.runtime_security_sha256,
                "runtime_sha256": evidence.runtime_sha256,
                "runtime_user_namespace": evidence.runtime_user_namespace,
            }
        )
    ).hexdigest()


def _reject_duplicate_json_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise AttestedJudgeError("raw broker ledger contains duplicate JSON keys")
        value[key] = item
    return value


def _canonical_ledger_json_bytes(value: object) -> bytes:
    """Match the ledger's canonical JSON without the I-JSON timestamp limit."""

    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError) as error:
        raise AttestedJudgeError("raw broker ledger records are invalid") from error


def _validate_final_broker_ledger_records(
    final_ledger: BrokerLedgerEvidence,
    *,
    provisioned_executions: Sequence[ProvisionedBrokerExecutionEvidence],
    context: TrustedAttestationContext,
) -> tuple[dict[str, object], ...]:
    try:
        payload = json.loads(
            final_ledger.records.decode("utf-8", errors="strict"),
            object_pairs_hook=_reject_duplicate_json_keys,
        )
    except (UnicodeError, json.JSONDecodeError, TypeError, ValueError) as error:
        raise AttestedJudgeError("raw broker ledger records are invalid") from error
    if (
        not isinstance(payload, dict)
        or set(payload) != {"packet_sha256", "records", "schema_version"}
        or payload["schema_version"] != "1.0"
        or payload["packet_sha256"] != context.review_packet_sha256
        or _canonical_ledger_json_bytes(payload) != final_ledger.records
        or not isinstance(payload["records"], list)
    ):
        raise AttestedJudgeError("raw broker ledger records are invalid")
    records: list[dict[str, object]] = []
    attempts_by_role: dict[str, list[int]] = {"reviewer": [], "adversary": []}
    cumulative = 0
    cumulative_cost = 0
    for raw_record in payload["records"]:
        if not isinstance(raw_record, dict) or set(raw_record) != {
            "attempt",
            "packet_sha256",
            "reservation_unix_ns",
            "reserved_cost_microusd",
            "reserved_tokens",
            "role",
        }:
            raise AttestedJudgeError("raw broker ledger records are invalid")
        role = raw_record["role"]
        attempt = raw_record["attempt"]
        reserved_tokens = raw_record["reserved_tokens"]
        reserved_cost = raw_record["reserved_cost_microusd"]
        reservation_unix_ns = raw_record["reservation_unix_ns"]
        if (
            role not in attempts_by_role
            or type(attempt) is not int
            or not 1 <= attempt <= 2
            or type(reserved_tokens) is not int
            or not 1 <= reserved_tokens <= context.broker_packet_reservation_limit
            or type(reserved_cost) is not int
            or not 1 <= reserved_cost <= final_ledger.broker_packet_cost_limit_microusd
            or type(reservation_unix_ns) is not int
            or reservation_unix_ns <= 0
            or raw_record["packet_sha256"] != context.review_packet_sha256
        ):
            raise AttestedJudgeError("raw broker ledger records are invalid")
        attempts_by_role[role].append(attempt)
        cumulative += reserved_tokens
        cumulative_cost += reserved_cost
        records.append(raw_record)
    if any(
        attempts != list(range(1, len(attempts) + 1)) or not 1 <= len(attempts) <= 2
        for attempts in attempts_by_role.values()
    ):
        raise AttestedJudgeError("raw broker attempts are not contiguous or exceed the limit")
    if (
        cumulative != final_ledger.cumulative_reserved_tokens
        or cumulative > context.broker_packet_reservation_limit
        or cumulative_cost != final_ledger.cumulative_reserved_cost_microusd
        or cumulative_cost > final_ledger.broker_packet_cost_limit_microusd
        or final_ledger.records_sha256 != hashlib.sha256(final_ledger.records).hexdigest()
    ):
        raise AttestedJudgeError("raw broker reservations do not match the cumulative cap")
    success_by_role = {item.execution.role: item.execution for item in provisioned_executions}
    if len(provisioned_executions) != 2 or set(success_by_role) != {
        "reviewer",
        "adversary",
    }:
        raise AttestedJudgeError("one provisioned broker success per review role is required")
    for role, execution in success_by_role.items():
        matches = [
            record
            for record in records
            if record["role"] == role and record["attempt"] == execution.attempt
        ]
        if (
            len(matches) != 1
            or matches[0]["reserved_tokens"] != execution.reserved_tokens
            or matches[0]["reserved_cost_microusd"] != execution.reserved_cost_microusd
        ):
            raise AttestedJudgeError(
                f"{role} successful execution does not match its ledger reservation"
            )
    return tuple(records)


def tdd_phase_artifact_payload(tdd: TddEvidence, phase: Literal["red", "green"]) -> dict:
    """Return a phase-only artifact so RED cannot depend on later GREEN evidence."""

    common = {
        "schema_version": tdd.schema_version,
        "phase": phase,
        "task_id": tdd.task_id,
        "task_sha256": tdd.task_sha256,
        "base_sha": tdd.base_sha,
        "acceptance_test_id": tdd.acceptance_test_id,
        "command": tdd.command,
        "test_paths": tdd.test_paths,
        "test_manifest_sha256": tdd.test_manifest_sha256,
        "test_patch_sha256": tdd.test_patch_sha256,
    }
    if phase == "red":
        return {
            **common,
            "snapshot_sha256": tdd.red_snapshot_sha256,
            "evidence": tdd.red.model_dump(mode="json"),
        }
    return {
        **common,
        "head_sha": tdd.head_sha,
        "patch_sha256": tdd.patch_sha256,
        "snapshot_sha256": tdd.green_snapshot_sha256,
        "evidence": tdd.green.model_dump(mode="json"),
    }


def tdd_phase_artifact_sha256(
    tdd: TddEvidence,
    phase: Literal["red", "green"],
) -> str:
    return canonical_sha256(tdd_phase_artifact_payload(tdd, phase))


def _fail(
    task: TaskSpec,
    policy: PolicyReport,
    gates: Sequence[GateResult],
    *,
    task_sha256: str,
    reasons: Sequence[str],
    blockers: Sequence[str] = (),
) -> Verdict:
    return Verdict(
        task_id=task.task_id,
        task_sha256=task_sha256,
        trusted_harness_sha256=task.trusted_harness_sha256,
        base_sha=task.base_sha,
        head_sha=policy.head_sha,
        patch_sha256=policy.patch_sha256,
        status="fail",
        gates=list(gates),
        blocking_findings=list(dict.fromkeys(blockers)),
        reasons=list(dict.fromkeys(reasons)) or ["attested evidence validation failed"],
        human_approval_required=True,
    )


def _expected_roles(task: TaskSpec) -> set[str]:
    roles = {"task", "policy", "reviewer", "adversary"}
    roles.update(f"gate:{acceptance.id}" for acceptance in task.acceptance_tests)
    for acceptance in task.acceptance_tests:
        if acceptance.kind == "test":
            roles.add(f"tdd-red:{acceptance.id}")
            roles.add(f"tdd-green:{acceptance.id}")
    return roles


def _exactly_once_by_key(values: Sequence, key, *, label: str) -> dict:
    keys = [key(value) for value in values]
    duplicates = sorted(name for name, count in Counter(keys).items() if count != 1)
    if duplicates:
        raise AttestedJudgeError(f"{label} must appear exactly once: {', '.join(duplicates)}")
    return dict(zip(keys, values, strict=True))


def _require_equal(role: str, label: str, actual: object, expected: object) -> None:
    if actual != expected:
        raise AttestedJudgeError(f"{role} trusted request {label} does not match the artifact")


def _require_broker_equal(role: str, label: str, actual: object, expected: object) -> None:
    if actual != expected:
        raise AttestedJudgeError(f"{role} broker {label} does not match trusted evidence")


def _is_sha256(value: object) -> bool:
    return isinstance(value, str) and re.fullmatch(SHA256_PATTERN, value) is not None


def _validate_review_packet(
    packet: ReviewPacket,
    *,
    task: TaskSpec,
    policy: PolicyReport,
    gates: Sequence[GateResult],
    tdd_evidence: Sequence[TddEvidence],
    context: TrustedAttestationContext,
    task_sha256: str,
    base_snapshot: SnapshotEvidence | None,
    candidate_snapshot: SnapshotEvidence | None,
    candidate_uid: int | None,
) -> None:
    try:
        canonical_packet_bytes(packet)
    except ValueError as error:
        raise AttestedJudgeError(f"review packet is invalid: {error}") from error
    checks = (
        ("SHA-256", packet.packet_sha256, context.review_packet_sha256),
        ("raw task SHA-256", packet.task_sha256, task_sha256),
        ("TaskSpec", packet.task, task),
        ("policy", packet.policy, policy),
        ("candidate digest", packet.candidate_digest_sha256, policy.patch_sha256),
        (
            "gates",
            packet.gates,
            tuple(sorted(gates, key=lambda item: item.acceptance_test_id)),
        ),
        (
            "TDD evidence",
            packet.tdd_evidence,
            tuple(sorted(tdd_evidence, key=lambda item: item.acceptance_test_id)),
        ),
    )
    for label, actual, expected in checks:
        if actual != expected:
            raise AttestedJudgeError(f"review packet {label} does not match attested artifacts")
    if base_snapshot is None or candidate_snapshot is None or candidate_uid is None:
        return
    try:
        material = derive_snapshot_review_material(
            task=task,
            task_sha256=task_sha256,
            policy=policy,
            base_snapshot_root=base_snapshot.root,
            candidate_snapshot_root=candidate_snapshot.root,
            context_paths=tuple(item.path for item in packet.context),
            candidate_uid=candidate_uid,
        )
    except ValueError as error:
        raise AttestedJudgeError(f"review packet snapshot material is invalid: {error}") from error
    snapshot_checks = (
        ("base snapshot", material.base_snapshot.snapshot_sha256, context.base_snapshot_sha256),
        (
            "base manifest",
            material.base_snapshot.manifest_sha256,
            context.base_snapshot_manifest_sha256,
        ),
        ("base commit tree", material.base_snapshot.commit_tree_sha, context.base_commit_tree_sha),
        (
            "candidate snapshot",
            material.candidate_snapshot.snapshot_sha256,
            context.candidate_snapshot_sha256,
        ),
        (
            "candidate manifest",
            material.candidate_snapshot.manifest_sha256,
            context.candidate_snapshot_manifest_sha256,
        ),
        (
            "candidate commit tree",
            material.candidate_snapshot.commit_tree_sha,
            context.candidate_commit_tree_sha,
        ),
        ("trusted diff", material.trusted_diff, packet.trusted_diff),
        ("trusted diff binding", material.trusted_diff_binding, packet.trusted_diff_binding),
        (
            "context bytes",
            tuple(sorted(material.context.items())),
            tuple((item.path, item.content) for item in packet.context),
        ),
    )
    for label, actual, expected in snapshot_checks:
        if actual != expected:
            raise AttestedJudgeError(
                f"review packet {label} does not match re-measured snapshot bytes"
            )


def _validate_tdd_snapshot_bindings(
    task: TaskSpec,
    tdd_evidence: Sequence[TddEvidence],
    context: TrustedAttestationContext,
) -> None:
    acceptances = {
        acceptance.id: acceptance
        for acceptance in task.acceptance_tests
        if acceptance.kind == "test"
    }
    for tdd in tdd_evidence:
        acceptance = acceptances.get(tdd.acceptance_test_id)
        if acceptance is None:
            continue
        if tdd.schema_version != "2.0":
            raise AttestedJudgeError(f"{tdd.acceptance_test_id} requires TDD v2 evidence")
        if tdd.red_snapshot_sha256 == context.base_snapshot_sha256:
            raise AttestedJudgeError(
                f"{tdd.acceptance_test_id} RED overlay snapshot equals its unpatched base"
            )
        if tdd.green_snapshot_sha256 != context.candidate_snapshot_sha256:
            raise AttestedJudgeError(
                f"{tdd.acceptance_test_id} GREEN snapshot does not match the candidate"
            )
        if tdd.test_paths != acceptance.test_paths:
            raise AttestedJudgeError(
                f"{tdd.acceptance_test_id} test paths do not match TaskSpec v2"
            )


def _validate_broker_request(
    *,
    role: Literal["reviewer", "adversary"],
    approved: ToolFreeResponsesRequest,
    packet: ReviewPacket,
    artifacts: TrustedBrokerArtifacts,
    binding: TrustedRunBinding,
    context: TrustedAttestationContext,
) -> None:
    try:
        measured = validated_tool_free_request_bytes(approved, expected_packet=packet)
    except ValueError as error:
        raise AttestedJudgeError(f"{role} canonical broker request is invalid: {error}") from error
    if measured != artifacts.canonical_request:
        raise AttestedJudgeError(
            f"{role} raw canonical request differs from the approved packet factory"
        )
    request_sha256 = hashlib.sha256(measured).hexdigest()
    checks = (
        ("role", approved.role, role),
        ("packet SHA-256", approved.packet_sha256, context.review_packet_sha256),
        ("request SHA-256", approved.request_sha256, request_sha256),
        ("run request SHA-256", binding.request_sha256, request_sha256),
        ("model", approved.model, binding.request.model),
        ("reasoning effort", approved.reasoning_effort, binding.request.effort),
        ("attempt", approved.attempt, binding.request.attempt),
    )
    for label, actual, expected in checks:
        if actual != expected:
            raise AttestedJudgeError(
                f"{role} canonical broker request {label} does not match trusted evidence"
            )
    output_schema = approved.payload["text"]["format"]["schema"]
    if canonical_sha256(output_schema) != context.review_output_schema_sha256:
        raise AttestedJudgeError(f"{role} output schema does not match trusted preflight")


def _validate_broker_evidence(
    *,
    role: Literal["reviewer", "adversary"],
    evidence: BrokerInferenceEvidence,
    artifacts: TrustedBrokerArtifacts,
    approved_request: ToolFreeResponsesRequest,
    packet: ReviewPacket,
    binding: TrustedRunBinding,
    context: TrustedAttestationContext,
    review: ReviewReport,
    execution: BrokerExecutionEvidence | None = None,
) -> ParsedBrokerReview:
    """Bind a measured broker exchange to its semantic request and signed statement."""

    request = binding.request
    _validate_broker_request(
        role=role,
        approved=approved_request,
        packet=packet,
        artifacts=artifacts,
        binding=binding,
        context=context,
    )
    try:
        parsed = parse_broker_review(
            artifacts.canonical_envelope,
            expected_request_sha256=binding.request_sha256,
            expected_packet_sha256=context.review_packet_sha256,
            role=role,
            attempt=request.attempt,
        )
    except BrokerResultError as error:
        raise AttestedJudgeError(f"{role} raw broker envelope is invalid: {error}") from error
    measured_usage = parsed.inference.usage
    if not isinstance(evidence.usage, CodexUsage):
        raise AttestedJudgeError(f"{role} broker evidence has invalid usage evidence")
    if type(evidence.attempt) is not int or not 1 <= evidence.attempt <= 2:
        raise AttestedJudgeError(f"{role} broker evidence has an invalid attempt")
    usage = evidence.usage
    usage_counts = (
        usage.input_tokens,
        usage.cached_input_tokens,
        usage.output_tokens,
        usage.reasoning_output_tokens,
        usage.event_count,
    )
    if any(type(value) is not int for value in usage_counts):
        raise AttestedJudgeError(f"{role} broker usage counts must be strict integers")
    if (
        usage.input_tokens < 0
        or usage.input_tokens > TOKEN_HARD_LIMIT
        or usage.cached_input_tokens < 0
        or usage.cached_input_tokens > usage.input_tokens
        or usage.output_tokens < 0
        or usage.output_tokens > MAX_OUTPUT_TOKENS
        or usage.reasoning_output_tokens < 0
        or usage.reasoning_output_tokens > usage.output_tokens
        or not 1 <= usage.event_count <= MAX_USAGE_JSONL_LINES
    ):
        raise AttestedJudgeError(f"{role} broker usage counts are outside approved bounds")
    if usage.input_tokens > approved_request.estimated_input_tokens:
        raise AttestedJudgeError(
            f"{role} broker actual input exceeds the approved request estimate"
        )
    if type(usage.warning_250k) is not bool or usage.warning_250k != (
        usage.input_tokens >= TOKEN_WARNING_THRESHOLD
    ):
        raise AttestedJudgeError(f"{role} broker token warning is inconsistent")
    if usage.hard_limit_exceeded is not False:
        raise AttestedJudgeError(f"{role} broker evidence exceeds the token hard limit")
    digest_values = (
        evidence.packet_sha256,
        evidence.request_sha256,
        evidence.response_sha256,
        evidence.usage_jsonl_sha256,
        evidence.usage.usage_jsonl_sha256,
    )
    if any(not _is_sha256(value) for value in digest_values):
        raise AttestedJudgeError(f"{role} broker evidence contains an invalid SHA-256")
    _require_broker_equal(
        role,
        "packet SHA-256",
        evidence.packet_sha256,
        context.review_packet_sha256,
    )
    _require_broker_equal(
        role,
        "request SHA-256",
        evidence.request_sha256,
        parsed.inference.request_sha256,
    )
    _require_broker_equal(
        role,
        "response SHA-256",
        evidence.response_sha256,
        parsed.inference.response_sha256,
    )
    _require_broker_equal(
        role,
        "usage log SHA-256",
        evidence.usage_jsonl_sha256,
        measured_usage.usage_jsonl_sha256,
    )
    _require_broker_equal(
        role,
        "nested usage log SHA-256",
        evidence.usage.usage_jsonl_sha256,
        evidence.usage_jsonl_sha256,
    )
    _require_broker_equal(role, "role", evidence.role, role)
    _require_broker_equal(role, "model", evidence.model, request.model)
    _require_broker_equal(
        role,
        "reasoning effort",
        evidence.reasoning_effort,
        request.effort,
    )
    _require_broker_equal(role, "attempt", evidence.attempt, request.attempt)
    _require_broker_equal(
        role,
        "request binding SHA-256",
        parsed.inference.request_sha256,
        binding.request_sha256,
    )
    _require_broker_equal(
        role,
        "response binding SHA-256",
        parsed.inference.response_sha256,
        binding.response_sha256,
    )
    if execution is None:
        _require_broker_equal(
            role,
            "usage binding SHA-256",
            measured_usage.usage_jsonl_sha256,
            binding.log_sha256,
        )
    else:
        if artifacts.canonical_request + b"\n" != execution.stdin:
            raise AttestedJudgeError(
                f"{role} raw broker request differs from isolated execution stdin"
            )
        if artifacts.canonical_envelope != execution.canonical_envelope:
            raise AttestedJudgeError(
                f"{role} raw broker envelope differs from isolated execution stdout"
            )
        _require_broker_equal(
            role,
            "execution request SHA-256",
            execution.request_sha256,
            parsed.inference.request_sha256,
        )
        _require_broker_equal(
            role,
            "execution response SHA-256",
            execution.response_sha256,
            parsed.inference.response_sha256,
        )
        _require_broker_equal(
            role,
            "raw execution log SHA-256",
            _broker_execution_log_sha256(execution),
            binding.log_sha256,
        )
    if measured_usage != evidence.usage:
        raise AttestedJudgeError(f"{role} broker usage evidence does not match the raw log")
    if parsed.inference != evidence:
        raise AttestedJudgeError(f"{role} broker inference does not match the raw envelope")
    if parsed.review != review:
        raise AttestedJudgeError(f"{role} review artifact does not match the raw broker envelope")
    if parsed.review.session_id != binding.session_id:
        raise AttestedJudgeError(f"{role} derived broker session does not match the run binding")
    return parsed


def _validate_request(
    binding: TrustedRunBinding,
    *,
    task_sha256: str,
    source_sha: str,
    source_snapshot_sha256: str,
    candidate_sha256: str | None,
    snapshot_sha256: str,
    acceptance_test_id: str | None = None,
    command: Sequence[str] = (),
    test_patch_sha256: str | None = None,
    test_manifest_sha256: str | None = None,
    prompt_sha256: str | None = None,
    input_sha256: str,
) -> None:
    request = binding.request
    role = binding.role
    _require_equal(role, "task SHA-256", request.task_sha256, task_sha256)
    _require_equal(role, "source commit", request.source_sha, source_sha)
    _require_equal(
        role,
        "source snapshot SHA-256",
        request.source_snapshot_sha256,
        source_snapshot_sha256,
    )
    _require_equal(role, "candidate digest", request.candidate_sha256, candidate_sha256)
    _require_equal(role, "snapshot SHA-256", request.snapshot_sha256, snapshot_sha256)
    _require_equal(role, "acceptance id", request.acceptance_test_id, acceptance_test_id)
    _require_equal(role, "command", request.command, tuple(command))
    _require_equal(role, "test patch SHA-256", request.test_patch_sha256, test_patch_sha256)
    _require_equal(
        role,
        "test manifest SHA-256",
        request.test_manifest_sha256,
        test_manifest_sha256,
    )
    if role in {"reviewer", "adversary"} and request.prompt_sha256 != prompt_sha256:
        raise AttestedJudgeError(f"{role} model prompt does not match the task")
    _require_equal(role, "prompt SHA-256", request.prompt_sha256, prompt_sha256)
    _require_equal(role, "input SHA-256", request.input_sha256, input_sha256)
    if role in {"reviewer", "adversary"}:
        expected_effort = "high" if role == "reviewer" else "xhigh"
        _require_equal(role, "provider", request.provider, "openai")
        _require_equal(role, "model", request.model, "gpt-5.6-sol")
        _require_equal(role, "reasoning effort", request.effort, expected_effort)
        _require_equal(role, "review role", request.review_role, role)
        if request.attempt is None or not 1 <= request.attempt <= 2:
            raise AttestedJudgeError(f"{role} model attempt is outside the approved range")
    if binding.artifact_type in {"task", "policy"} and (
        binding.request_sha256 != run_request_sha256(request)
    ):
        raise AttestedJudgeError(f"{role} request SHA-256 does not match the trusted RunRequest")


def _expectation(
    *,
    task: TaskSpec,
    policy: PolicyReport,
    task_sha256: str,
    context: TrustedAttestationContext,
    binding: TrustedRunBinding,
    artifact_type: ArtifactType,
    artifact_sha256: str,
    snapshot_sha256: str,
) -> AttestationExpectation:
    if binding.artifact_type != artifact_type:
        raise AttestedJudgeError(f"{binding.role} artifact type does not match the artifact")
    if binding.request.kind != artifact_type:
        raise AttestedJudgeError(f"{binding.role} request kind does not match the artifact")
    if policy.patch_sha256 is None:
        raise AttestedJudgeError("policy must provide a candidate digest for attestation")
    runner_image_digest = (
        context.coordinator_image_digest
        if artifact_type in {"task", "policy"}
        else context.broker_image_digest
        if artifact_type == "review"
        else context.offline_runner_image_digest
    )
    return AttestationExpectation(
        artifact_type=artifact_type,
        artifact_sha256=artifact_sha256,
        task_id=task.task_id,
        task_sha256=task_sha256,
        base_sha=task.base_sha,
        head_sha=policy.head_sha,
        candidate_sha256=policy.patch_sha256,
        snapshot_sha256=snapshot_sha256,
        runtime_manifest_sha256=context.runtime_manifest_sha256,
        runner_image_digest=runner_image_digest,
        runner_sha256=binding.runner_sha256,
        argv_sha256=argv_sha256(binding.argv),
        log_sha256=binding.log_sha256,
        role=binding.role,
        session_id=binding.session_id,
        request_sha256=binding.request_sha256,
        response_sha256=binding.response_sha256,
    )


def _offline_runner_sha256(evidence: OfflineRunEvidence) -> str:
    return canonical_sha256(
        {
            "runtime_name": evidence.runtime_name,
            "runtime_sha256": evidence.runtime_sha256,
            "runtime_security_sha256": evidence.runtime_security_sha256,
            "runtime_rootless": evidence.runtime_rootless,
            "runtime_user_namespace": evidence.runtime_user_namespace,
            "runtime_seccomp_profile": evidence.runtime_seccomp_profile,
        }
    )


def _trusted_binding_from_offline_run(
    evidence: OfflineRunEvidence,
    *,
    task: TaskSpec,
    policy: PolicyReport,
    artifact_type: Literal["gate", "tdd-red", "tdd-green"],
) -> TrustedRunBinding:
    request = evidence.request
    role = (
        f"gate:{request.acceptance_test_id}"
        if artifact_type == "gate"
        else f"{artifact_type}:{request.acceptance_test_id}"
    )
    trusted_request = TrustedRunRequest(
        kind=artifact_type,
        task_sha256=request.task_sha256,
        source_sha=request.source_commit_sha,
        source_snapshot_sha256=request.source_snapshot_sha256,
        candidate_sha256=request.candidate_sha256,
        snapshot_sha256=request.execution_snapshot_sha256,
        acceptance_test_id=request.acceptance_test_id,
        command=request.command,
        test_patch_sha256=request.test_patch_sha256,
        test_manifest_sha256=request.test_manifest_sha256,
        input_sha256=request.execution_snapshot_sha256,
    )
    if request.source_commit_sha not in {task.base_sha, policy.head_sha}:
        raise AttestedJudgeError(f"{role} offline source commit is not task-owned")
    return TrustedRunBinding(
        role=role,
        artifact_type=artifact_type,
        session_id=request.session_id,
        runner_sha256=_offline_runner_sha256(evidence),
        argv=evidence.argv,
        log_sha256=evidence.log_sha256,
        request=trusted_request,
        request_sha256=evidence.request_sha256,
        response_sha256=evidence.response_sha256,
    )


def derive_offline_artifacts(
    *,
    task: TaskSpec,
    policy: PolicyReport,
    task_sha256: str,
    raw_runs: Sequence[OfflineRunEvidence],
    base_snapshot: SnapshotEvidence,
    candidate_snapshot: SnapshotEvidence,
    red_snapshots: Sequence[RedTddSnapshotEvidence],
    offline_runner_image: str,
    context: TrustedAttestationContext,
    candidate_uid: int,
) -> tuple[list[GateResult], list[TddEvidence], list[TrustedRunBinding]]:
    try:
        base = verify_readonly_snapshot(base_snapshot.root, candidate_uid=candidate_uid)
        candidate = verify_readonly_snapshot(candidate_snapshot.root, candidate_uid=candidate_uid)
    except SnapshotError as error:
        raise AttestedJudgeError(f"offline source snapshots are invalid: {error}") from error
    if base != base_snapshot or candidate != candidate_snapshot:
        raise AttestedJudgeError("offline source snapshot evidence changed")
    if (
        base.commit_sha != task.base_sha
        or base.commit_tree_sha != context.base_commit_tree_sha
        or base.manifest_sha256 != context.base_snapshot_manifest_sha256
        or base.snapshot_sha256 != context.base_snapshot_sha256
        or candidate.commit_sha != policy.head_sha
        or candidate.commit_tree_sha != context.candidate_commit_tree_sha
        or candidate.manifest_sha256 != context.candidate_snapshot_manifest_sha256
        or candidate.snapshot_sha256 != context.candidate_snapshot_sha256
    ):
        raise AttestedJudgeError("offline source snapshots do not match trusted context")

    red_by_paths = _exactly_once_by_key(
        red_snapshots,
        lambda item: item.test_paths,
        label="RED snapshot test paths",
    )
    expected_test_paths = {
        tuple(acceptance.test_paths)
        for acceptance in task.acceptance_tests
        if acceptance.kind == "test"
    }
    if set(red_by_paths) != expected_test_paths:
        raise AttestedJudgeError("RED snapshots do not exactly cover TaskSpec test paths")
    verified_red: dict[str, RedTddSnapshotEvidence] = {}
    for acceptance in task.acceptance_tests:
        if acceptance.kind != "test":
            continue
        raw_red = red_by_paths[tuple(acceptance.test_paths)]
        try:
            red = verify_red_tdd_snapshot(
                raw_red,
                base_snapshot=base,
                candidate_snapshot=candidate,
                candidate_uid=candidate_uid,
            )
            green_manifest = build_snapshot_test_manifest(
                snapshot=candidate,
                test_paths=tuple(acceptance.test_paths),
                candidate_uid=candidate_uid,
            )
        except SnapshotError as error:
            raise AttestedJudgeError(
                f"{acceptance.id} RED/GREEN snapshot evidence is invalid: {error}"
            ) from error
        if red.test_manifest_sha256 != green_manifest.test_manifest_sha256:
            raise AttestedJudgeError(f"{acceptance.id} RED and GREEN test manifests do not match")
        verified_red[acceptance.id] = red

    raw_by_key = _exactly_once_by_key(
        raw_runs,
        lambda item: (item.request.phase, item.request.acceptance_test_id),
        label="raw offline runs",
    )
    expected_keys = {("gate", item.id) for item in task.acceptance_tests}
    expected_keys.update(
        (phase, item.id)
        for item in task.acceptance_tests
        if item.kind == "test"
        for phase in ("red", "green")
    )
    if set(raw_by_key) != expected_keys:
        raise AttestedJudgeError("raw offline runs do not exactly cover all acceptance phases")

    measured: dict[tuple[str, str], OfflineRunEvidence] = {}
    for key, raw in raw_by_key.items():
        phase, acceptance_id = key
        execution_snapshot = verified_red[acceptance_id].snapshot if phase == "red" else candidate
        try:
            measured[key] = validate_offline_run_evidence(
                raw,
                execution_snapshot=execution_snapshot,
                image=offline_runner_image,
                approved_image_digest=context.offline_runner_image_digest,
                candidate_uid=candidate_uid,
            )
        except OfflineRunnerError as error:
            raise AttestedJudgeError(
                f"{phase}:{acceptance_id} raw offline evidence is invalid: {error}"
            ) from error

    gates: list[GateResult] = []
    tdds: list[TddEvidence] = []
    bindings: list[TrustedRunBinding] = []
    for acceptance in task.acceptance_tests:
        gate = measured[("gate", acceptance.id)]
        expected_common = (
            (gate.request.task_sha256, task_sha256, "task SHA-256"),
            (gate.request.candidate_sha256, policy.patch_sha256, "candidate digest"),
            (
                gate.request.candidate_snapshot_sha256,
                candidate.snapshot_sha256,
                "candidate snapshot",
            ),
            (gate.request.source_snapshot_sha256, candidate.snapshot_sha256, "source snapshot"),
            (gate.request.source_commit_sha, policy.head_sha, "source commit"),
            (gate.request.source_commit_tree_sha, candidate.commit_tree_sha, "source tree"),
            (gate.request.command, tuple(acceptance.command), "command"),
        )
        for actual, expected, label in expected_common:
            if actual != expected:
                raise AttestedJudgeError(
                    f"gate:{acceptance.id} raw offline {label} does not match the task"
                )
        gates.append(
            GateResult(
                task_id=task.task_id,
                task_sha256=task_sha256,
                head_sha=policy.head_sha,
                patch_sha256=policy.patch_sha256,
                acceptance_test_id=acceptance.id,
                command=acceptance.command,
                expected_exit_code=acceptance.expected_exit_code,
                passed=gate.exit_code == acceptance.expected_exit_code,
                exit_code=gate.exit_code,
                evidence_sha256=gate.log_sha256,
            )
        )
        bindings.append(
            _trusted_binding_from_offline_run(
                gate,
                task=task,
                policy=policy,
                artifact_type="gate",
            )
        )
        if acceptance.kind != "test":
            continue
        red_snapshot = verified_red[acceptance.id]
        red = measured[("red", acceptance.id)]
        green = measured[("green", acceptance.id)]
        phase_checks = (
            (red.request.task_sha256, task_sha256, "RED task SHA-256"),
            (green.request.task_sha256, task_sha256, "GREEN task SHA-256"),
            (red.request.candidate_sha256, policy.patch_sha256, "RED candidate digest"),
            (green.request.candidate_sha256, policy.patch_sha256, "GREEN candidate digest"),
            (red.request.source_snapshot_sha256, base.snapshot_sha256, "RED source snapshot"),
            (red.request.source_commit_sha, task.base_sha, "RED source commit"),
            (red.request.source_commit_tree_sha, base.commit_tree_sha, "RED source tree"),
            (
                red.request.candidate_snapshot_sha256,
                candidate.snapshot_sha256,
                "RED candidate snapshot",
            ),
            (
                red.request.execution_snapshot_sha256,
                red_snapshot.snapshot.snapshot_sha256,
                "RED execution snapshot",
            ),
            (
                green.request.source_snapshot_sha256,
                candidate.snapshot_sha256,
                "GREEN source snapshot",
            ),
            (green.request.source_commit_sha, policy.head_sha, "GREEN source commit"),
            (
                green.request.source_commit_tree_sha,
                candidate.commit_tree_sha,
                "GREEN source tree",
            ),
            (
                green.request.execution_snapshot_sha256,
                candidate.snapshot_sha256,
                "GREEN execution snapshot",
            ),
            (red.request.command, tuple(acceptance.command), "RED command"),
            (green.request.command, tuple(acceptance.command), "GREEN command"),
            (red.request.test_patch_sha256, red_snapshot.test_patch_sha256, "RED test patch"),
            (
                green.request.test_patch_sha256,
                red_snapshot.test_patch_sha256,
                "GREEN test patch",
            ),
            (
                red.request.test_manifest_sha256,
                red_snapshot.test_manifest_sha256,
                "RED test manifest",
            ),
            (
                green.request.test_manifest_sha256,
                red_snapshot.test_manifest_sha256,
                "GREEN test manifest",
            ),
        )
        for actual, expected, label in phase_checks:
            if actual != expected:
                raise AttestedJudgeError(
                    f"{acceptance.id} raw offline {label} does not match trusted snapshots"
                )
        tdds.append(
            TddEvidence(
                schema_version="2.0",
                task_id=task.task_id,
                task_sha256=task_sha256,
                base_sha=task.base_sha,
                head_sha=policy.head_sha,
                patch_sha256=policy.patch_sha256,
                acceptance_test_id=acceptance.id,
                command=acceptance.command,
                test_paths=acceptance.test_paths,
                test_manifest_sha256=red_snapshot.test_manifest_sha256,
                test_patch_sha256=red_snapshot.test_patch_sha256,
                red_snapshot_sha256=red_snapshot.snapshot.snapshot_sha256,
                green_snapshot_sha256=candidate.snapshot_sha256,
                red={
                    "exit_code": red.exit_code,
                    "log_sha256": red.log_sha256,
                    "failure_fingerprint_sha256": red.failure_fingerprint_sha256,
                    "test_patch_sha256": red_snapshot.test_patch_sha256,
                },
                green={
                    "exit_code": green.exit_code,
                    "log_sha256": green.log_sha256,
                    "test_patch_sha256": red_snapshot.test_patch_sha256,
                },
            )
        )
        bindings.extend(
            (
                _trusted_binding_from_offline_run(
                    red,
                    task=task,
                    policy=policy,
                    artifact_type="tdd-red",
                ),
                _trusted_binding_from_offline_run(
                    green,
                    task=task,
                    policy=policy,
                    artifact_type="tdd-green",
                ),
            )
        )
    return gates, tdds, bindings


def derive_broker_run_bindings(
    *,
    task: TaskSpec,
    policy: PolicyReport,
    task_sha256: str,
    reviews: Sequence[ReviewReport],
    review_packet: ReviewPacket,
    broker_evidence: Sequence[BrokerInferenceEvidence],
    broker_requests: Sequence[ToolFreeResponsesRequest],
    broker_artifacts: Sequence[TrustedBrokerArtifacts],
    broker_invocations: Sequence[IsolatedBrokerInvocation],
    provisioned_broker_executions: Sequence[ProvisionedBrokerExecutionEvidence],
    broker_boundary_evidence: BrokerBoundaryEvidence,
    broker_ledger_path: Path | None,
    context: TrustedAttestationContext,
    candidate_uid: int,
    broker_runtime_which: Callable[[str], str | None] | None = None,
    broker_runtime_probe: Callable[..., object] | None = None,
    broker_runtime_command_runner: Callable[..., object] | None = None,
    _frozen_finalization: bool = False,
) -> list[TrustedRunBinding]:
    """Rebuild both review bindings from provisioned, lifecycle-measured executions."""

    roles = {"reviewer", "adversary"}
    try:
        broker_boundary_evidence.validate_for(review_packet)
        boundary_sha256 = broker_boundary_evidence_sha256(broker_boundary_evidence)
    except ValueError as error:
        raise AttestedJudgeError(f"raw broker boundary evidence is invalid: {error}") from error

    typed_sequences = (
        (broker_requests, ToolFreeResponsesRequest, "broker requests"),
        (broker_artifacts, TrustedBrokerArtifacts, "raw broker artifacts"),
        (broker_invocations, IsolatedBrokerInvocation, "broker invocations"),
        (
            provisioned_broker_executions,
            ProvisionedBrokerExecutionEvidence,
            "provisioned broker executions",
        ),
        (broker_evidence, BrokerInferenceEvidence, "broker inference evidence"),
    )
    for values, expected_type, label in typed_sequences:
        if any(type(value) is not expected_type for value in values):
            raise AttestedJudgeError(f"{label} contain an unsupported value")

    requests_by_role = _exactly_once_by_key(
        broker_requests,
        lambda item: item.role,
        label="broker request roles",
    )
    artifacts_by_role = _exactly_once_by_key(
        broker_artifacts,
        lambda item: item.role,
        label="raw broker artifact roles",
    )
    invocations_by_role = _exactly_once_by_key(
        broker_invocations,
        lambda item: item.role,
        label="broker invocation roles",
    )
    provisioned_by_role = _exactly_once_by_key(
        provisioned_broker_executions,
        lambda item: item.execution.role,
        label="provisioned broker execution roles",
    )
    inference_by_role = _exactly_once_by_key(
        broker_evidence,
        lambda item: item.role,
        label="broker evidence roles",
    )
    reviews_by_role = _exactly_once_by_key(
        reviews,
        lambda item: item.role,
        label="review roles",
    )
    for label, values in (
        ("broker requests", requests_by_role),
        ("raw broker artifacts", artifacts_by_role),
        ("broker invocations", invocations_by_role),
        ("provisioned broker executions", provisioned_by_role),
        ("broker evidence", inference_by_role),
        ("reviews", reviews_by_role),
    ):
        if set(values) != roles:
            raise AttestedJudgeError(f"{label} must exactly cover reviewer and adversary")

    try:
        egress_boundary_set_sha256 = broker_egress_boundary_set_sha256(
            provisioned_broker_executions
        )
    except ValueError as error:
        raise AttestedJudgeError(f"raw broker egress boundaries are invalid: {error}") from error
    if egress_boundary_set_sha256 != context.broker_egress_boundary_sha256:
        raise AttestedJudgeError(
            "raw broker role-specific egress boundaries do not match trusted context"
        )

    measured_provisioned: dict[str, ProvisionedBrokerExecutionEvidence] = {}
    parsed_by_role: dict[str, ParsedBrokerReview] = {}
    for role in ("reviewer", "adversary"):
        request = requests_by_role[role]
        invocation = invocations_by_role[role]
        raw_provisioned = provisioned_by_role[role]
        review = reviews_by_role[role]
        try:
            request_bytes = validated_tool_free_request_bytes(
                request,
                expected_packet=review_packet,
            )
            expected_request_sha256 = hashlib.sha256(request_bytes).hexdigest()
            expected_stdin_sha256 = hashlib.sha256(request_bytes + b"\n").hexdigest()
            expected_descriptor_argv_sha256 = hashlib.sha256(
                canonical_json_bytes(list(invocation.argv))
            ).hexdigest()
            if _frozen_finalization:
                provisioned = raw_provisioned
            else:
                if broker_ledger_path is None:
                    raise AttestedJudgeError("live broker validation requires its ledger path")
                runtime_options = {}
                if broker_runtime_which is not None:
                    runtime_options["which"] = broker_runtime_which
                if broker_runtime_probe is not None:
                    runtime_options["probe"] = broker_runtime_probe
                if broker_runtime_command_runner is not None:
                    runtime_options["command_runner"] = broker_runtime_command_runner
                provisioned = validate_provisioned_broker_execution_evidence(
                    raw_provisioned,
                    invocation=invocation,
                    expected_packet_sha256=context.review_packet_sha256,
                    expected_request_sha256=expected_request_sha256,
                    expected_boundary_evidence_sha256=boundary_sha256,
                    expected_role=role,
                    expected_attempt=request.attempt,
                    approved_image_digest=context.broker_image_digest,
                    expected_descriptor_argv_sha256=expected_descriptor_argv_sha256,
                    expected_stdin_sha256=expected_stdin_sha256,
                    expected_broker_gateway_image_digest=context.broker_gateway_image_digest,
                    expected_broker_allowlist_policy_sha256=(
                        context.broker_allowlist_policy_sha256
                    ),
                    ledger_path=broker_ledger_path,
                    expected_broker_ledger_identity_sha256=(context.broker_ledger_identity_sha256),
                    broker_packet_reservation_limit=context.broker_packet_reservation_limit,
                    expected_broker_pricing_policy_sha256=(context.broker_pricing_policy_sha256),
                    broker_packet_cost_limit_microusd=(context.broker_packet_cost_limit_microusd),
                    candidate_uid=candidate_uid,
                    **runtime_options,
                )
            measured = provisioned.execution
            parsed = parse_broker_review(
                measured.canonical_envelope,
                expected_request_sha256=expected_request_sha256,
                expected_packet_sha256=context.review_packet_sha256,
                role=role,
                attempt=request.attempt,
            )
        except (BrokerEgressProvisioningError, BrokerResultError, ValueError) as error:
            raise AttestedJudgeError(
                f"{role} provisioned broker execution is invalid: {error}"
            ) from error

        expected_artifacts = TrustedBrokerArtifacts(
            role=role,
            canonical_request=request_bytes,
            canonical_envelope=measured.canonical_envelope,
        )
        if artifacts_by_role[role] != expected_artifacts:
            raise AttestedJudgeError(
                f"{role} raw broker artifacts do not match isolated execution bytes"
            )
        if parsed.review != review or parsed.inference != inference_by_role[role]:
            raise AttestedJudgeError(
                f"{role} broker artifacts do not match the isolated execution envelope"
            )
        parsed_by_role[role] = parsed
        measured_provisioned[role] = provisioned

    provisioned_executions = list(measured_provisioned.values())
    executions = [item.execution for item in provisioned_executions]
    if _frozen_finalization:
        final_ledger = executions[-1].ledger
    else:
        assert broker_ledger_path is not None
        try:
            final_ledger = measure_broker_ledger(
                broker_ledger_path,
                packet_sha256=context.review_packet_sha256,
                broker_packet_reservation_limit=context.broker_packet_reservation_limit,
                broker_packet_cost_limit_microusd=(context.broker_packet_cost_limit_microusd),
                broker_pricing_policy_sha256=context.broker_pricing_policy_sha256,
                candidate_uid=candidate_uid,
            )
        except BrokerExecutionError as error:
            raise AttestedJudgeError(f"raw broker ledger is invalid: {error}") from error
    if (
        final_ledger.broker_ledger_identity_sha256 != context.broker_ledger_identity_sha256
        or final_ledger.broker_packet_reservation_limit != context.broker_packet_reservation_limit
        or final_ledger.broker_packet_cost_limit_microusd
        != context.broker_packet_cost_limit_microusd
        or final_ledger.broker_pricing_policy_sha256 != context.broker_pricing_policy_sha256
        or any(
            item.broker_ledger_identity_sha256 != context.broker_ledger_identity_sha256
            for item in executions
        )
        or any(
            item.broker_egress_boundary_sha256
            != item.broker_egress_boundary.broker_egress_boundary_sha256
            for item in executions
        )
    ):
        raise AttestedJudgeError("raw broker executions do not match trusted runtime boundaries")
    if len({item.evidence_sha256 for item in provisioned_executions}) != len(
        provisioned_executions
    ):
        raise AttestedJudgeError("reviewer and adversary require distinct provisioned executions")
    if len({item.broker_egress_lifecycle_sha256 for item in provisioned_executions}) != len(
        provisioned_executions
    ):
        raise AttestedJudgeError("reviewer and adversary require distinct egress lifecycles")
    if any(
        item.egress_lifecycle.broker_gateway_image_digest != context.broker_gateway_image_digest
        or item.egress_lifecycle.broker_allowlist_policy_sha256
        != context.broker_allowlist_policy_sha256
        or item.egress_lifecycle.cleanup_succeeded is not True
        for item in provisioned_executions
    ):
        raise AttestedJudgeError("provisioned broker lifecycle does not match trusted policy")
    if len({item.evidence_sha256 for item in executions}) != len(executions):
        raise AttestedJudgeError("reviewer and adversary require distinct broker executions")
    if len({item.container_name for item in executions}) != len(executions):
        raise AttestedJudgeError("reviewer and adversary require distinct broker containers")
    _validate_final_broker_ledger_records(
        final_ledger,
        provisioned_executions=provisioned_executions,
        context=context,
    )
    try:
        validate_successful_broker_executions_against_final_ledger(
            executions,
            final_ledger,
        )
    except BrokerExecutionError:
        raise AttestedJudgeError(
            "raw broker executions do not prove the complete cumulative attempt ledger"
        ) from None

    if policy.patch_sha256 is None:
        raise AttestedJudgeError("policy must provide a candidate digest for broker execution")
    bindings: list[TrustedRunBinding] = []
    for role in ("reviewer", "adversary"):
        request = requests_by_role[role]
        review = reviews_by_role[role]
        parsed = parsed_by_role[role]
        provisioned = measured_provisioned[role]
        measured = provisioned.execution
        trusted_request = TrustedRunRequest(
            kind="review",
            task_sha256=task_sha256,
            source_sha=policy.head_sha,
            source_snapshot_sha256=context.candidate_snapshot_sha256,
            candidate_sha256=policy.patch_sha256,
            snapshot_sha256=context.candidate_snapshot_sha256,
            prompt_sha256=review.prompt_sha256,
            input_sha256=context.review_packet_sha256,
            provider="openai",
            model=request.model,
            effort=request.reasoning_effort,
            attempt=request.attempt,
            review_role=role,
        )
        binding = TrustedRunBinding(
            role=role,
            artifact_type="review",
            session_id=parsed.review.session_id,
            runner_sha256=_broker_runner_sha256(
                provisioned,
                boundary_evidence_sha256=boundary_sha256,
                egress_boundary_set_sha256=egress_boundary_set_sha256,
                packet_reservation_limit=context.broker_packet_reservation_limit,
                packet_cost_limit_microusd=(context.broker_packet_cost_limit_microusd),
                pricing_policy_sha256=context.broker_pricing_policy_sha256,
                final_ledger_records_sha256=final_ledger.records_sha256,
                final_cumulative_reserved_tokens=(final_ledger.cumulative_reserved_tokens),
                final_cumulative_reserved_cost_microusd=(
                    final_ledger.cumulative_reserved_cost_microusd
                ),
            ),
            argv=measured.argv,
            log_sha256=_broker_execution_log_sha256(measured),
            request=trusted_request,
            request_sha256=measured.request_sha256,
            response_sha256=measured.response_sha256,
        )
        _validate_broker_evidence(
            role=role,
            evidence=inference_by_role[role],
            artifacts=artifacts_by_role[role],
            approved_request=request,
            packet=review_packet,
            binding=binding,
            context=context,
            review=review,
            execution=measured,
        )
        bindings.append(binding)
    return bindings


def _request_from_frozen_run(
    run: object,
    *,
    review_packet: ReviewPacket,
) -> ToolFreeResponsesRequest:
    """Rebuild one approved request from the exact prepared stdin bytes."""

    stdin = getattr(run, "stdin", None)
    if type(stdin) is not bytes or not stdin.endswith(b"\n"):
        raise AttestedJudgeError("frozen broker request is not canonical newline JSON")
    raw = stdin[:-1]
    try:
        payload = json.loads(raw.decode("utf-8", errors="strict"))
        reasoning = payload["reasoning"]
        request = ToolFreeResponsesRequest(
            payload=payload,
            request_sha256=getattr(run, "request_sha256"),
            packet_sha256=getattr(run, "packet_sha256"),
            role=getattr(run, "role"),
            attempt=getattr(run, "attempt"),
            model=payload["model"],
            reasoning_effort=reasoning["effort"],
            estimated_input_tokens=len(raw),
            warning_250k=len(raw) >= TOKEN_WARNING_THRESHOLD,
        )
        measured = validated_tool_free_request_bytes(request, expected_packet=review_packet)
    except (AttributeError, KeyError, TypeError, UnicodeError, ValueError) as error:
        raise AttestedJudgeError("frozen broker request is invalid") from error
    if measured != raw:
        raise AttestedJudgeError("frozen broker request changed canonical bytes")
    return request


def derive_frozen_broker_run_bindings(
    *,
    task: TaskSpec,
    policy: PolicyReport,
    task_sha256: str,
    reviews: Sequence[ReviewReport],
    review_packet: ReviewPacket,
    broker_evidence: Sequence[BrokerInferenceEvidence],
    broker_requests: Sequence[ToolFreeResponsesRequest],
    broker_artifacts: Sequence[TrustedBrokerArtifacts],
    prepared_broker_batch_raw: bytes,
    outer_broker_evidence_raw: bytes,
    broker_allowlist_policy: bytes,
    broker_pricing_policy: bytes,
    context: TrustedAttestationContext,
    candidate_uid: int,
) -> tuple[list[TrustedRunBinding], tuple[ProvisionedBrokerExecutionEvidence, ...]]:
    """Derive review bindings only from the PhaseResult-bound frozen broker pair.

    The prepared batch, outer evidence, and the two runtime-manifest-pinned policy
    byte strings are the authority.  No host SQLite pathname, runtime executable,
    caller-created invocation, or caller-created provisioned evidence is accepted.
    """

    if any(
        type(value) is not bytes or not value
        for value in (
            prepared_broker_batch_raw,
            outer_broker_evidence_raw,
            broker_allowlist_policy,
            broker_pricing_policy,
        )
    ):
        raise AttestedJudgeError("frozen broker inputs must be non-empty exact bytes")
    try:
        batch = PreparedBrokerBatch.parse(prepared_broker_batch_raw)
        provisioned = finalize_provisioned_broker_execution(
            prepared_broker_batch_raw,
            outer_broker_evidence_raw,
            allowlist_policy=broker_allowlist_policy,
            pricing_policy=broker_pricing_policy,
        )
    except BrokerPhaseProtocolError as error:
        raise AttestedJudgeError("frozen broker evidence finalization failed") from error
    if (
        batch.task_sha256 != task_sha256
        or batch.runtime_manifest_sha256 != context.runtime_manifest_sha256
        or batch.candidate_snapshot_sha256 != context.candidate_snapshot_sha256
        or batch.review_packet_sha256 != review_packet.packet_sha256
        or batch.review_packet_sha256 != context.review_packet_sha256
        or batch.candidate_uid != candidate_uid
        or batch.broker_gateway_image_digest != context.broker_gateway_image_digest
        or batch.broker_allowlist_policy_sha256 != context.broker_allowlist_policy_sha256
        or batch.broker_pricing_policy_sha256 != context.broker_pricing_policy_sha256
        or batch.broker_ledger_identity_sha256 != context.broker_ledger_identity_sha256
        or batch.broker_packet_reservation_limit != context.broker_packet_reservation_limit
        or batch.broker_packet_cost_limit_microusd != context.broker_packet_cost_limit_microusd
        or any(run.approved_image_digest != context.broker_image_digest for run in batch.runs)
    ):
        raise AttestedJudgeError("frozen broker batch changed a trusted workflow anchor")
    runtime_raw = (
        canonical_json_bytes(
            {
                "environment_sha256": batch.runtime.environment_sha256,
                "executable_sha256": batch.runtime.executable_sha256,
                "name": batch.runtime.name,
                "rootless": batch.runtime.rootless,
                "seccomp_profile": batch.runtime.seccomp_profile,
                "security_evidence_sha256": batch.runtime.security_evidence_sha256,
                "user_namespace": batch.runtime.user_namespace,
            }
        )
        + b"\n"
    )
    boundary = BrokerBoundaryEvidence(
        packet_sha256=review_packet.packet_sha256,
        external_preflight_sha256=hashlib.sha256(runtime_raw).hexdigest(),
        snapshot_manifest_sha256=context.candidate_snapshot_manifest_sha256,
        isolation_attestation_sha256=batch.runtime.security_evidence_sha256,
        candidate_filesystem_unmounted=True,
        read_only_snapshot_verified=True,
        network_isolation_verified=True,
        coordinator_attestation_verified=True,
    )
    try:
        boundary.validate_for(review_packet)
        boundary_sha256 = broker_boundary_evidence_sha256(boundary)
    except ValueError as error:
        raise AttestedJudgeError("frozen broker boundary evidence is invalid") from error
    if any(run.boundary_evidence_sha256 != boundary_sha256 for run in batch.runs):
        raise AttestedJudgeError("frozen broker runs changed their boundary binding")
    derived_requests = tuple(
        _request_from_frozen_run(run, review_packet=review_packet) for run in batch.runs
    )
    requests_by_role = _exactly_once_by_key(
        broker_requests,
        lambda item: item.role,
        label="broker request roles",
    )
    if set(requests_by_role) != {"reviewer", "adversary"} or any(
        requests_by_role[item.role] != item for item in derived_requests
    ):
        raise AttestedJudgeError("caller broker requests differ from the frozen prepared batch")
    invocations = tuple(run.invocation() for run in batch.runs)
    bindings = derive_broker_run_bindings(
        task=task,
        policy=policy,
        task_sha256=task_sha256,
        reviews=reviews,
        review_packet=review_packet,
        broker_evidence=broker_evidence,
        broker_requests=derived_requests,
        broker_artifacts=broker_artifacts,
        broker_invocations=invocations,
        provisioned_broker_executions=provisioned,
        broker_boundary_evidence=boundary,
        broker_ledger_path=None,
        context=context,
        candidate_uid=candidate_uid,
        _frozen_finalization=True,
    )
    return bindings, provisioned


def build_attestation_expectations(
    task: TaskSpec,
    policy: PolicyReport,
    reviews: Sequence[ReviewReport],
    gates: Sequence[GateResult],
    tdd_evidence: Sequence[TddEvidence],
    run_bindings: Sequence[TrustedRunBinding],
    review_packet: ReviewPacket,
    broker_evidence: Sequence[BrokerInferenceEvidence],
    broker_requests: Sequence[ToolFreeResponsesRequest],
    broker_artifacts: Sequence[TrustedBrokerArtifacts],
    *,
    context: TrustedAttestationContext,
    task_sha256: str,
    raw_offline_runs: Sequence[OfflineRunEvidence] | None = None,
    base_snapshot: SnapshotEvidence | None = None,
    candidate_snapshot: SnapshotEvidence | None = None,
    red_snapshots: Sequence[RedTddSnapshotEvidence] | None = None,
    offline_runner_image: str | None = None,
    broker_invocations: Sequence[IsolatedBrokerInvocation] | None = None,
    provisioned_broker_executions: (Sequence[ProvisionedBrokerExecutionEvidence] | None) = None,
    # Kept only to fail closed for callers that still try to authorize a pass
    # with executor evidence that has no independently measured egress lifecycle.
    raw_broker_executions: Sequence[BrokerExecutionEvidence] | None = None,
    broker_boundary_evidence: BrokerBoundaryEvidence | None = None,
    broker_ledger_path: Path | None = None,
    broker_runtime_which: Callable[[str], str | None] | None = None,
    broker_runtime_probe: Callable[..., object] | None = None,
    broker_runtime_command_runner: Callable[..., object] | None = None,
    prepared_broker_batch_raw: bytes | None = None,
    outer_broker_evidence_raw: bytes | None = None,
    broker_allowlist_policy: bytes | None = None,
    broker_pricing_policy: bytes | None = None,
    candidate_uid: int | None = None,
    _diagnostic_allow_unmeasured: bool = False,
) -> dict[str, AttestationExpectation]:
    """Reconstruct every expected signed field from artifacts and trusted run inputs."""

    if task.schema_version != "2.0":
        raise AttestedJudgeError("attested pass requires TaskSpec v2")
    strict_values = (
        raw_offline_runs,
        base_snapshot,
        candidate_snapshot,
        red_snapshots,
        offline_runner_image,
        candidate_uid,
    )
    strict_offline = all(value is not None for value in strict_values)
    if any(value is not None for value in strict_values) and not strict_offline:
        raise AttestedJudgeError("raw offline validation requires its complete trusted input set")
    if raw_broker_executions is not None:
        raise AttestedJudgeError(
            "low-level broker execution evidence cannot authorize attested pass"
        )
    legacy_broker_values = (
        broker_invocations,
        provisioned_broker_executions,
        broker_boundary_evidence,
        broker_ledger_path,
    )
    legacy_broker = all(value is not None for value in legacy_broker_values)
    if any(value is not None for value in legacy_broker_values) and not legacy_broker:
        raise AttestedJudgeError(
            "provisioned broker validation requires its complete trusted input set"
        )
    frozen_broker_values = (
        prepared_broker_batch_raw,
        outer_broker_evidence_raw,
        broker_allowlist_policy,
        broker_pricing_policy,
    )
    frozen_broker = all(value is not None for value in frozen_broker_values)
    if any(value is not None for value in frozen_broker_values) and not frozen_broker:
        raise AttestedJudgeError(
            "frozen broker validation requires its complete canonical byte set"
        )
    if frozen_broker and any(value is not None for value in legacy_broker_values):
        raise AttestedJudgeError(
            "frozen broker validation rejects caller-supplied execution evidence"
        )
    strict_broker = frozen_broker or legacy_broker
    effective_gates = list(gates)
    effective_tdds = list(tdd_evidence)
    effective_bindings = list(run_bindings)
    measured_broker_executions_by_role: dict[str, BrokerExecutionEvidence] = {}
    if strict_offline:
        assert raw_offline_runs is not None
        assert base_snapshot is not None
        assert candidate_snapshot is not None
        assert red_snapshots is not None
        assert offline_runner_image is not None
        assert candidate_uid is not None
        measured_gates, measured_tdds, measured_bindings = derive_offline_artifacts(
            task=task,
            policy=policy,
            task_sha256=task_sha256,
            raw_runs=raw_offline_runs,
            base_snapshot=base_snapshot,
            candidate_snapshot=candidate_snapshot,
            red_snapshots=red_snapshots,
            offline_runner_image=offline_runner_image,
            context=context,
            candidate_uid=candidate_uid,
        )
        if sorted(gates, key=lambda item: item.acceptance_test_id) != sorted(
            measured_gates,
            key=lambda item: item.acceptance_test_id,
        ):
            raise AttestedJudgeError("gate artifacts do not match raw offline executions")
        if sorted(tdd_evidence, key=lambda item: item.acceptance_test_id) != sorted(
            measured_tdds,
            key=lambda item: item.acceptance_test_id,
        ):
            raise AttestedJudgeError("TDD artifacts do not match raw offline executions")
        offline_roles = {
            role
            for role in _expected_roles(task)
            if role.startswith(("gate:", "tdd-red:", "tdd-green:"))
        }
        if any(binding.role in offline_roles for binding in effective_bindings):
            raise AttestedJudgeError(
                "offline run bindings must be derived internally from raw evidence"
            )
        effective_bindings.extend(measured_bindings)
        effective_gates = measured_gates
        effective_tdds = measured_tdds

    acceptance_ids_for_packet = {acceptance.id for acceptance in task.acceptance_tests}
    gate_ids_for_packet = [gate.acceptance_test_id for gate in effective_gates]
    if len(gate_ids_for_packet) != len(set(gate_ids_for_packet)):
        raise AttestedJudgeError("acceptance gates must appear exactly once")
    if set(gate_ids_for_packet) != acceptance_ids_for_packet:
        raise AttestedJudgeError("acceptance gates do not match the task")
    test_acceptance_ids_for_packet = {
        acceptance.id for acceptance in task.acceptance_tests if acceptance.kind == "test"
    }
    tdd_ids_for_packet = [item.acceptance_test_id for item in effective_tdds]
    if len(tdd_ids_for_packet) != len(set(tdd_ids_for_packet)):
        raise AttestedJudgeError("TDD evidence must appear exactly once")
    if set(tdd_ids_for_packet) != test_acceptance_ids_for_packet:
        missing = sorted(test_acceptance_ids_for_packet - set(tdd_ids_for_packet))
        unexpected = sorted(set(tdd_ids_for_packet) - test_acceptance_ids_for_packet)
        details = []
        if missing:
            details.append("missing TDD evidence: " + ", ".join(missing))
        if unexpected:
            details.append("unexpected TDD evidence: " + ", ".join(unexpected))
        raise AttestedJudgeError("; ".join(details))
    _validate_tdd_snapshot_bindings(task, effective_tdds, context)
    _validate_review_packet(
        review_packet,
        task=task,
        policy=policy,
        gates=effective_gates,
        tdd_evidence=effective_tdds,
        context=context,
        task_sha256=task_sha256,
        base_snapshot=base_snapshot,
        candidate_snapshot=candidate_snapshot,
        candidate_uid=candidate_uid,
    )
    if strict_offline and not strict_broker and not _diagnostic_allow_unmeasured:
        raise AttestedJudgeError("attested pass requires provisioned broker executions")
    if frozen_broker:
        assert prepared_broker_batch_raw is not None
        assert outer_broker_evidence_raw is not None
        assert broker_allowlist_policy is not None
        assert broker_pricing_policy is not None
        if candidate_uid is None:
            raise AttestedJudgeError(
                "frozen broker validation requires the protected candidate uid"
            )
        if any(binding.role in {"reviewer", "adversary"} for binding in effective_bindings):
            raise AttestedJudgeError(
                "broker review bindings must be derived internally from raw evidence"
            )
        measured_broker_bindings, frozen_provisioned = derive_frozen_broker_run_bindings(
            task=task,
            policy=policy,
            task_sha256=task_sha256,
            reviews=reviews,
            review_packet=review_packet,
            broker_evidence=broker_evidence,
            broker_requests=broker_requests,
            broker_artifacts=broker_artifacts,
            prepared_broker_batch_raw=prepared_broker_batch_raw,
            outer_broker_evidence_raw=outer_broker_evidence_raw,
            broker_allowlist_policy=broker_allowlist_policy,
            broker_pricing_policy=broker_pricing_policy,
            context=context,
            candidate_uid=candidate_uid,
        )
        effective_bindings.extend(measured_broker_bindings)
        measured_broker_executions_by_role = {
            evidence.execution.role: evidence.execution for evidence in frozen_provisioned
        }
    elif legacy_broker:
        assert broker_invocations is not None
        assert provisioned_broker_executions is not None
        assert broker_boundary_evidence is not None
        assert broker_ledger_path is not None
        if candidate_uid is None:
            raise AttestedJudgeError(
                "provisioned broker validation requires the protected candidate uid"
            )
        if any(binding.role in {"reviewer", "adversary"} for binding in effective_bindings):
            raise AttestedJudgeError(
                "broker review bindings must be derived internally from raw evidence"
            )
        measured_broker_bindings = derive_broker_run_bindings(
            task=task,
            policy=policy,
            task_sha256=task_sha256,
            reviews=reviews,
            review_packet=review_packet,
            broker_evidence=broker_evidence,
            broker_requests=broker_requests,
            broker_artifacts=broker_artifacts,
            broker_invocations=broker_invocations,
            provisioned_broker_executions=provisioned_broker_executions,
            broker_boundary_evidence=broker_boundary_evidence,
            broker_ledger_path=broker_ledger_path,
            context=context,
            candidate_uid=candidate_uid,
            broker_runtime_which=broker_runtime_which,
            broker_runtime_probe=broker_runtime_probe,
            broker_runtime_command_runner=broker_runtime_command_runner,
        )
        effective_bindings.extend(measured_broker_bindings)
        measured_broker_executions_by_role = {
            evidence.execution.role: evidence.execution
            for evidence in provisioned_broker_executions
        }

    expected_roles = _expected_roles(task)
    bindings = _exactly_once_by_key(
        effective_bindings,
        lambda item: item.role,
        label="run bindings",
    )
    if set(bindings) != expected_roles:
        missing = sorted(expected_roles - set(bindings))
        unexpected = sorted(set(bindings) - expected_roles)
        details = []
        if missing:
            details.append("missing " + ", ".join(missing))
        if unexpected:
            details.append("unexpected " + ", ".join(unexpected))
        raise AttestedJudgeError("run binding roles do not match the task: " + "; ".join(details))
    sessions = [binding.session_id for binding in bindings.values()]
    if len(sessions) != len(set(sessions)):
        raise AttestedJudgeError("every attested run requires a distinct session id")

    acceptance_ids = {acceptance.id for acceptance in task.acceptance_tests}
    gate_by_id = _exactly_once_by_key(
        effective_gates,
        lambda item: item.acceptance_test_id,
        label="acceptance gates",
    )
    if set(gate_by_id) != acceptance_ids:
        missing = sorted(acceptance_ids - set(gate_by_id))
        unexpected = sorted(set(gate_by_id) - acceptance_ids)
        details = []
        if missing:
            details.append("missing " + ", ".join(missing))
        if unexpected:
            details.append("unexpected " + ", ".join(unexpected))
        raise AttestedJudgeError("acceptance gates do not match the task: " + "; ".join(details))

    test_acceptance_ids = {
        acceptance.id for acceptance in task.acceptance_tests if acceptance.kind == "test"
    }
    tdd_by_id = _exactly_once_by_key(
        effective_tdds,
        lambda item: item.acceptance_test_id,
        label="TDD evidence",
    )
    if set(tdd_by_id) != test_acceptance_ids:
        missing = sorted(test_acceptance_ids - set(tdd_by_id))
        unexpected = sorted(set(tdd_by_id) - test_acceptance_ids)
        details = []
        if missing:
            details.append("missing TDD evidence: " + ", ".join(missing))
        if unexpected:
            details.append("unexpected TDD evidence: " + ", ".join(unexpected))
        raise AttestedJudgeError("; ".join(details))
    if not tdd_by_id:
        raise AttestedJudgeError("attested TDD pass requires at least one test acceptance")
    review_by_role = _exactly_once_by_key(reviews, lambda item: item.role, label="review roles")
    if set(review_by_role) != {"reviewer", "adversary"}:
        raise AttestedJudgeError("reviewer and adversary reports are both required")
    if any(not isinstance(item, BrokerInferenceEvidence) for item in broker_evidence):
        raise AttestedJudgeError("broker evidence contains an unsupported value")
    broker_by_role = _exactly_once_by_key(
        broker_evidence,
        lambda item: item.role,
        label="broker evidence roles",
    )
    if set(broker_by_role) != {"reviewer", "adversary"}:
        raise AttestedJudgeError("reviewer and adversary broker evidence are both required")
    if any(not isinstance(item, ToolFreeResponsesRequest) for item in broker_requests):
        raise AttestedJudgeError("broker requests contain an unsupported value")
    broker_requests_by_role = _exactly_once_by_key(
        broker_requests,
        lambda item: item.role,
        label="broker request roles",
    )
    if set(broker_requests_by_role) != {"reviewer", "adversary"}:
        raise AttestedJudgeError("reviewer and adversary broker requests are both required")
    broker_artifacts_by_role = _exactly_once_by_key(
        broker_artifacts,
        lambda item: item.role,
        label="raw broker artifact roles",
    )
    if set(broker_artifacts_by_role) != {"reviewer", "adversary"}:
        raise AttestedJudgeError("reviewer and adversary raw broker artifacts are both required")
    for field, label in (
        ("request_sha256", "request"),
        ("response_sha256", "canonical response"),
    ):
        if getattr(broker_by_role["reviewer"], field) == getattr(
            broker_by_role["adversary"], field
        ):
            raise AttestedJudgeError(
                f"reviewer and adversary broker {label} digests must be distinct"
            )

    expectations: dict[str, AttestationExpectation] = {}

    task_binding = bindings["task"]
    _validate_request(
        task_binding,
        task_sha256=task_sha256,
        source_sha=task.base_sha,
        source_snapshot_sha256=context.base_snapshot_sha256,
        candidate_sha256=None,
        snapshot_sha256=context.base_snapshot_sha256,
        input_sha256=task_sha256,
    )
    expectations["task"] = _expectation(
        task=task,
        policy=policy,
        task_sha256=task_sha256,
        context=context,
        binding=task_binding,
        artifact_type="task",
        artifact_sha256=canonical_sha256(task),
        snapshot_sha256=context.base_snapshot_sha256,
    )

    policy_binding = bindings["policy"]
    _validate_request(
        policy_binding,
        task_sha256=task_sha256,
        source_sha=policy.head_sha,
        source_snapshot_sha256=context.candidate_snapshot_sha256,
        candidate_sha256=policy.patch_sha256,
        snapshot_sha256=context.candidate_snapshot_sha256,
        input_sha256=context.candidate_snapshot_sha256,
    )
    expectations["policy"] = _expectation(
        task=task,
        policy=policy,
        task_sha256=task_sha256,
        context=context,
        binding=policy_binding,
        artifact_type="policy",
        artifact_sha256=canonical_sha256(policy),
        snapshot_sha256=context.candidate_snapshot_sha256,
    )

    for acceptance in task.acceptance_tests:
        gate = gate_by_id[acceptance.id]
        role = f"gate:{acceptance.id}"
        binding = bindings[role]
        _validate_request(
            binding,
            task_sha256=task_sha256,
            source_sha=policy.head_sha,
            source_snapshot_sha256=context.candidate_snapshot_sha256,
            candidate_sha256=policy.patch_sha256,
            snapshot_sha256=context.candidate_snapshot_sha256,
            acceptance_test_id=acceptance.id,
            command=acceptance.command,
            input_sha256=context.candidate_snapshot_sha256,
        )
        if binding.log_sha256 != gate.evidence_sha256:
            raise AttestedJudgeError(f"{role} log SHA-256 does not match gate evidence")
        expectations[role] = _expectation(
            task=task,
            policy=policy,
            task_sha256=task_sha256,
            context=context,
            binding=binding,
            artifact_type="gate",
            artifact_sha256=canonical_sha256(gate),
            snapshot_sha256=context.candidate_snapshot_sha256,
        )

    for acceptance_id, tdd in sorted(tdd_by_id.items()):
        for phase in ("red", "green"):
            role = f"tdd-{phase}:{acceptance_id}"
            binding = bindings[role]
            red = phase == "red"
            snapshot_sha256 = tdd.red_snapshot_sha256 if red else tdd.green_snapshot_sha256
            if snapshot_sha256 is None:
                raise AttestedJudgeError(f"{role} measured snapshot SHA-256 is missing")
            _validate_request(
                binding,
                task_sha256=task_sha256,
                source_sha=(task.base_sha if red else policy.head_sha),
                source_snapshot_sha256=(
                    context.base_snapshot_sha256 if red else context.candidate_snapshot_sha256
                ),
                candidate_sha256=policy.patch_sha256,
                snapshot_sha256=snapshot_sha256,
                acceptance_test_id=acceptance_id,
                command=tdd.command,
                test_patch_sha256=tdd.test_patch_sha256,
                test_manifest_sha256=tdd.test_manifest_sha256,
                input_sha256=snapshot_sha256,
            )
            phase_log_sha256 = tdd.red.log_sha256 if red else tdd.green.log_sha256
            if binding.log_sha256 != phase_log_sha256:
                raise AttestedJudgeError(f"{role} log SHA-256 does not match TDD evidence")
            artifact_type: ArtifactType = "tdd-red" if red else "tdd-green"
            expectations[role] = _expectation(
                task=task,
                policy=policy,
                task_sha256=task_sha256,
                context=context,
                binding=binding,
                artifact_type=artifact_type,
                artifact_sha256=tdd_phase_artifact_sha256(tdd, phase),
                snapshot_sha256=snapshot_sha256,
            )

    parsed_broker_envelopes: dict[str, ParsedBrokerReview] = {}
    for role in ("reviewer", "adversary"):
        review = review_by_role[role]
        binding = bindings[role]
        _validate_request(
            binding,
            task_sha256=task_sha256,
            source_sha=policy.head_sha,
            source_snapshot_sha256=context.candidate_snapshot_sha256,
            candidate_sha256=policy.patch_sha256,
            snapshot_sha256=context.candidate_snapshot_sha256,
            prompt_sha256=review.prompt_sha256,
            input_sha256=context.review_packet_sha256,
        )
        parsed_broker_envelopes[role] = _validate_broker_evidence(
            role=role,
            evidence=broker_by_role[role],
            artifacts=broker_artifacts_by_role[role],
            approved_request=broker_requests_by_role[role],
            packet=review_packet,
            binding=binding,
            context=context,
            review=review,
            execution=measured_broker_executions_by_role.get(role),
        )
        if binding.session_id != review.session_id:
            raise AttestedJudgeError(f"{role} session does not match the review artifact")
        expectations[role] = _expectation(
            task=task,
            policy=policy,
            task_sha256=task_sha256,
            context=context,
            binding=binding,
            artifact_type="review",
            artifact_sha256=canonical_sha256(review),
            snapshot_sha256=context.candidate_snapshot_sha256,
        )

    for field, label in (("request_id", "request ids"), ("response_id", "response ids")):
        if getattr(parsed_broker_envelopes["reviewer"], field) == getattr(
            parsed_broker_envelopes["adversary"], field
        ):
            raise AttestedJudgeError(f"reviewer and adversary broker {label} must be distinct")

    if (not strict_offline or not strict_broker) and not _diagnostic_allow_unmeasured:
        raise AttestedJudgeError(
            "attested pass requires raw offline runs, snapshot roots, and broker executions"
        )

    return expectations


def _ordinary_verdicts(
    task: TaskSpec,
    policy: PolicyReport,
    reviews: Sequence[ReviewReport],
    gates: Sequence[GateResult],
    tdds: Sequence[TddEvidence],
    *,
    task_sha256: str,
) -> list[Verdict]:
    return [
        judge(
            task,
            policy,
            list(reviews),
            list(gates),
            tdd,
            task_sha256=task_sha256,
        )
        for tdd in tdds
    ]


def build_frozen_bundle_expectations(bundle: object) -> dict[str, AttestationExpectation]:
    """Build expectations from one coordinator-reconstructed immutable bundle.

    This deliberately does not consume the bundle's typed provisioned evidence,
    invocations, boundary object, or broker digests as authority.  The broker
    portion is finalized again from its canonical prepared/outer byte pair and
    the pinned policy byte strings.
    """

    try:
        return build_attestation_expectations(
            bundle.task,
            bundle.policy,
            bundle.reviews,
            bundle.gates,
            bundle.tdd_evidence,
            bundle.task_policy_bindings,
            bundle.review_packet,
            bundle.broker_inference,
            bundle.broker_requests,
            bundle.broker_artifacts,
            context=bundle.context,
            task_sha256=bundle.task_sha256,
            raw_offline_runs=bundle.raw_offline_runs,
            base_snapshot=bundle.base_snapshot,
            candidate_snapshot=bundle.candidate_snapshot,
            red_snapshots=bundle.red_snapshots,
            offline_runner_image=bundle.offline_runner_image,
            prepared_broker_batch_raw=bundle.broker_prepared_raw,
            outer_broker_evidence_raw=bundle.broker_outer_raw,
            broker_allowlist_policy=bundle.broker_allowlist_policy,
            broker_pricing_policy=bundle.broker_pricing_policy,
            candidate_uid=bundle.broker_batch.candidate_uid,
        )
    except AttributeError as error:
        raise AttestedJudgeError("frozen attestation bundle is incomplete") from error


def judge_frozen_attestation_bundle(
    bundle: object,
    attestations: Sequence[SignedAttestation],
    *,
    trusted_public_keys: Mapping[str, Ed25519PublicKey],
    nonce_ledger: NonceLedger,
    now: int | None = None,
    max_age_seconds: int = 300,
    max_future_skew_seconds: int = 30,
) -> Verdict:
    """Judge one frozen bundle without a live broker ledger or runtime probe."""
    try:
        return judge_attested(
            bundle.task,
            bundle.policy,
            bundle.reviews,
            bundle.gates,
            bundle.tdd_evidence,
            attestations,
            bundle.task_policy_bindings,
            bundle.review_packet,
            bundle.broker_inference,
            bundle.broker_requests,
            bundle.broker_artifacts,
            context=bundle.context,
            task_sha256=bundle.task_sha256,
            trusted_public_keys=trusted_public_keys,
            nonce_ledger=nonce_ledger,
            now=now,
            max_age_seconds=max_age_seconds,
            max_future_skew_seconds=max_future_skew_seconds,
            raw_offline_runs=bundle.raw_offline_runs,
            base_snapshot=bundle.base_snapshot,
            candidate_snapshot=bundle.candidate_snapshot,
            red_snapshots=bundle.red_snapshots,
            offline_runner_image=bundle.offline_runner_image,
            prepared_broker_batch_raw=bundle.broker_prepared_raw,
            outer_broker_evidence_raw=bundle.broker_outer_raw,
            broker_allowlist_policy=bundle.broker_allowlist_policy,
            broker_pricing_policy=bundle.broker_pricing_policy,
            candidate_uid=bundle.broker_batch.candidate_uid,
        )
    except AttributeError as error:
        raise AttestedJudgeError("frozen attestation bundle is incomplete") from error


def judge_attested(
    task: TaskSpec,
    policy: PolicyReport,
    reviews: Sequence[ReviewReport],
    gates: Sequence[GateResult],
    tdd_evidence: Sequence[TddEvidence],
    attestations: Sequence[SignedAttestation],
    run_bindings: Sequence[TrustedRunBinding],
    review_packet: ReviewPacket,
    broker_evidence: Sequence[BrokerInferenceEvidence],
    broker_requests: Sequence[ToolFreeResponsesRequest],
    broker_artifacts: Sequence[TrustedBrokerArtifacts],
    *,
    context: TrustedAttestationContext,
    task_sha256: str,
    trusted_public_keys: Mapping[str, Ed25519PublicKey],
    nonce_ledger: NonceLedger,
    now: int | None = None,
    max_age_seconds: int = 300,
    max_future_skew_seconds: int = 30,
    raw_offline_runs: Sequence[OfflineRunEvidence] | None = None,
    base_snapshot: SnapshotEvidence | None = None,
    candidate_snapshot: SnapshotEvidence | None = None,
    red_snapshots: Sequence[RedTddSnapshotEvidence] | None = None,
    offline_runner_image: str | None = None,
    broker_invocations: Sequence[IsolatedBrokerInvocation] | None = None,
    provisioned_broker_executions: (Sequence[ProvisionedBrokerExecutionEvidence] | None) = None,
    raw_broker_executions: Sequence[BrokerExecutionEvidence] | None = None,
    broker_boundary_evidence: BrokerBoundaryEvidence | None = None,
    broker_ledger_path: Path | None = None,
    broker_runtime_which: Callable[[str], str | None] | None = None,
    broker_runtime_probe: Callable[..., object] | None = None,
    broker_runtime_command_runner: Callable[..., object] | None = None,
    prepared_broker_batch_raw: bytes | None = None,
    outer_broker_evidence_raw: bytes | None = None,
    broker_allowlist_policy: bytes | None = None,
    broker_pricing_policy: bytes | None = None,
    candidate_uid: int | None = None,
) -> Verdict:
    """Upgrade only an otherwise-clean deterministic verdict with complete attestation."""

    gates_list = list(gates)
    tdds = list(tdd_evidence)
    ordinary = _ordinary_verdicts(
        task,
        policy,
        reviews,
        gates_list,
        tdds,
        task_sha256=task_sha256,
    )
    ordinary_reasons = list(
        dict.fromkeys(reason for verdict in ordinary for reason in verdict.reasons)
    )
    ordinary_blockers = list(
        dict.fromkeys(blocker for verdict in ordinary for blocker in verdict.blocking_findings)
    )

    try:
        expectations = build_attestation_expectations(
            task,
            policy,
            reviews,
            gates_list,
            tdds,
            run_bindings,
            review_packet,
            broker_evidence,
            broker_requests,
            broker_artifacts,
            context=context,
            task_sha256=task_sha256,
            raw_offline_runs=raw_offline_runs,
            base_snapshot=base_snapshot,
            candidate_snapshot=candidate_snapshot,
            red_snapshots=red_snapshots,
            offline_runner_image=offline_runner_image,
            broker_invocations=broker_invocations,
            provisioned_broker_executions=provisioned_broker_executions,
            raw_broker_executions=raw_broker_executions,
            broker_boundary_evidence=broker_boundary_evidence,
            broker_ledger_path=broker_ledger_path,
            broker_runtime_which=broker_runtime_which,
            broker_runtime_probe=broker_runtime_probe,
            broker_runtime_command_runner=broker_runtime_command_runner,
            prepared_broker_batch_raw=prepared_broker_batch_raw,
            outer_broker_evidence_raw=outer_broker_evidence_raw,
            broker_allowlist_policy=broker_allowlist_policy,
            broker_pricing_policy=broker_pricing_policy,
            candidate_uid=candidate_uid,
        )
        verify_attestation_set(
            attestations,
            trusted_public_keys=trusted_public_keys,
            expectations=expectations,
            nonce_ledger=nonce_ledger,
            now=now,
            max_age_seconds=max_age_seconds,
            max_future_skew_seconds=max_future_skew_seconds,
        )
    except (AttestationError, AttestedJudgeError, ValueError) as error:
        return _fail(
            task,
            policy,
            gates_list,
            task_sha256=task_sha256,
            reasons=[*ordinary_reasons, f"attestation: {error}"],
            blockers=ordinary_blockers,
        )

    if any(verdict.status == "fail" for verdict in ordinary):
        return _fail(
            task,
            policy,
            gates_list,
            task_sha256=task_sha256,
            reasons=ordinary_reasons,
            blockers=ordinary_blockers,
        )

    quality_reasons = [reason for reason in ordinary_reasons if reason != SELF_REPORTED_REASON]
    if quality_reasons:
        return Verdict(
            task_id=task.task_id,
            task_sha256=task_sha256,
            trusted_harness_sha256=task.trusted_harness_sha256,
            base_sha=task.base_sha,
            head_sha=policy.head_sha,
            patch_sha256=policy.patch_sha256,
            status="human_review",
            gates=gates_list,
            blocking_findings=[],
            reasons=quality_reasons,
            human_approval_required=True,
        )

    return Verdict(
        task_id=task.task_id,
        task_sha256=task_sha256,
        trusted_harness_sha256=task.trusted_harness_sha256,
        base_sha=task.base_sha,
        head_sha=policy.head_sha,
        patch_sha256=policy.patch_sha256,
        status="pass",
        gates=gates_list,
        blocking_findings=[],
        reasons=[],
        human_approval_required=True,
    )
