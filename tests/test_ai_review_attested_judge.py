from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from tools.ai_review.attestation import AttestationStatement
from tools.ai_review.attestation import InMemoryNonceLedger
from tools.ai_review.attestation import SignedAttestation
from tools.ai_review.attestation import canonical_sha256
from tools.ai_review.attestation import sign_attestation
from tools.ai_review.broker_entry import BrokerResult
from tools.ai_review.broker_entry import canonical_response_bytes
from tools.ai_review.broker_entry import canonical_result_bytes
from tools.ai_review.broker_executor import MAX_PACKET_RESERVED_TOKENS
from tools.ai_review.broker_executor import prepare_broker_ledger
from tools.ai_review.broker_egress_provisioner import BrokerEgressProvisioningError
from tools.ai_review.broker_egress_provisioner import ProvisionedBrokerExecutionEvidence
from tools.ai_review.broker_egress_provisioner import execute_provisioned_isolated_broker
from tools.ai_review.attested_judge import TrustedAttestationContext
from tools.ai_review.attested_judge import AttestedJudgeError
from tools.ai_review.attested_judge import TrustedBrokerArtifacts
from tools.ai_review.attested_judge import TrustedRunBinding
from tools.ai_review.attested_judge import TrustedRunRequest
from tools.ai_review.attested_judge import build_attestation_expectations
from tools.ai_review.attested_judge import broker_egress_boundary_set_sha256
from tools.ai_review.attested_judge import derive_offline_artifacts
from tools.ai_review.attested_judge import judge_attested
from tools.ai_review.attested_judge import run_request_sha256
from tools.ai_review.codex_adapter import BrokerInferenceEvidence
from tools.ai_review.codex_adapter import BrokerBoundaryEvidence
from tools.ai_review.codex_adapter import CodexAdapter
from tools.ai_review.codex_adapter import IsolatedBrokerInvocation
from tools.ai_review.codex_adapter import ToolFreeResponsesRequest
from tools.ai_review.codex_adapter import validated_tool_free_request_bytes
from tools.ai_review.broker_result import parse_broker_review
from tools.ai_review.egress_policy import canonical_broker_egress_policy_bytes
from tools.ai_review.judge import build_test_manifest_sha256
from tools.ai_review.judge import judge
from tools.ai_review.models import DiffFile
from tools.ai_review.models import Finding
from tools.ai_review.models import GateResult
from tools.ai_review.models import PolicyReport
from tools.ai_review.models import ReviewReport
from tools.ai_review.models import TaskSpec
from tools.ai_review.models import TddEvidence
from tools.ai_review.offline_runner import execute_offline
from tools.ai_review.offline_runner import failure_fingerprint_sha256
from tools.ai_review.pricing_policy import APPROVED_OPENAI_PRICING_POLICY
from tools.ai_review.pricing_policy import DEFAULT_PACKET_COST_LIMIT_MICROUSD
from tools.ai_review.review_packet import ReviewPacket
from tools.ai_review.review_packet import TrustedDiffBinding
from tools.ai_review.review_packet import build_review_packet
from tools.ai_review.review_packet import build_review_packet_from_snapshots
from tools.ai_review.snapshot import RedTddSnapshotEvidence
from tools.ai_review.snapshot import SnapshotEvidence
from tools.ai_review.snapshot import create_readonly_snapshot
from tools.ai_review.snapshot import create_red_tdd_snapshot
from tests.test_ai_review_broker_egress_provisioner import FakeRuntime


BASE_SHA = "1" * 40
HEAD_SHA = "2" * 40
TASK_SHA = "3" * 64
PATCH_SHA = "4" * 64
RUNTIME_SHA = "5" * 64
COORDINATOR_IMAGE_DIGEST = "sha256:" + "a" * 64
OFFLINE_IMAGE_DIGEST = "sha256:" + "b" * 64
BROKER_IMAGE_DIGEST = "sha256:" + "c" * 64
BROKER_GATEWAY_IMAGE_DIGEST = "sha256:" + "d" * 64
BASE_SNAPSHOT_SHA = "b" * 64
BASE_MANIFEST_SHA = hashlib.sha256(b"base-manifest").hexdigest()
BASE_TREE_SHA = "a" * 40
CANDIDATE_SNAPSHOT_SHA = "6" * 64
CANDIDATE_MANIFEST_SHA = hashlib.sha256(b"candidate-manifest").hexdigest()
CANDIDATE_TREE_SHA = "b" * 40
RED_SNAPSHOT_SHA = "7" * 64
GREEN_SNAPSHOT_SHA = CANDIDATE_SNAPSHOT_SHA
HARNESS_SHA = "8" * 64
TEST_PATCH_SHA = "9" * 64
RED_FINGERPRINT_SHA = "a" * 64
SRC_CONTENT_SHA = "e" * 64
TEST_CONTENT_SHA = "f" * 64
SECOND_TEST_CONTENT_SHA = "0" * 64
NOW = 1_800_000_000


def digest(label: str) -> str:
    return hashlib.sha256(label.encode()).hexdigest()


def canonical_test_json(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


BROKER_ALLOWLIST_POLICY = canonical_broker_egress_policy_bytes()
BROKER_ALLOWLIST_POLICY_SHA256 = hashlib.sha256(BROKER_ALLOWLIST_POLICY).hexdigest()


SYNTHETIC_EGRESS_BOUNDARY_SET_SHA256 = digest("synthetic-egress-boundary-set")


REVIEWER_PROMPT = "Review the exact immutable packet and report only evidence-backed findings."
ADVERSARY_PROMPT = "Try to falsify the exact immutable packet and report only proven findings."
ROLE_PROMPTS = {"reviewer": REVIEWER_PROMPT, "adversary": ADVERSARY_PROMPT}
REPO_ROOT = Path(__file__).resolve().parents[1]
REVIEW_SCHEMA = REPO_ROOT / "specs" / "schemas" / "review.schema.json"


def model_review_payload(role: str, review: ReviewReport | None = None) -> dict:
    payload = (
        {
            "schema_version": "1.0",
            "task_id": "TASK-ATTESTED",
            "task_sha256": TASK_SHA,
            "role": role,
            "reviewer_id": "model-self-report",
            "session_id": "model-self-report",
            "prompt_sha256": hashlib.sha256(ROLE_PROMPTS[role].encode()).hexdigest(),
            "decision": "accept",
            "base_sha": BASE_SHA,
            "head_sha": HEAD_SHA,
            "patch_sha256": PATCH_SHA,
            "summary": "blocking findingなし",
            "findings": [],
            "unverified": [],
            "external_calls": False,
        }
        if review is None
        else review.model_dump(mode="json")
    )
    payload["reviewer_id"] = "model-self-report"
    payload["session_id"] = "model-self-report"
    return payload


def broker_response(role: str, review: ReviewReport | None = None) -> dict:
    review_text = json.dumps(
        model_review_payload(role, review),
        ensure_ascii=False,
        separators=(",", ":"),
    )
    return {
        "id": f"resp_{role}",
        "object": "response",
        "status": "completed",
        "model": "gpt-5.6-sol",
        "service_tier": "default",
        "output": [
            {
                "type": "message",
                "role": "assistant",
                "status": "completed",
                "content": [{"type": "output_text", "text": review_text}],
            }
        ],
        "usage": {
            "input_tokens": 100,
            "output_tokens": 20,
            "input_tokens_details": {"cached_tokens": 10},
            "output_tokens_details": {"reasoning_tokens": 5},
            "total_tokens": 120,
        },
    }


def broker_response_sha256(role: str, review: ReviewReport | None = None) -> str:
    return hashlib.sha256(canonical_response_bytes(broker_response(role, review))).hexdigest()


def broker_envelope(
    role: str,
    request: ToolFreeResponsesRequest,
    review: ReviewReport | None = None,
) -> bytes:
    response = broker_response(role, review)
    return canonical_result_bytes(
        BrokerResult(
            schema_version="1.0",
            request_sha256=request.request_sha256,
            response_sha256=broker_response_sha256(role, review),
            request_id=f"req_{role}_unique",
            response=response,
        )
    )


def parsed_broker_review(
    role: str,
    packet: ReviewPacket,
    request: ToolFreeResponsesRequest,
    review: ReviewReport | None = None,
):
    return parse_broker_review(
        broker_envelope(role, request, review),
        expected_request_sha256=request.request_sha256,
        expected_packet_sha256=packet.packet_sha256,
        role=role,
        attempt=request.attempt,
    )


def make_task(*, second_test: bool = False, schema_version: str = "2.0") -> TaskSpec:
    acceptance_tests = [
        {
            "id": "AT-TEST",
            "kind": "test",
            "command": ["pytest", "tests/test_example.py"],
            "expected_exit_code": 0,
            "expected_red_exit_codes": [1],
            "expected_red_fingerprint_sha256": RED_FINGERPRINT_SHA,
            "test_paths": ["tests/test_example.py"],
        },
        {
            "id": "AT-QUALITY",
            "kind": "quality",
            "command": ["ruff", "check", "."],
            "expected_exit_code": 0,
        },
    ]
    if second_test:
        acceptance_tests.insert(
            1,
            {
                "id": "AT-SECOND",
                "kind": "test",
                "command": ["pytest", "tests/test_second.py"],
                "expected_exit_code": 0,
                "expected_red_exit_codes": [1],
                "expected_red_fingerprint_sha256": "b" * 64,
                "test_paths": ["tests/test_second.py"],
            },
        )
    return TaskSpec.model_validate(
        {
            "schema_version": schema_version,
            "task_id": "TASK-ATTESTED",
            "base_sha": BASE_SHA,
            "trusted_harness_sha256": HARNESS_SHA,
            "objective": "署名済み証拠だけを受理する",
            "requirements": [{"id": "REQ-1", "text": "証拠を候補へ結合する"}],
            "review_prompts": {
                "reviewer_sha256": hashlib.sha256(REVIEWER_PROMPT.encode()).hexdigest(),
                "adversary_sha256": hashlib.sha256(ADVERSARY_PROMPT.encode()).hexdigest(),
            },
            "candidate_commit": {
                "message": "TASK-ATTESTED",
                "author_name": "Harness Test",
                "author_email": "test@example.com",
                "timestamp": 946_684_800,
                "timezone": "+0000",
            },
            "acceptance_tests": acceptance_tests,
            "allowed_paths": ["src/**", "tests/**"],
            "denied_paths": [".env", ".git/**"],
            "limits": {"max_changed_files": 10, "max_added_lines": 100},
            "network_policy": "deny",
        }
    )


def make_policy(task: TaskSpec) -> PolicyReport:
    changed = [
        DiffFile(
            path="src/example.py",
            status="M",
            additions=1,
            deletions=1,
            content_sha256=SRC_CONTENT_SHA,
        ),
        DiffFile(
            path="tests/test_example.py",
            status="A",
            additions=3,
            deletions=0,
            content_sha256=TEST_CONTENT_SHA,
        ),
    ]
    if any(test.id == "AT-SECOND" for test in task.acceptance_tests):
        changed.append(
            DiffFile(
                path="tests/test_second.py",
                status="A",
                additions=3,
                deletions=0,
                content_sha256=SECOND_TEST_CONTENT_SHA,
            )
        )
    return PolicyReport(
        task_id=task.task_id,
        task_sha256=TASK_SHA,
        passed=True,
        trusted_harness_sha256=HARNESS_SHA,
        base_sha=BASE_SHA,
        head_sha=HEAD_SHA,
        patch_sha256=PATCH_SHA,
        changed_files=changed,
        total_added_lines=sum(item.additions or 0 for item in changed),
        violations=[],
    )


def make_reviews(
    task: TaskSpec,
    packet: ReviewPacket,
    requests: list[ToolFreeResponsesRequest],
) -> list[ReviewReport]:
    request_by_role = {request.role: request for request in requests}
    reviews = [
        parsed_broker_review(role, packet, request_by_role[role]).review
        for role in ("reviewer", "adversary")
    ]
    assert all(review.task_id == task.task_id for review in reviews)
    return reviews


def make_gates(task: TaskSpec) -> list[GateResult]:
    return [
        GateResult(
            task_id=task.task_id,
            task_sha256=TASK_SHA,
            head_sha=HEAD_SHA,
            patch_sha256=PATCH_SHA,
            acceptance_test_id=acceptance.id,
            command=acceptance.command,
            expected_exit_code=acceptance.expected_exit_code,
            passed=True,
            exit_code=acceptance.expected_exit_code,
            evidence_sha256=digest(f"gate-log:{acceptance.id}"),
        )
        for acceptance in task.acceptance_tests
    ]


def make_tdds(task: TaskSpec, policy: PolicyReport) -> list[TddEvidence]:
    evidence: list[TddEvidence] = []
    for index, acceptance in enumerate(
        item for item in task.acceptance_tests if item.kind == "test"
    ):
        test_path = "tests/test_example.py" if index == 0 else "tests/test_second.py"
        test_patch = TEST_PATCH_SHA if index == 0 else digest("second-test-patch")
        evidence.append(
            TddEvidence(
                schema_version="2.0",
                task_id=task.task_id,
                task_sha256=TASK_SHA,
                base_sha=BASE_SHA,
                head_sha=HEAD_SHA,
                patch_sha256=PATCH_SHA,
                acceptance_test_id=acceptance.id,
                command=acceptance.command,
                test_paths=[test_path],
                test_manifest_sha256=build_test_manifest_sha256(policy, [test_path]),
                test_patch_sha256=test_patch,
                red_snapshot_sha256=(RED_SNAPSHOT_SHA if index == 0 else digest("red-second")),
                green_snapshot_sha256=(
                    GREEN_SNAPSHOT_SHA if index == 0 else CANDIDATE_SNAPSHOT_SHA
                ),
                red={
                    "exit_code": 1,
                    "log_sha256": digest(f"red-log:{acceptance.id}"),
                    "failure_fingerprint_sha256": acceptance.expected_red_fingerprint_sha256,
                    "test_patch_sha256": test_patch,
                },
                green={
                    "exit_code": 0,
                    "log_sha256": digest(f"green-log:{acceptance.id}"),
                    "test_patch_sha256": test_patch,
                },
            )
        )
    return evidence


def make_trusted_diff(task: TaskSpec) -> str:
    sections = [
        """diff --git a/src/example.py b/src/example.py
--- a/src/example.py
+++ b/src/example.py
@@ -1 +1 @@
-VALUE = 1
+VALUE = 2
""",
        """diff --git a/tests/test_example.py b/tests/test_example.py
new file mode 100644
--- /dev/null
+++ b/tests/test_example.py
@@ -0,0 +1 @@
+def test_example(): assert True
""",
    ]
    if any(acceptance.id == "AT-SECOND" for acceptance in task.acceptance_tests):
        sections.append(
            """diff --git a/tests/test_second.py b/tests/test_second.py
new file mode 100644
--- /dev/null
+++ b/tests/test_second.py
@@ -0,0 +1 @@
+def test_second(): assert True
"""
        )
    return "".join(sections)


def make_review_packet(
    task: TaskSpec,
    policy: PolicyReport,
    gates: list[GateResult],
    tdds: list[TddEvidence],
) -> ReviewPacket:
    trusted_diff = make_trusted_diff(task)
    return build_review_packet(
        task=task,
        task_sha256=TASK_SHA,
        policy=policy,
        trusted_diff=trusted_diff,
        trusted_diff_binding=TrustedDiffBinding(
            task_sha256=TASK_SHA,
            base_sha=BASE_SHA,
            head_sha=HEAD_SHA,
            candidate_digest_sha256=PATCH_SHA,
            trusted_diff_sha256=hashlib.sha256(trusted_diff.encode()).hexdigest(),
            snapshot_manifest_sha256=digest("candidate-snapshot-manifest"),
            coordinator_attestation_sha256=digest("diff-coordinator-attestation"),
        ),
        context={},
        gates=gates,
        tdd_evidence=tdds,
    )


def make_broker_requests(
    packet: ReviewPacket,
    *,
    attempt_by_role: dict[str, int] | None = None,
) -> list[ToolFreeResponsesRequest]:
    adapter = CodexAdapter()
    attempts = attempt_by_role or {}
    with tempfile.TemporaryDirectory(prefix="ai-review-coordinator-") as directory:
        trusted_cwd = Path(directory)
        trusted_schema = trusted_cwd / REVIEW_SCHEMA.name
        shutil.copyfile(REVIEW_SCHEMA, trusted_schema)
        return [
            adapter.build_tool_free_responses_request(
                packet=packet,
                role=role,
                role_prompt=ROLE_PROMPTS[role],
                output_schema=trusted_schema,
                cwd=trusted_cwd,
                attempt=attempts.get(role, 1),
            )
            for role in ("reviewer", "adversary")
        ]


def request_for(
    *,
    role: str,
    task: TaskSpec,
    policy: PolicyReport,
    gate: GateResult | None = None,
    tdd: TddEvidence | None = None,
    review: ReviewReport | None = None,
    review_packet_sha256: str | None = None,
    review_attempt: int | None = None,
) -> TrustedRunRequest:
    if role == "task":
        kind, source, source_snapshot, candidate, snapshot = (
            "task",
            BASE_SHA,
            BASE_SNAPSHOT_SHA,
            None,
            BASE_SNAPSHOT_SHA,
        )
    elif role == "policy":
        kind, source, source_snapshot, candidate, snapshot = (
            "policy",
            HEAD_SHA,
            CANDIDATE_SNAPSHOT_SHA,
            PATCH_SHA,
            CANDIDATE_SNAPSHOT_SHA,
        )
    elif gate is not None:
        kind, source, source_snapshot, candidate, snapshot = (
            "gate",
            HEAD_SHA,
            CANDIDATE_SNAPSHOT_SHA,
            PATCH_SHA,
            CANDIDATE_SNAPSHOT_SHA,
        )
    elif role.startswith("tdd-red:") and tdd is not None:
        kind, source, source_snapshot, candidate, snapshot = (
            "tdd-red",
            BASE_SHA,
            BASE_SNAPSHOT_SHA,
            PATCH_SHA,
            tdd.red_snapshot_sha256,
        )
    elif role.startswith("tdd-green:") and tdd is not None:
        kind, source, source_snapshot, candidate, snapshot = (
            "tdd-green",
            HEAD_SHA,
            CANDIDATE_SNAPSHOT_SHA,
            PATCH_SHA,
            tdd.green_snapshot_sha256,
        )
    elif review is not None:
        kind, source, source_snapshot, candidate, snapshot = (
            "review",
            HEAD_SHA,
            CANDIDATE_SNAPSHOT_SHA,
            PATCH_SHA,
            CANDIDATE_SNAPSHOT_SHA,
        )
    else:  # pragma: no cover - fixture misuse
        raise AssertionError(role)
    acceptance_id = gate.acceptance_test_id if gate is not None else None
    command: tuple[str, ...] = tuple(gate.command) if gate is not None else ()
    test_patch = None
    prompt = None
    if tdd is not None:
        acceptance_id = tdd.acceptance_test_id
        command = tuple(tdd.command)
        test_patch = tdd.test_patch_sha256
    if review is not None:
        prompt = review.prompt_sha256
    return TrustedRunRequest(
        kind=kind,
        task_sha256=TASK_SHA,
        source_sha=source,
        source_snapshot_sha256=source_snapshot,
        candidate_sha256=candidate,
        snapshot_sha256=snapshot,
        acceptance_test_id=acceptance_id,
        command=command,
        test_patch_sha256=test_patch,
        test_manifest_sha256=(tdd.test_manifest_sha256 if tdd is not None else None),
        prompt_sha256=prompt,
        input_sha256=(
            TASK_SHA if role == "task" else review_packet_sha256 if review is not None else snapshot
        ),
        provider=("openai" if review is not None else None),
        model=("gpt-5.6-sol" if review is not None else None),
        effort=(("high" if role == "reviewer" else "xhigh") if review is not None else None),
        attempt=((review_attempt or 1) if review is not None else None),
        review_role=(role if review is not None else None),
    )


def make_bindings(
    task: TaskSpec,
    policy: PolicyReport,
    gates: list[GateResult],
    tdds: list[TddEvidence],
    reviews: list[ReviewReport],
    broker_requests: list[ToolFreeResponsesRequest],
) -> list[TrustedRunBinding]:
    bindings: list[TrustedRunBinding] = []
    broker_request_by_role = {request.role: request for request in broker_requests}

    def add(role, artifact_type, request, log_sha256, session_id=None, review=None):
        request_digest = (
            broker_request_by_role[role].request_sha256
            if artifact_type == "review"
            else run_request_sha256(request)
        )
        bindings.append(
            TrustedRunBinding(
                role=role,
                artifact_type=artifact_type,
                session_id=session_id or f"run-session-{role.replace(':', '-')}",
                runner_sha256=digest(f"runner:{role}"),
                argv=("trusted-runner", "--role", role),
                log_sha256=log_sha256,
                request=request,
                request_sha256=request_digest,
                response_sha256=(
                    broker_response_sha256(role, review)
                    if artifact_type == "review"
                    else digest(f"response:{role}")
                ),
            )
        )

    add(
        "task",
        "task",
        request_for(role="task", task=task, policy=policy),
        digest("task-log"),
    )
    add(
        "policy",
        "policy",
        request_for(role="policy", task=task, policy=policy),
        digest("policy-log"),
    )
    for gate in gates:
        role = f"gate:{gate.acceptance_test_id}"
        add(
            role,
            "gate",
            request_for(role=role, task=task, policy=policy, gate=gate),
            gate.evidence_sha256,
        )
    for tdd in tdds:
        red_role = f"tdd-red:{tdd.acceptance_test_id}"
        green_role = f"tdd-green:{tdd.acceptance_test_id}"
        add(
            red_role,
            "tdd-red",
            request_for(role=red_role, task=task, policy=policy, tdd=tdd),
            tdd.red.log_sha256,
        )
        add(
            green_role,
            "tdd-green",
            request_for(role=green_role, task=task, policy=policy, tdd=tdd),
            tdd.green.log_sha256,
        )
    for review in reviews:
        add(
            review.role,
            "review",
            request_for(
                role=review.role,
                task=task,
                policy=policy,
                review=review,
                review_packet_sha256=broker_request_by_role[review.role].packet_sha256,
                review_attempt=broker_request_by_role[review.role].attempt,
            ),
            hashlib.sha256(
                broker_envelope(
                    review.role,
                    broker_request_by_role[review.role],
                    review,
                )
            ).hexdigest(),
            review.session_id,
            review,
        )
    return bindings


def make_broker_evidence(
    bindings: list[TrustedRunBinding],
    packet: ReviewPacket,
    requests: list[ToolFreeResponsesRequest],
    reviews: list[ReviewReport] | None = None,
) -> list[BrokerInferenceEvidence]:
    evidence: list[BrokerInferenceEvidence] = []
    review_by_role = {review.role: review for review in reviews or []}
    request_by_role = {request.role: request for request in requests}
    for binding in bindings:
        if binding.role not in {"reviewer", "adversary"}:
            continue
        parsed = parsed_broker_review(
            binding.role,
            packet,
            request_by_role[binding.role],
            review_by_role.get(binding.role),
        )
        assert parsed.inference.request_sha256 == binding.request_sha256
        assert parsed.inference.response_sha256 == binding.response_sha256
        assert parsed.inference.usage_jsonl_sha256 == binding.log_sha256
        evidence.append(parsed.inference)
    return evidence


def make_broker_artifacts(
    bindings: list[TrustedRunBinding],
    packet: ReviewPacket,
    requests: list[ToolFreeResponsesRequest],
    reviews: list[ReviewReport] | None = None,
) -> list[TrustedBrokerArtifacts]:
    artifacts: list[TrustedBrokerArtifacts] = []
    review_by_role = {review.role: review for review in reviews or []}
    request_by_role = {request.role: request for request in requests}
    for binding in bindings:
        if binding.role not in {"reviewer", "adversary"}:
            continue
        artifacts.append(
            TrustedBrokerArtifacts(
                role=binding.role,
                canonical_request=validated_tool_free_request_bytes(
                    request_by_role[binding.role],
                    expected_packet=packet,
                ),
                canonical_envelope=broker_envelope(
                    binding.role,
                    request_by_role[binding.role],
                    review_by_role.get(binding.role),
                ),
            )
        )
    return artifacts


@dataclass(frozen=True)
class AttestedTestBundle:
    task: TaskSpec
    policy: PolicyReport
    reviews: list[ReviewReport]
    gates: list[GateResult]
    tdds: list[TddEvidence]
    bindings: list[TrustedRunBinding]
    context: TrustedAttestationContext
    broker_evidence: list[BrokerInferenceEvidence]
    broker_artifacts: list[TrustedBrokerArtifacts]
    review_packet: ReviewPacket
    broker_requests: list[ToolFreeResponsesRequest]

    def __iter__(self):
        return iter(
            (
                self.task,
                self.policy,
                self.reviews,
                self.gates,
                self.tdds,
                self.bindings,
                self.context,
                self.broker_evidence,
                self.broker_artifacts,
            )
        )


@dataclass(frozen=True)
class StrictAttestedBundle:
    bundle: AttestedTestBundle
    non_offline_bindings: list[TrustedRunBinding]
    raw_offline_runs: list
    base_snapshot: SnapshotEvidence
    candidate_snapshot: SnapshotEvidence
    red_snapshots: list[RedTddSnapshotEvidence]
    offline_runner_image: str
    broker_invocations: list[IsolatedBrokerInvocation]
    provisioned_broker_executions: list[ProvisionedBrokerExecutionEvidence]
    broker_boundary_evidence: BrokerBoundaryEvidence
    broker_ledger_path: Path
    broker_runtime_binary: Path
    broker_runtime_probe: object
    broker_runtime_command_runner: object
    candidate_uid: int

    @property
    def strict_kwargs(self) -> dict:
        return {
            "raw_offline_runs": self.raw_offline_runs,
            "base_snapshot": self.base_snapshot,
            "candidate_snapshot": self.candidate_snapshot,
            "red_snapshots": self.red_snapshots,
            "offline_runner_image": self.offline_runner_image,
            "broker_invocations": self.broker_invocations,
            "provisioned_broker_executions": self.provisioned_broker_executions,
            "broker_boundary_evidence": self.broker_boundary_evidence,
            "broker_ledger_path": self.broker_ledger_path,
            "broker_runtime_which": (
                lambda name: str(self.broker_runtime_binary) if name == "podman" else None
            ),
            "broker_runtime_probe": self.broker_runtime_probe,
            "broker_runtime_command_runner": self.broker_runtime_command_runner,
            "candidate_uid": self.candidate_uid,
        }


def _run_git(repository: Path, *arguments: str) -> str:
    environment = {
        **os.environ,
        "GIT_AUTHOR_DATE": "2000-01-01T00:00:00+00:00",
        "GIT_COMMITTER_DATE": "2000-01-01T00:00:00+00:00",
    }
    result = subprocess.run(
        ["git", *arguments],
        cwd=repository,
        check=True,
        capture_output=True,
        env=environment,
        text=True,
    )
    return result.stdout.strip()


def make_strict_bundle(
    tmp_path: Path,
    *,
    failed_reviewer_attempt: bool = False,
) -> StrictAttestedBundle:
    global BASE_MANIFEST_SHA
    global BASE_SHA
    global BASE_SNAPSHOT_SHA
    global BASE_TREE_SHA
    global CANDIDATE_MANIFEST_SHA
    global CANDIDATE_SNAPSHOT_SHA
    global CANDIDATE_TREE_SHA
    global GREEN_SNAPSHOT_SHA
    global HEAD_SHA
    global RED_FINGERPRINT_SHA
    global RED_SNAPSHOT_SHA
    global SRC_CONTENT_SHA
    global TEST_CONTENT_SHA
    global TEST_PATCH_SHA

    repository = tmp_path / "candidate-repository"
    repository.mkdir(mode=0o700)
    _run_git(repository, "init", "-q")
    _run_git(repository, "config", "user.name", "Harness Test")
    _run_git(repository, "config", "user.email", "test@example.com")
    (repository / "src").mkdir()
    (repository / "src" / "example.py").write_text("VALUE = 1\n", encoding="utf-8")
    _run_git(repository, "add", "src/example.py")
    _run_git(repository, "commit", "-q", "-m", "base")
    base_commit = _run_git(repository, "rev-parse", "HEAD")
    (repository / "src" / "example.py").write_text("VALUE = 2\n", encoding="utf-8")
    (repository / "tests").mkdir()
    test_content = b"def test_example():\n    assert True\n"
    (repository / "tests" / "test_example.py").write_bytes(test_content)
    _run_git(repository, "add", "src/example.py", "tests/test_example.py")
    _run_git(repository, "commit", "-q", "-m", "candidate")
    candidate_commit = _run_git(repository, "rev-parse", "HEAD")
    bare_repository = tmp_path / "candidate.git"
    subprocess.run(
        [
            "git",
            "clone",
            "-q",
            "--bare",
            "--no-hardlinks",
            str(repository),
            str(bare_repository),
        ],
        check=True,
        capture_output=True,
    )

    candidate_uid = 65_534 if os.geteuid() != 65_534 else 65_533
    snapshots_root = tmp_path / "snapshots"
    snapshots_root.mkdir(mode=0o700)
    base_snapshot = create_readonly_snapshot(
        source_repo=bare_repository,
        commit_sha=base_commit,
        destination_root=snapshots_root,
        candidate_uid=candidate_uid,
    )
    candidate_snapshot = create_readonly_snapshot(
        source_repo=bare_repository,
        commit_sha=candidate_commit,
        destination_root=snapshots_root,
        candidate_uid=candidate_uid,
    )
    red_root = tmp_path / "red-snapshots"
    red_root.mkdir(mode=0o700)
    red_snapshot = create_red_tdd_snapshot(
        base_snapshot=base_snapshot,
        candidate_snapshot=candidate_snapshot,
        test_paths=("tests/test_example.py",),
        destination_root=red_root,
        candidate_uid=candidate_uid,
    )

    BASE_SHA = base_commit
    HEAD_SHA = candidate_commit
    BASE_SNAPSHOT_SHA = base_snapshot.snapshot_sha256
    BASE_MANIFEST_SHA = base_snapshot.manifest_sha256
    BASE_TREE_SHA = base_snapshot.commit_tree_sha
    CANDIDATE_SNAPSHOT_SHA = candidate_snapshot.snapshot_sha256
    CANDIDATE_MANIFEST_SHA = candidate_snapshot.manifest_sha256
    CANDIDATE_TREE_SHA = candidate_snapshot.commit_tree_sha
    RED_SNAPSHOT_SHA = red_snapshot.snapshot.snapshot_sha256
    GREEN_SNAPSHOT_SHA = candidate_snapshot.snapshot_sha256
    TEST_PATCH_SHA = red_snapshot.test_patch_sha256
    SRC_CONTENT_SHA = hashlib.sha256(b"VALUE = 2\n").hexdigest()
    TEST_CONTENT_SHA = hashlib.sha256(test_content).hexdigest()
    red_stdout = b"expected RED failure\n"
    RED_FINGERPRINT_SHA = failure_fingerprint_sha256(
        exit_code=1,
        stdout=red_stdout,
        stderr=b"",
    )

    task = make_task()
    policy = make_policy(task)
    runtime_binary = tmp_path / "podman"
    runtime_binary.write_bytes(b"trusted runtime\n")
    runtime_binary.chmod(0o555)
    offline_runner_image = f"example.invalid/offline-runner@{OFFLINE_IMAGE_DIGEST}"

    def probe(argv, **_kwargs):
        return subprocess.CompletedProcess(
            argv,
            0,
            stdout=(
                '{"host":{"security":{"rootless":true,"seccompEnabled":true,'
                '"seccompProfilePath":"/usr/share/containers/seccomp.json"}}}'
            ),
            stderr="",
        )

    broker_ledger = tmp_path / "broker-ledger" / "broker-attempts.sqlite3"
    broker_ledger.parent.mkdir(mode=0o700)
    broker_ledger_identity_sha256 = prepare_broker_ledger(
        broker_ledger,
        candidate_uid=candidate_uid,
    )

    session_index = 0

    def measured_run(
        *,
        phase: str,
        acceptance_id: str,
        command: tuple[str, ...],
        execution_snapshot: SnapshotEvidence,
        exit_code: int,
        stdout: bytes,
        test_patch_sha256: str | None,
        test_manifest_sha256: str | None,
    ):
        nonlocal session_index
        session_index += 1
        session_id = f"ai-review-{session_index:024x}"

        def runner(argv, **_kwargs):
            cidfile = next(item for item in argv if item.startswith("--cidfile="))
            Path(cidfile.split("=", 1)[1]).write_text("d" * 64 + "\n", encoding="ascii")
            return SimpleNamespace(
                exit_code=exit_code,
                stdout=stdout,
                stderr=b"",
                stdout_sha256=hashlib.sha256(stdout).hexdigest(),
                stderr_sha256=hashlib.sha256(b"").hexdigest(),
                duration_ms=1,
            )

        return execute_offline(
            snapshot_root=execution_snapshot.root,
            image=offline_runner_image,
            approved_image_digest=OFFLINE_IMAGE_DIGEST,
            command=command,
            phase=phase,
            acceptance_test_id=acceptance_id,
            session_id=session_id,
            task_sha256=TASK_SHA,
            candidate_sha256=PATCH_SHA,
            source_snapshot_sha256=(
                base_snapshot.snapshot_sha256
                if phase == "red"
                else candidate_snapshot.snapshot_sha256
            ),
            test_patch_sha256=test_patch_sha256,
            test_manifest_sha256=test_manifest_sha256,
            candidate_snapshot_sha256=candidate_snapshot.snapshot_sha256,
            candidate_uid=candidate_uid,
            which=lambda name: str(runtime_binary) if name == "podman" else None,
            probe=probe,
            stream_runner=runner,
            cleanup=lambda _backend, _name, _environment: True,
        )

    raw_runs = []
    for acceptance in task.acceptance_tests:
        raw_runs.append(
            measured_run(
                phase="gate",
                acceptance_id=acceptance.id,
                command=tuple(acceptance.command),
                execution_snapshot=candidate_snapshot,
                exit_code=acceptance.expected_exit_code,
                stdout=f"gate {acceptance.id}\n".encode(),
                test_patch_sha256=None,
                test_manifest_sha256=None,
            )
        )
        if acceptance.kind != "test":
            continue
        raw_runs.extend(
            (
                measured_run(
                    phase="red",
                    acceptance_id=acceptance.id,
                    command=tuple(acceptance.command),
                    execution_snapshot=red_snapshot.snapshot,
                    exit_code=1,
                    stdout=red_stdout,
                    test_patch_sha256=red_snapshot.test_patch_sha256,
                    test_manifest_sha256=red_snapshot.test_manifest_sha256,
                ),
                measured_run(
                    phase="green",
                    acceptance_id=acceptance.id,
                    command=tuple(acceptance.command),
                    execution_snapshot=candidate_snapshot,
                    exit_code=acceptance.expected_exit_code,
                    stdout=b"GREEN passed\n",
                    test_patch_sha256=red_snapshot.test_patch_sha256,
                    test_manifest_sha256=red_snapshot.test_manifest_sha256,
                ),
            )
        )

    preliminary_context = TrustedAttestationContext(
        runtime_manifest_sha256=RUNTIME_SHA,
        coordinator_image_digest=COORDINATOR_IMAGE_DIGEST,
        offline_runner_image_digest=OFFLINE_IMAGE_DIGEST,
        broker_image_digest=BROKER_IMAGE_DIGEST,
        broker_gateway_image_digest=BROKER_GATEWAY_IMAGE_DIGEST,
        broker_egress_boundary_sha256=digest("pending-broker-egress-boundary-set"),
        broker_allowlist_policy_sha256=BROKER_ALLOWLIST_POLICY_SHA256,
        broker_ledger_identity_sha256=broker_ledger_identity_sha256,
        broker_packet_reservation_limit=MAX_PACKET_RESERVED_TOKENS,
        broker_pricing_policy_sha256=APPROVED_OPENAI_PRICING_POLICY.sha256,
        broker_packet_cost_limit_microusd=DEFAULT_PACKET_COST_LIMIT_MICROUSD,
        base_snapshot_sha256=base_snapshot.snapshot_sha256,
        base_snapshot_manifest_sha256=base_snapshot.manifest_sha256,
        base_commit_tree_sha=base_snapshot.commit_tree_sha,
        candidate_snapshot_sha256=candidate_snapshot.snapshot_sha256,
        candidate_snapshot_manifest_sha256=candidate_snapshot.manifest_sha256,
        candidate_commit_tree_sha=candidate_snapshot.commit_tree_sha,
        review_packet_sha256=digest("pending-packet"),
        review_output_schema_sha256=digest("pending-schema"),
    )
    gates, tdds, _offline_bindings = derive_offline_artifacts(
        task=task,
        policy=policy,
        task_sha256=TASK_SHA,
        raw_runs=raw_runs,
        base_snapshot=base_snapshot,
        candidate_snapshot=candidate_snapshot,
        red_snapshots=[red_snapshot],
        offline_runner_image=offline_runner_image,
        context=preliminary_context,
        candidate_uid=candidate_uid,
    )
    packet = build_review_packet_from_snapshots(
        task=task,
        task_sha256=TASK_SHA,
        policy=policy,
        base_snapshot_root=base_snapshot.root,
        candidate_snapshot_root=candidate_snapshot.root,
        context_paths=(),
        candidate_uid=candidate_uid,
        gates=gates,
        tdd_evidence=tdds,
    )
    broker_requests = make_broker_requests(
        packet,
        attempt_by_role={"reviewer": 2} if failed_reviewer_attempt else None,
    )
    reviews = make_reviews(task, packet, broker_requests)
    all_bindings = make_bindings(task, policy, gates, tdds, reviews, broker_requests)
    non_offline_bindings = [
        binding for binding in all_bindings if binding.role in {"task", "policy"}
    ]
    broker_evidence = make_broker_evidence(
        all_bindings,
        packet,
        broker_requests,
        reviews,
    )
    broker_artifacts = make_broker_artifacts(
        all_bindings,
        packet,
        broker_requests,
        reviews,
    )
    broker_boundary_evidence = BrokerBoundaryEvidence(
        packet_sha256=packet.packet_sha256,
        external_preflight_sha256=digest("strict-external-preflight"),
        snapshot_manifest_sha256=candidate_snapshot.manifest_sha256,
        isolation_attestation_sha256=digest("strict-broker-isolation"),
        candidate_filesystem_unmounted=True,
        read_only_snapshot_verified=True,
        network_isolation_verified=True,
        coordinator_attestation_verified=True,
    )
    broker_image = f"example.invalid/review-broker@{BROKER_IMAGE_DIGEST}"
    broker_adapter = CodexAdapter()
    broker_invocations = [
        broker_adapter.build_isolated_broker_invocation(
            request=request,
            packet=packet,
            boundary_evidence=broker_boundary_evidence,
            container_runtime="podman",
            image=broker_image,
            approved_image_digest=BROKER_IMAGE_DIGEST,
            allow_external_ai=True,
            allow_isolated_broker=True,
        )
        for request in broker_requests
    ]
    request_by_role = {request.role: request for request in broker_requests}
    review_by_role = {review.role: review for review in reviews}
    broker_runtime = FakeRuntime()
    provisioned_broker_executions: list[ProvisionedBrokerExecutionEvidence] = []

    def execute_broker(invocation, request, stream_runner):
        return execute_provisioned_isolated_broker(
            invocation=invocation,
            expected_packet_sha256=packet.packet_sha256,
            expected_request_sha256=request.request_sha256,
            expected_boundary_evidence_sha256=invocation.boundary_evidence_sha256,
            expected_role=invocation.role,
            expected_attempt=request.attempt,
            approved_image_digest=BROKER_IMAGE_DIGEST,
            expected_argv_sha256=invocation.argv_sha256,
            expected_stdin_sha256=invocation.stdin_sha256,
            gateway_image=(f"example.invalid/review-gateway@{BROKER_GATEWAY_IMAGE_DIGEST}"),
            expected_broker_gateway_image_digest=BROKER_GATEWAY_IMAGE_DIGEST,
            allowlist_policy=BROKER_ALLOWLIST_POLICY,
            expected_broker_allowlist_policy_sha256=BROKER_ALLOWLIST_POLICY_SHA256,
            credential="sk-test-credential-never-record",
            ledger_path=broker_ledger,
            expected_broker_ledger_identity_sha256=broker_ledger_identity_sha256,
            broker_packet_reservation_limit=MAX_PACKET_RESERVED_TOKENS,
            expected_broker_pricing_policy_sha256=(APPROVED_OPENAI_PRICING_POLICY.sha256),
            broker_packet_cost_limit_microusd=DEFAULT_PACKET_COST_LIMIT_MICROUSD,
            candidate_uid=candidate_uid,
            allow_external_ai=True,
            allow_isolated_broker=True,
            which=lambda name: str(runtime_binary) if name == "podman" else None,
            probe=probe,
            command_runner=broker_runtime,
            stream_runner=stream_runner,
            cleanup=lambda _backend, _name, _environment: True,
        )

    if failed_reviewer_attempt:
        failed_request = replace(request_by_role["reviewer"], attempt=1)
        failed_invocation = broker_adapter.build_isolated_broker_invocation(
            request=failed_request,
            packet=packet,
            boundary_evidence=broker_boundary_evidence,
            container_runtime="podman",
            image=broker_image,
            approved_image_digest=BROKER_IMAGE_DIGEST,
            allow_external_ai=True,
            allow_isolated_broker=True,
        )

        def failed_broker_runner(_argv, **_kwargs):
            return SimpleNamespace(
                exit_code=1,
                stdout=b"",
                stderr=b"transient upstream failure\n",
                stdout_sha256=hashlib.sha256(b"").hexdigest(),
                stderr_sha256=hashlib.sha256(b"transient upstream failure\n").hexdigest(),
                duration_ms=1,
            )

        with pytest.raises(BrokerEgressProvisioningError):
            execute_broker(failed_invocation, failed_request, failed_broker_runner)

    for invocation in broker_invocations:
        request = request_by_role[invocation.role]
        raw_envelope = broker_envelope(
            invocation.role,
            request,
            review_by_role[invocation.role],
        )

        def broker_runner(_argv, *, _envelope=raw_envelope, **_kwargs):
            return SimpleNamespace(
                exit_code=0,
                stdout=_envelope,
                stderr=b"broker diagnostic\n",
                stdout_sha256=hashlib.sha256(_envelope).hexdigest(),
                stderr_sha256=hashlib.sha256(b"broker diagnostic\n").hexdigest(),
                duration_ms=1,
            )

        provisioned_broker_executions.append(execute_broker(invocation, request, broker_runner))
    output_schema = broker_requests[0].payload["text"]["format"]["schema"]
    context = preliminary_context.model_copy(
        update={
            "review_packet_sha256": packet.packet_sha256,
            "review_output_schema_sha256": canonical_sha256(output_schema),
            "broker_egress_boundary_sha256": broker_egress_boundary_set_sha256(
                provisioned_broker_executions
            ),
        }
    )
    bundle = AttestedTestBundle(
        task=task,
        policy=policy,
        reviews=reviews,
        gates=gates,
        tdds=tdds,
        bindings=non_offline_bindings,
        context=context,
        broker_evidence=broker_evidence,
        broker_artifacts=broker_artifacts,
        review_packet=packet,
        broker_requests=broker_requests,
    )
    return StrictAttestedBundle(
        bundle=bundle,
        non_offline_bindings=non_offline_bindings,
        raw_offline_runs=raw_runs,
        base_snapshot=base_snapshot,
        candidate_snapshot=candidate_snapshot,
        red_snapshots=[red_snapshot],
        offline_runner_image=offline_runner_image,
        broker_invocations=broker_invocations,
        provisioned_broker_executions=provisioned_broker_executions,
        broker_boundary_evidence=broker_boundary_evidence,
        broker_ledger_path=broker_ledger,
        broker_runtime_binary=runtime_binary,
        broker_runtime_probe=probe,
        broker_runtime_command_runner=broker_runtime,
        candidate_uid=candidate_uid,
    )


def make_bundle(*, second_test: bool = False):
    task = make_task(second_test=second_test)
    policy = make_policy(task)
    gates = make_gates(task)
    tdds = make_tdds(task, policy)
    packet = make_review_packet(task, policy, gates, tdds)
    broker_requests = make_broker_requests(packet)
    reviews = make_reviews(task, packet, broker_requests)
    bindings = make_bindings(task, policy, gates, tdds, reviews, broker_requests)
    broker_evidence = make_broker_evidence(
        bindings,
        packet,
        broker_requests,
        reviews,
    )
    broker_artifacts = make_broker_artifacts(
        bindings,
        packet,
        broker_requests,
        reviews,
    )
    output_schema = broker_requests[0].payload["text"]["format"]["schema"]
    context = TrustedAttestationContext(
        runtime_manifest_sha256=RUNTIME_SHA,
        coordinator_image_digest=COORDINATOR_IMAGE_DIGEST,
        offline_runner_image_digest=OFFLINE_IMAGE_DIGEST,
        broker_image_digest=BROKER_IMAGE_DIGEST,
        broker_gateway_image_digest=BROKER_GATEWAY_IMAGE_DIGEST,
        broker_egress_boundary_sha256=SYNTHETIC_EGRESS_BOUNDARY_SET_SHA256,
        broker_allowlist_policy_sha256=digest("synthetic-broker-allowlist"),
        broker_ledger_identity_sha256=digest("synthetic-broker-ledger-identity"),
        broker_packet_reservation_limit=MAX_PACKET_RESERVED_TOKENS,
        broker_pricing_policy_sha256=APPROVED_OPENAI_PRICING_POLICY.sha256,
        broker_packet_cost_limit_microusd=DEFAULT_PACKET_COST_LIMIT_MICROUSD,
        base_snapshot_sha256=BASE_SNAPSHOT_SHA,
        base_snapshot_manifest_sha256=BASE_MANIFEST_SHA,
        base_commit_tree_sha=BASE_TREE_SHA,
        candidate_snapshot_sha256=CANDIDATE_SNAPSHOT_SHA,
        candidate_snapshot_manifest_sha256=CANDIDATE_MANIFEST_SHA,
        candidate_commit_tree_sha=CANDIDATE_TREE_SHA,
        review_packet_sha256=packet.packet_sha256,
        review_output_schema_sha256=canonical_sha256(output_schema),
    )
    return AttestedTestBundle(
        task=task,
        policy=policy,
        reviews=reviews,
        gates=gates,
        tdds=tdds,
        bindings=bindings,
        context=context,
        broker_evidence=broker_evidence,
        broker_artifacts=broker_artifacts,
        review_packet=packet,
        broker_requests=broker_requests,
    )


def sign_expected(
    private_key,
    task,
    policy,
    reviews,
    gates,
    tdds,
    bindings,
    context,
    review_packet=None,
    broker_requests=None,
    broker_evidence=None,
    broker_artifacts=None,
    *,
    issued_at=NOW,
) -> list[SignedAttestation]:
    if review_packet is None:
        review_packet = make_review_packet(task, policy, gates, tdds)
    if broker_requests is None:
        broker_requests = make_broker_requests(review_packet)
    if broker_evidence is None:
        broker_evidence = make_broker_evidence(
            bindings,
            review_packet,
            broker_requests,
            reviews,
        )
    if broker_artifacts is None:
        broker_artifacts = make_broker_artifacts(
            bindings,
            review_packet,
            broker_requests,
            reviews,
        )
    expectations = build_attestation_expectations(
        task,
        policy,
        reviews,
        gates,
        tdds,
        bindings,
        review_packet,
        broker_evidence,
        broker_requests,
        broker_artifacts,
        context=context,
        task_sha256=TASK_SHA,
        _diagnostic_allow_unmeasured=True,
    )
    return [
        sign_attestation(
            AttestationStatement(
                **expected.model_dump(),
                nonce=digest(f"nonce:{role}"),
                issued_at=issued_at,
            ),
            private_key,
        )
        for role, expected in expectations.items()
    ]


def call_attested(
    bundle,
    private_key,
    attestations,
    ledger=None,
    *,
    review_packet=None,
    broker_requests=None,
):
    task, policy, reviews, gates, tdds, bindings, context, broker_evidence, broker_artifacts = (
        bundle
    )
    if review_packet is None and isinstance(bundle, AttestedTestBundle):
        review_packet = bundle.review_packet
    if broker_requests is None and isinstance(bundle, AttestedTestBundle):
        broker_requests = bundle.broker_requests
    if review_packet is None:
        review_packet = make_review_packet(task, policy, gates, tdds)
    if broker_requests is None:
        broker_requests = make_broker_requests(review_packet)
    return judge_attested(
        task,
        policy,
        reviews,
        gates,
        tdds,
        attestations,
        bindings,
        review_packet,
        broker_evidence,
        broker_requests,
        broker_artifacts,
        context=context,
        task_sha256=TASK_SHA,
        trusted_public_keys={
            attestations[0].key_id if attestations else digest("unknown"): private_key.public_key()
        },
        nonce_ledger=ledger or InMemoryNonceLedger(),
        now=NOW,
    )


def sign_strict_bundle(
    strict: StrictAttestedBundle,
    private_key: Ed25519PrivateKey,
    *,
    issued_at: int = NOW,
) -> list[SignedAttestation]:
    bundle = strict.bundle
    expectations = build_attestation_expectations(
        bundle.task,
        bundle.policy,
        bundle.reviews,
        bundle.gates,
        bundle.tdds,
        strict.non_offline_bindings,
        bundle.review_packet,
        bundle.broker_evidence,
        bundle.broker_requests,
        bundle.broker_artifacts,
        context=bundle.context,
        task_sha256=TASK_SHA,
        **strict.strict_kwargs,
    )
    return [
        sign_attestation(
            AttestationStatement(
                **expected.model_dump(),
                nonce=digest(f"strict-nonce:{role}"),
                issued_at=issued_at,
            ),
            private_key,
        )
        for role, expected in expectations.items()
    ]


def call_strict_bundle(
    strict: StrictAttestedBundle,
    private_key: Ed25519PrivateKey,
    attestations: list[SignedAttestation],
    *,
    raw_offline_runs=None,
    provisioned_broker_executions=None,
    raw_broker_executions=...,
    run_bindings=None,
    include_broker_execution: bool = True,
    nonce_ledger=None,
):
    bundle = strict.bundle
    strict_kwargs = {
        **strict.strict_kwargs,
        "raw_offline_runs": (
            strict.raw_offline_runs if raw_offline_runs is None else raw_offline_runs
        ),
    }
    if provisioned_broker_executions is not None:
        strict_kwargs["provisioned_broker_executions"] = provisioned_broker_executions
    if raw_broker_executions is not ...:
        strict_kwargs["raw_broker_executions"] = raw_broker_executions
    if not include_broker_execution:
        for field in (
            "broker_invocations",
            "provisioned_broker_executions",
            "broker_boundary_evidence",
            "broker_ledger_path",
            "broker_runtime_which",
            "broker_runtime_probe",
            "broker_runtime_command_runner",
        ):
            strict_kwargs.pop(field)
    return judge_attested(
        bundle.task,
        bundle.policy,
        bundle.reviews,
        bundle.gates,
        bundle.tdds,
        attestations,
        strict.non_offline_bindings if run_bindings is None else run_bindings,
        bundle.review_packet,
        bundle.broker_evidence,
        bundle.broker_requests,
        bundle.broker_artifacts,
        context=bundle.context,
        task_sha256=TASK_SHA,
        trusted_public_keys={
            attestations[0].key_id if attestations else digest("unknown"): private_key.public_key()
        },
        nonce_ledger=nonce_ledger or InMemoryNonceLedger(),
        now=NOW,
        **strict_kwargs,
    )


def test_complete_raw_snapshot_and_offline_chain_is_required_for_attested_pass(tmp_path):
    strict = make_strict_bundle(tmp_path)
    bundle = strict.bundle
    private_key = Ed25519PrivateKey.generate()
    attestations = sign_strict_bundle(strict, private_key)

    verdict = call_strict_bundle(strict, private_key, attestations)
    assert verdict.status == "pass"
    assert verdict.human_approval_required is True

    missing_raw_broker = call_strict_bundle(
        strict,
        private_key,
        attestations,
        include_broker_execution=False,
    )
    assert missing_raw_broker.status == "fail"
    assert any("broker executions" in reason for reason in missing_raw_broker.reasons)

    caller_review_bindings = [
        binding
        for binding in make_bindings(
            bundle.task,
            bundle.policy,
            bundle.gates,
            bundle.tdds,
            bundle.reviews,
            bundle.broker_requests,
        )
        if binding.role in {"reviewer", "adversary"}
    ]
    injected_binding = call_strict_bundle(
        strict,
        private_key,
        attestations,
        run_bindings=[*strict.non_offline_bindings, *caller_review_bindings],
    )
    assert injected_binding.status == "fail"
    assert any("derived internally" in reason for reason in injected_binding.reasons)

    ledger = InMemoryNonceLedger()
    assert (
        call_strict_bundle(
            strict,
            private_key,
            attestations,
            nonce_ledger=ledger,
        ).status
        == "pass"
    )
    replay = call_strict_bundle(
        strict,
        private_key,
        attestations,
        nonce_ledger=ledger,
    )
    assert replay.status == "fail"
    assert any("replay" in reason for reason in replay.reasons)

    tampered_runs = list(strict.raw_offline_runs)
    tampered_runs[0] = replace(
        tampered_runs[0],
        stdout=tampered_runs[0].stdout + b"tampered",
    )
    tampered = call_strict_bundle(
        strict,
        private_key,
        attestations,
        raw_offline_runs=tampered_runs,
    )
    assert tampered.status == "fail"
    assert any("raw offline" in reason for reason in tampered.reasons)

    tampered_broker = list(strict.provisioned_broker_executions)
    tampered_broker[0] = replace(
        tampered_broker[0],
        execution=replace(
            tampered_broker[0].execution,
            stderr=tampered_broker[0].execution.stderr + b"tampered",
        ),
    )
    broker_verdict = call_strict_bundle(
        strict,
        private_key,
        attestations,
        provisioned_broker_executions=tampered_broker,
    )
    assert broker_verdict.status == "fail"
    assert any("broker" in reason for reason in broker_verdict.reasons)

    tampered_egress = list(strict.provisioned_broker_executions)
    tampered_egress[0] = replace(
        tampered_egress[0],
        egress_lifecycle=replace(
            tampered_egress[0].egress_lifecycle,
            cleanup_succeeded=False,
        ),
    )
    egress_verdict = call_strict_bundle(
        strict,
        private_key,
        attestations,
        provisioned_broker_executions=tampered_egress,
    )
    assert egress_verdict.status == "fail"
    assert any("broker" in reason for reason in egress_verdict.reasons)

    tampered_ledger = list(strict.provisioned_broker_executions)
    tampered_ledger[1] = replace(
        tampered_ledger[1],
        execution=replace(
            tampered_ledger[1].execution,
            cumulative_reserved_tokens=(
                tampered_ledger[1].execution.cumulative_reserved_tokens - 1
            ),
        ),
    )
    ledger_verdict = call_strict_bundle(
        strict,
        private_key,
        attestations,
        provisioned_broker_executions=tampered_ledger,
    )
    assert ledger_verdict.status == "fail"
    assert any("broker" in reason for reason in ledger_verdict.reasons)

    raw_execution_substitutions = {
        "runtime": {"runtime_sha256": "0" * 64},
        "image": {"approved_image_digest": "sha256:" + "0" * 64},
        "argv": {
            "argv": (
                "/substituted/runtime",
                *tampered_broker[0].execution.argv[1:],
            )
        },
        "cleanup": {"cleanup_succeeded": False},
        "boundary": {"boundary_evidence_sha256": "0" * 64},
        "response": {"response_sha256": "0" * 64},
    }
    for label, update in raw_execution_substitutions.items():
        substituted = list(strict.provisioned_broker_executions)
        substituted[0] = replace(
            substituted[0],
            execution=replace(substituted[0].execution, **update),
        )
        substituted_verdict = call_strict_bundle(
            strict,
            private_key,
            attestations,
            provisioned_broker_executions=substituted,
        )
        assert substituted_verdict.status == "fail", label
        assert any("broker" in reason for reason in substituted_verdict.reasons), label

    fake_diff = make_trusted_diff(bundle.task)
    fake_packet = build_review_packet(
        task=bundle.task,
        task_sha256=TASK_SHA,
        policy=bundle.policy,
        trusted_diff=fake_diff,
        trusted_diff_binding=TrustedDiffBinding(
            task_sha256=TASK_SHA,
            base_sha=bundle.task.base_sha,
            head_sha=bundle.policy.head_sha,
            candidate_digest_sha256=bundle.policy.patch_sha256,
            trusted_diff_sha256=hashlib.sha256(fake_diff.encode()).hexdigest(),
            snapshot_manifest_sha256=strict.candidate_snapshot.manifest_sha256,
            coordinator_attestation_sha256=digest("forged-snapshot-material"),
        ),
        context={},
        gates=bundle.gates,
        tdd_evidence=bundle.tdds,
    )
    forged_context = bundle.context.model_copy(
        update={"review_packet_sha256": fake_packet.packet_sha256}
    )
    with pytest.raises(AttestedJudgeError, match="re-measured snapshot bytes"):
        build_attestation_expectations(
            bundle.task,
            bundle.policy,
            bundle.reviews,
            bundle.gates,
            bundle.tdds,
            strict.non_offline_bindings,
            fake_packet,
            bundle.broker_evidence,
            bundle.broker_requests,
            bundle.broker_artifacts,
            context=forged_context,
            task_sha256=TASK_SHA,
            **strict.strict_kwargs,
        )

    stale = sign_strict_bundle(strict, private_key, issued_at=NOW - 301)
    stale_verdict = call_strict_bundle(strict, private_key, stale)
    assert stale_verdict.status == "fail"
    assert any("expired" in reason for reason in stale_verdict.reasons)


def test_low_level_broker_execution_evidence_cannot_authorize_attested_pass(tmp_path):
    strict = make_strict_bundle(tmp_path)
    private_key = Ed25519PrivateKey.generate()
    attestations = sign_strict_bundle(strict, private_key)

    verdict = call_strict_bundle(
        strict,
        private_key,
        attestations,
        provisioned_broker_executions=[],
        raw_broker_executions=[
            evidence.execution for evidence in strict.provisioned_broker_executions
        ],
    )

    assert verdict.status == "fail"
    assert any("low-level broker" in reason for reason in verdict.reasons)


def test_failed_broker_reservation_is_charged_before_one_success_per_role(tmp_path):
    strict = make_strict_bundle(tmp_path, failed_reviewer_attempt=True)
    executions = [evidence.execution for evidence in strict.provisioned_broker_executions]
    by_role = {execution.role: execution for execution in executions}
    final = max(executions, key=lambda execution: execution.cumulative_reserved_tokens)

    assert by_role["reviewer"].attempt == 2
    assert by_role["adversary"].attempt == 1
    assert final.ledger.cumulative_reserved_tokens > sum(
        execution.reserved_tokens for execution in executions
    )
    assert final.ledger.cumulative_reserved_cost_microusd > sum(
        execution.reserved_cost_microusd for execution in executions
    )

    private_key = Ed25519PrivateKey.generate()
    attestations = sign_strict_bundle(strict, private_key)
    verdict = call_strict_bundle(strict, private_key, attestations)

    assert verdict.status == "pass"


def test_clean_self_reported_verdict_becomes_pass_only_with_complete_attestation():
    bundle = make_bundle()
    (
        task,
        policy,
        reviews,
        gates,
        tdds,
        bindings,
        context,
        _broker_evidence,
        _broker_artifacts,
    ) = bundle
    ordinary = judge(task, policy, reviews, gates, tdds[0], task_sha256=TASK_SHA)
    assert ordinary.status == "human_review"

    private_key = Ed25519PrivateKey.generate()
    attestations = sign_expected(private_key, task, policy, reviews, gates, tdds, bindings, context)
    verdict = call_attested(bundle, private_key, attestations)

    assert verdict.status == "fail"
    assert any("raw offline runs" in reason for reason in verdict.reasons)
    assert verdict.human_approval_required is True


def test_unsigned_missing_and_stale_attestations_fail_closed():
    bundle = make_bundle()
    (
        task,
        policy,
        reviews,
        gates,
        tdds,
        bindings,
        context,
        _broker_evidence,
        _broker_artifacts,
    ) = bundle
    private_key = Ed25519PrivateKey.generate()
    complete = sign_expected(private_key, task, policy, reviews, gates, tdds, bindings, context)

    assert call_attested(bundle, private_key, [], InMemoryNonceLedger()).status == "fail"
    assert call_attested(bundle, private_key, complete[:-1], InMemoryNonceLedger()).status == "fail"
    stale = sign_expected(
        private_key,
        task,
        policy,
        reviews,
        gates,
        tdds,
        bindings,
        context,
        issued_at=NOW - 301,
    )
    stale_verdict = call_attested(bundle, private_key, stale, InMemoryNonceLedger())
    assert stale_verdict.status == "fail"
    assert any("raw offline runs" in reason for reason in stale_verdict.reasons)


def test_replay_and_artifact_substitution_fail_closed():
    bundle = make_bundle()
    task, policy, reviews, gates, tdds, bindings, context, broker_evidence, broker_artifacts = (
        bundle
    )
    private_key = Ed25519PrivateKey.generate()
    attestations = sign_expected(private_key, task, policy, reviews, gates, tdds, bindings, context)
    ledger = InMemoryNonceLedger()

    first = call_attested(bundle, private_key, attestations, ledger)
    assert first.status == "fail"
    assert any("raw offline runs" in reason for reason in first.reasons)
    replay = call_attested(bundle, private_key, attestations, ledger)
    assert replay.status == "fail"
    assert any("raw offline runs" in reason for reason in replay.reasons)

    substituted_policy = policy.model_copy(update={"total_added_lines": 99})
    substituted = (
        task,
        substituted_policy,
        reviews,
        gates,
        tdds,
        bindings,
        context,
        broker_evidence,
        broker_artifacts,
    )
    verdict = call_attested(substituted, private_key, attestations, InMemoryNonceLedger())
    assert verdict.status == "fail"
    assert any(
        "artifact_sha256" in reason or "review packet" in reason for reason in verdict.reasons
    )

    substituted_task = task.model_copy(
        update={
            "objective": "署名後に置換された目的",
            "allowed_paths": ["src/**", "tests/**", "substituted/**"],
        }
    )
    substituted = (
        substituted_task,
        policy,
        reviews,
        gates,
        tdds,
        bindings,
        context,
        broker_evidence,
        broker_artifacts,
    )
    verdict = call_attested(substituted, private_key, attestations, InMemoryNonceLedger())
    assert verdict.status == "fail"
    assert any(
        "artifact_sha256" in reason or "review packet" in reason for reason in verdict.reasons
    )


@pytest.mark.parametrize(
    "dimension",
    [
        "snapshot",
        "base_snapshot",
        "red_snapshot",
        "red_source_snapshot",
        "green_source_snapshot",
        "red_test_manifest",
        "green_test_manifest",
        "runtime",
        "runner",
        "argv",
        "log",
        "response",
    ],
)
def test_trusted_runtime_snapshot_runner_and_io_substitution_fail_closed(dimension):
    bundle = make_bundle()
    task, policy, reviews, gates, tdds, bindings, context, broker_evidence, broker_artifacts = (
        bundle
    )
    private_key = Ed25519PrivateKey.generate()
    attestations = sign_expected(private_key, task, policy, reviews, gates, tdds, bindings, context)
    changed_bindings = list(bindings)
    changed_context = context
    if dimension == "snapshot":
        changed_context = context.model_copy(
            update={"candidate_snapshot_sha256": digest("substituted-candidate-snapshot")}
        )
    elif dimension == "base_snapshot":
        changed_context = context.model_copy(
            update={"base_snapshot_sha256": digest("substituted-base-snapshot")}
        )
    elif dimension == "red_snapshot":
        target_index = next(
            index
            for index, binding in enumerate(changed_bindings)
            if binding.role.startswith("tdd-red:")
        )
        target = changed_bindings[target_index]
        changed_bindings[target_index] = target.model_copy(
            update={"request": target.request.model_copy(update={"snapshot_sha256": "0" * 64})}
        )
    elif dimension in {
        "red_source_snapshot",
        "green_source_snapshot",
        "red_test_manifest",
        "green_test_manifest",
    }:
        phase = "red" if dimension.startswith("red_") else "green"
        target_index = next(
            index
            for index, binding in enumerate(changed_bindings)
            if binding.role.startswith(f"tdd-{phase}:")
        )
        target = changed_bindings[target_index]
        request_field = (
            "test_manifest_sha256"
            if dimension.endswith("test_manifest")
            else "source_snapshot_sha256"
        )
        changed_bindings[target_index] = target.model_copy(
            update={
                "request": target.request.model_copy(
                    update={request_field: digest(f"substituted-{dimension}")}
                )
            }
        )
    elif dimension == "runtime":
        changed_context = context.model_copy(update={"runtime_manifest_sha256": "0" * 64})
    else:
        target = changed_bindings[1]
        field, value = {
            "runner": ("runner_sha256", "0" * 64),
            "argv": ("argv", ("different-runner",)),
            "log": ("log_sha256", "0" * 64),
            "response": ("response_sha256", "0" * 64),
        }[dimension]
        changed_bindings[1] = target.model_copy(update={field: value})
    changed = (
        task,
        policy,
        reviews,
        gates,
        tdds,
        changed_bindings,
        changed_context,
        broker_evidence,
        broker_artifacts,
    )

    assert call_attested(changed, private_key, attestations).status == "fail"


def test_red_overlay_snapshot_cannot_be_the_unpatched_base():
    bundle = make_bundle()
    task, policy, reviews, gates, tdds, bindings, context, broker_evidence, broker_artifacts = (
        bundle
    )
    private_key = Ed25519PrivateKey.generate()
    attestations = sign_expected(private_key, task, policy, reviews, gates, tdds, bindings, context)
    changed_tdd = tdds[0].model_copy(update={"red_snapshot_sha256": context.base_snapshot_sha256})
    changed = (
        task,
        policy,
        reviews,
        gates,
        [changed_tdd],
        bindings,
        context,
        broker_evidence,
        broker_artifacts,
    )

    verdict = call_attested(
        changed,
        private_key,
        attestations,
        review_packet=bundle.review_packet,
        broker_requests=bundle.broker_requests,
    )

    assert verdict.status == "fail"
    assert any("RED overlay" in reason for reason in verdict.reasons)


def test_green_snapshot_must_be_the_exact_candidate_snapshot():
    bundle = make_bundle()
    task, policy, reviews, gates, tdds, bindings, context, broker_evidence, broker_artifacts = (
        bundle
    )
    private_key = Ed25519PrivateKey.generate()
    attestations = sign_expected(private_key, task, policy, reviews, gates, tdds, bindings, context)
    changed_tdd = tdds[0].model_copy(
        update={"green_snapshot_sha256": digest("substituted-green-snapshot")}
    )
    changed = (
        task,
        policy,
        reviews,
        gates,
        [changed_tdd],
        bindings,
        context,
        broker_evidence,
        broker_artifacts,
    )

    verdict = call_attested(
        changed,
        private_key,
        attestations,
        review_packet=bundle.review_packet,
        broker_requests=bundle.broker_requests,
    )

    assert verdict.status == "fail"
    assert any("GREEN snapshot" in reason for reason in verdict.reasons)


def test_tdd_test_paths_must_exactly_match_taskspec_v2():
    bundle = make_bundle()
    task, policy, reviews, gates, tdds, bindings, context, broker_evidence, broker_artifacts = (
        bundle
    )
    private_key = Ed25519PrivateKey.generate()
    attestations = sign_expected(private_key, task, policy, reviews, gates, tdds, bindings, context)
    changed_tdd = tdds[0].model_copy(update={"test_paths": ["tests/substituted.py"]})
    changed = (
        task,
        policy,
        reviews,
        gates,
        [changed_tdd],
        bindings,
        context,
        broker_evidence,
        broker_artifacts,
    )

    verdict = call_attested(
        changed,
        private_key,
        attestations,
        review_packet=bundle.review_packet,
        broker_requests=bundle.broker_requests,
    )

    assert verdict.status == "fail"
    assert any("test paths do not match TaskSpec v2" in reason for reason in verdict.reasons)


def test_mismatched_model_request_and_duplicate_review_session_fail_closed():
    bundle = make_bundle()
    task, policy, reviews, gates, tdds, bindings, context, broker_evidence, broker_artifacts = (
        bundle
    )
    private_key = Ed25519PrivateKey.generate()
    attestations = sign_expected(private_key, task, policy, reviews, gates, tdds, bindings, context)
    changed_bindings = list(bindings)
    reviewer_index = next(
        index for index, binding in enumerate(changed_bindings) if binding.role == "reviewer"
    )
    reviewer_binding = changed_bindings[reviewer_index]
    changed_bindings[reviewer_index] = reviewer_binding.model_copy(
        update={"request": reviewer_binding.request.model_copy(update={"prompt_sha256": "0" * 64})}
    )
    changed = (
        task,
        policy,
        reviews,
        gates,
        tdds,
        changed_bindings,
        context,
        broker_evidence,
        broker_artifacts,
    )
    request_verdict = call_attested(changed, private_key, attestations)
    assert request_verdict.status == "fail"
    assert any("model prompt" in reason for reason in request_verdict.reasons)

    changed_bindings = list(bindings)
    reviewer_binding = changed_bindings[reviewer_index]
    changed_bindings[reviewer_index] = reviewer_binding.model_copy(
        update={"request": reviewer_binding.request.model_copy(update={"input_sha256": "0" * 64})}
    )
    changed = (
        task,
        policy,
        reviews,
        gates,
        tdds,
        changed_bindings,
        context,
        broker_evidence,
        broker_artifacts,
    )
    input_verdict = call_attested(changed, private_key, attestations)
    assert input_verdict.status == "fail"
    assert any("input SHA-256" in reason for reason in input_verdict.reasons)

    changed_bindings = list(bindings)
    reviewer_binding = changed_bindings[reviewer_index]
    changed_bindings[reviewer_index] = reviewer_binding.model_copy(
        update={"request_sha256": "0" * 64}
    )
    changed = (
        task,
        policy,
        reviews,
        gates,
        tdds,
        changed_bindings,
        context,
        broker_evidence,
        broker_artifacts,
    )
    digest_verdict = call_attested(changed, private_key, attestations)
    assert digest_verdict.status == "fail"
    assert any("request SHA-256" in reason for reason in digest_verdict.reasons)

    duplicate_reviews = [
        reviews[0],
        reviews[1].model_copy(update={"session_id": reviews[0].session_id}),
    ]
    duplicate_bindings = make_bindings(
        task,
        policy,
        gates,
        tdds,
        duplicate_reviews,
        bundle.broker_requests,
    )
    duplicate_broker_evidence = make_broker_evidence(
        duplicate_bindings,
        bundle.review_packet,
        bundle.broker_requests,
        duplicate_reviews,
    )
    duplicate_broker_artifacts = make_broker_artifacts(
        duplicate_bindings,
        bundle.review_packet,
        bundle.broker_requests,
        duplicate_reviews,
    )
    duplicate_bundle = (
        task,
        policy,
        duplicate_reviews,
        gates,
        tdds,
        duplicate_bindings,
        context,
        duplicate_broker_evidence,
        duplicate_broker_artifacts,
    )
    assert call_attested(duplicate_bundle, private_key, attestations).status == "fail"


@pytest.mark.parametrize(
    ("field", "value", "reason"),
    [
        ("provider", "other", "provider"),
        ("model", "gpt-other", "model"),
        ("effort", "low", "reasoning effort"),
        ("attempt", 3, "attempt"),
        ("review_role", "adversary", "review role"),
    ],
)
def test_review_request_provider_model_effort_attempt_and_role_are_fixed(field, value, reason):
    bundle = make_bundle()
    task, policy, reviews, gates, tdds, bindings, context, broker_evidence, broker_artifacts = (
        bundle
    )
    private_key = Ed25519PrivateKey.generate()
    attestations = sign_expected(private_key, task, policy, reviews, gates, tdds, bindings, context)
    changed_bindings = list(bindings)
    reviewer_index = next(
        index for index, binding in enumerate(changed_bindings) if binding.role == "reviewer"
    )
    target = changed_bindings[reviewer_index]
    changed_bindings[reviewer_index] = target.model_copy(
        update={"request": target.request.model_copy(update={field: value})}
    )
    changed = (
        task,
        policy,
        reviews,
        gates,
        tdds,
        changed_bindings,
        context,
        broker_evidence,
        broker_artifacts,
    )

    verdict = call_attested(changed, private_key, attestations)

    assert verdict.status == "fail"
    assert any(reason in item for item in verdict.reasons)


@pytest.mark.parametrize(
    "dimension",
    [
        "packet",
        "request",
        "response",
        "usage",
        "model",
        "effort",
        "attempt",
        "attempt_bool",
        "hard_limit",
        "negative_input",
        "zero_events",
        "inconsistent_warning",
        "excessive_input",
    ],
)
def test_broker_inference_evidence_is_independently_bound(dimension):
    bundle = make_bundle()
    task, policy, reviews, gates, tdds, bindings, context, broker_evidence, broker_artifacts = (
        bundle
    )
    private_key = Ed25519PrivateKey.generate()
    attestations = sign_expected(private_key, task, policy, reviews, gates, tdds, bindings, context)
    changed_evidence = list(broker_evidence)
    reviewer_index = next(
        index for index, evidence in enumerate(changed_evidence) if evidence.role == "reviewer"
    )
    target = changed_evidence[reviewer_index]
    if dimension in {
        "hard_limit",
        "negative_input",
        "zero_events",
        "inconsistent_warning",
        "excessive_input",
    }:
        usage_update = {
            "hard_limit": {"hard_limit_exceeded": True},
            "negative_input": {"input_tokens": -1},
            "zero_events": {"event_count": 0},
            "inconsistent_warning": {"warning_250k": True},
            "excessive_input": {"input_tokens": 999_999},
        }[dimension]
        target = replace(target, usage=replace(target.usage, **usage_update))
    elif dimension == "attempt_bool":
        target = replace(target, attempt=True)
    else:
        field, value = {
            "packet": ("packet_sha256", digest("substituted-packet")),
            "request": ("request_sha256", digest("substituted-request")),
            "response": ("response_sha256", digest("substituted-response")),
            "usage": ("usage_jsonl_sha256", digest("substituted-usage")),
            "model": ("model", "gpt-other"),
            "effort": ("reasoning_effort", "xhigh"),
            "attempt": ("attempt", 2),
        }[dimension]
        target = replace(target, **{field: value})
    changed_evidence[reviewer_index] = target
    changed = (
        task,
        policy,
        reviews,
        gates,
        tdds,
        bindings,
        context,
        changed_evidence,
        broker_artifacts,
    )

    verdict = call_attested(changed, private_key, attestations)

    assert verdict.status == "fail"
    assert any("broker" in reason for reason in verdict.reasons)


def test_review_artifact_and_canonical_broker_response_have_separate_signed_digests():
    bundle = make_bundle()
    (
        task,
        policy,
        reviews,
        gates,
        tdds,
        bindings,
        context,
        broker_evidence,
        broker_artifacts,
    ) = bundle

    expectations = build_attestation_expectations(
        task,
        policy,
        reviews,
        gates,
        tdds,
        bindings,
        bundle.review_packet,
        broker_evidence,
        bundle.broker_requests,
        broker_artifacts,
        context=context,
        task_sha256=TASK_SHA,
        _diagnostic_allow_unmeasured=True,
    )

    reviewer = expectations["reviewer"]
    reviewer_broker = next(item for item in broker_evidence if item.role == "reviewer")
    assert reviewer.artifact_sha256 == canonical_sha256(reviews[0])
    assert reviewer.response_sha256 == reviewer_broker.response_sha256
    assert reviewer.artifact_sha256 != reviewer.response_sha256


def test_all_test_acceptances_require_exactly_one_red_and_green_attestation():
    bundle = make_bundle(second_test=True)
    task, policy, reviews, gates, tdds, bindings, context, broker_evidence, broker_artifacts = (
        bundle
    )
    private_key = Ed25519PrivateKey.generate()
    complete = sign_expected(private_key, task, policy, reviews, gates, tdds, bindings, context)
    assert call_attested(bundle, private_key, complete).status == "fail"

    incomplete_tdds = tdds[:-1]
    incomplete = (
        task,
        policy,
        reviews,
        gates,
        incomplete_tdds,
        bindings,
        context,
        broker_evidence,
        broker_artifacts,
    )
    verdict = call_attested(
        incomplete,
        private_key,
        complete,
        review_packet=bundle.review_packet,
        broker_requests=bundle.broker_requests,
    )
    assert verdict.status == "fail"
    assert any("missing TDD evidence" in reason for reason in verdict.reasons)


@pytest.mark.parametrize("quality", ["medium", "unverified", "blocker"])
def test_attestation_never_overrides_medium_unverified_or_blocking_review(quality):
    bundle = make_bundle()
    (
        task,
        policy,
        reviews,
        gates,
        tdds,
        _bindings,
        context,
        _broker_evidence,
        _broker_artifacts,
    ) = bundle
    if quality == "medium":
        reviews[0] = reviews[0].model_copy(
            update={"findings": [Finding(id="REV-1", severity="medium", evidence="要確認")]}
        )
    elif quality == "unverified":
        reviews[0] = reviews[0].model_copy(update={"unverified": ["external behavior"]})
    else:
        reviews[0] = ReviewReport(
            **{
                **reviews[0].model_dump(),
                "decision": "changes_required",
                "findings": [Finding(id="REV-1", severity="high", evidence="blocking regression")],
            }
        )
    bindings = make_bindings(
        task,
        policy,
        gates,
        tdds,
        reviews,
        bundle.broker_requests,
    )
    broker_evidence = make_broker_evidence(
        bindings,
        bundle.review_packet,
        bundle.broker_requests,
        reviews,
    )
    broker_artifacts = make_broker_artifacts(
        bindings,
        bundle.review_packet,
        bundle.broker_requests,
        reviews,
    )
    changed = (
        task,
        policy,
        reviews,
        gates,
        tdds,
        bindings,
        context,
        broker_evidence,
        broker_artifacts,
    )
    private_key = Ed25519PrivateKey.generate()
    attestations = sign_expected(
        private_key,
        task,
        policy,
        reviews,
        gates,
        tdds,
        bindings,
        context,
        review_packet=bundle.review_packet,
        broker_requests=bundle.broker_requests,
        broker_evidence=broker_evidence,
        broker_artifacts=broker_artifacts,
    )

    verdict = call_attested(
        changed,
        private_key,
        attestations,
        review_packet=bundle.review_packet,
        broker_requests=bundle.broker_requests,
    )
    assert verdict.status == "fail"
    assert verdict.status != "pass"
    assert verdict.human_approval_required is True


def test_tdd_v1_is_diagnostic_only_and_cannot_receive_attested_pass():
    bundle = make_bundle()
    task, policy, reviews, gates, tdds, bindings, context, broker_evidence, broker_artifacts = (
        bundle
    )
    v1_payload = tdds[0].model_dump()
    v1_payload["schema_version"] = "1.0"
    v1_payload.pop("red_snapshot_sha256")
    v1_payload.pop("green_snapshot_sha256")
    v1 = TddEvidence.model_validate(v1_payload)
    changed = (
        task,
        policy,
        reviews,
        gates,
        [v1],
        bindings,
        context,
        broker_evidence,
        broker_artifacts,
    )

    verdict = call_attested(
        changed,
        Ed25519PrivateKey.generate(),
        [],
        review_packet=bundle.review_packet,
        broker_requests=bundle.broker_requests,
    )
    assert verdict.status == "fail"
    assert any("TDD v2" in reason for reason in verdict.reasons)


def test_taskspec_v1_is_diagnostic_only_and_cannot_receive_attested_pass():
    task = make_task(schema_version="1.0")
    policy = make_policy(task)
    gates = make_gates(task)
    tdds = make_tdds(task, policy)
    packet = make_review_packet(task, policy, gates, tdds)
    broker_requests = make_broker_requests(packet)
    reviews = make_reviews(task, packet, broker_requests)
    bindings = make_bindings(task, policy, gates, tdds, reviews, broker_requests)
    output_schema = broker_requests[0].payload["text"]["format"]["schema"]
    context = TrustedAttestationContext(
        runtime_manifest_sha256=RUNTIME_SHA,
        coordinator_image_digest=COORDINATOR_IMAGE_DIGEST,
        offline_runner_image_digest=OFFLINE_IMAGE_DIGEST,
        broker_image_digest=BROKER_IMAGE_DIGEST,
        broker_gateway_image_digest=BROKER_GATEWAY_IMAGE_DIGEST,
        broker_egress_boundary_sha256=SYNTHETIC_EGRESS_BOUNDARY_SET_SHA256,
        broker_allowlist_policy_sha256=digest("v1-broker-allowlist"),
        broker_ledger_identity_sha256=digest("v1-broker-ledger-identity"),
        broker_packet_reservation_limit=MAX_PACKET_RESERVED_TOKENS,
        broker_pricing_policy_sha256=APPROVED_OPENAI_PRICING_POLICY.sha256,
        broker_packet_cost_limit_microusd=DEFAULT_PACKET_COST_LIMIT_MICROUSD,
        base_snapshot_sha256=BASE_SNAPSHOT_SHA,
        base_snapshot_manifest_sha256=BASE_MANIFEST_SHA,
        base_commit_tree_sha=BASE_TREE_SHA,
        candidate_snapshot_sha256=CANDIDATE_SNAPSHOT_SHA,
        candidate_snapshot_manifest_sha256=CANDIDATE_MANIFEST_SHA,
        candidate_commit_tree_sha=CANDIDATE_TREE_SHA,
        review_packet_sha256=packet.packet_sha256,
        review_output_schema_sha256=canonical_sha256(output_schema),
    )
    bundle = (
        task,
        policy,
        reviews,
        gates,
        tdds,
        bindings,
        context,
        make_broker_evidence(bindings, packet, broker_requests, reviews),
        make_broker_artifacts(bindings, packet, broker_requests, reviews),
    )

    verdict = call_attested(bundle, Ed25519PrivateKey.generate(), [])

    assert verdict.status == "fail"
    assert any("TaskSpec v2" in reason for reason in verdict.reasons)
