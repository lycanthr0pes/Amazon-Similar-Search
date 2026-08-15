from __future__ import annotations

import hashlib
from collections import Counter

from tools.ai_review.models import GateResult
from tools.ai_review.models import PolicyReport
from tools.ai_review.models import ReviewReport
from tools.ai_review.models import TaskSpec
from tools.ai_review.models import TddEvidence
from tools.ai_review.models import Verdict


REQUIRED_ROLES = {"reviewer", "adversary"}


def build_test_manifest_sha256(policy: PolicyReport, test_paths: list[str]) -> str | None:
    """Bind the declared test paths to content hashes from the inspected candidate tree."""

    files_by_path = {item.path: item for item in policy.changed_files}
    digest = hashlib.sha256()
    digest.update(b"amazon-explorer-ai-review-test-manifest-v1\0")
    for path in sorted(test_paths):
        item = files_by_path.get(path)
        if item is None or item.content_sha256 is None:
            return None
        for value in (path, item.content_sha256):
            encoded = value.encode("utf-8")
            digest.update(len(encoded).to_bytes(4, "big"))
            digest.update(encoded)
    return digest.hexdigest()


def judge(
    task: TaskSpec,
    policy: PolicyReport,
    reviews: list[ReviewReport],
    gates: list[GateResult],
    tdd: TddEvidence,
    *,
    task_sha256: str,
) -> Verdict:
    """Return the same verdict for the same validated evidence."""

    reasons: list[str] = []
    blockers: list[str] = []
    requirement_ids = {requirement.id for requirement in task.requirements}
    acceptance_by_id = {test.id: test for test in task.acceptance_tests}

    if policy.task_id != task.task_id:
        reasons.append("policy task id does not match the task")
    if policy.task_sha256 != task_sha256:
        reasons.append("policy raw task SHA-256 does not match the task input")
    if policy.base_sha != task.base_sha:
        reasons.append("policy base SHA does not match the task")
    if policy.trusted_harness_sha256 != task.trusted_harness_sha256:
        reasons.append("policy trusted harness SHA-256 does not match the task")
    if not policy.passed:
        reasons.extend(f"policy: {violation}" for violation in policy.violations)
    if policy.patch_sha256 is None:
        reasons.append("policy did not produce a patch SHA-256")

    if tdd.base_sha != task.base_sha:
        reasons.append("TDD evidence base SHA does not match the task")
    if tdd.task_id != task.task_id:
        reasons.append("TDD evidence task id does not match the task")
    if tdd.task_sha256 != task_sha256:
        reasons.append("TDD evidence raw task SHA-256 does not match the task input")
    if tdd.head_sha != policy.head_sha:
        reasons.append("TDD evidence head SHA does not match policy evidence")
    if tdd.patch_sha256 != policy.patch_sha256:
        reasons.append("TDD evidence patch SHA-256 does not match policy evidence")
    tdd_acceptance = acceptance_by_id.get(tdd.acceptance_test_id)
    if tdd_acceptance is None:
        reasons.append("TDD evidence references an unknown acceptance test")
    elif tdd_acceptance.kind != "test":
        reasons.append("TDD evidence must reference an acceptance test of kind test")
    elif tdd.command != tdd_acceptance.command:
        reasons.append("TDD evidence command does not match the task")
    elif task.schema_version == "2.0" and tdd.test_paths != tdd_acceptance.test_paths:
        reasons.append("TDD evidence test paths do not match the TaskSpec")
    if (
        tdd_acceptance is not None
        and tdd.red.exit_code not in tdd_acceptance.expected_red_exit_codes
    ):
        reasons.append("RED phase exit code does not match the task's expected failure")
    if (
        tdd_acceptance is not None
        and tdd.red.failure_fingerprint_sha256 != tdd_acceptance.expected_red_fingerprint_sha256
    ):
        reasons.append("RED phase failure fingerprint does not match the task")
    if tdd_acceptance is not None and tdd.green.exit_code != tdd_acceptance.expected_exit_code:
        reasons.append("GREEN phase did not pass")
    if (
        tdd.red.test_patch_sha256 != tdd.test_patch_sha256
        or tdd.green.test_patch_sha256 != tdd.test_patch_sha256
    ):
        reasons.append("test patch changed between RED and GREEN")
    if tdd.schema_version == "2.0":
        if tdd.red_snapshot_sha256 is None or tdd.green_snapshot_sha256 is None:
            reasons.append("TDD v2 requires measured RED and GREEN snapshot SHA-256 values")
        elif tdd.red_snapshot_sha256 == tdd.green_snapshot_sha256:
            reasons.append("TDD v2 RED and GREEN snapshots must be distinct")
    changed_paths = {item.path for item in policy.changed_files}
    missing_test_paths = sorted(set(tdd.test_paths) - changed_paths)
    if missing_test_paths:
        reasons.append(
            "TDD test paths are absent from the candidate diff: " + ", ".join(missing_test_paths)
        )
    expected_test_manifest_sha256 = build_test_manifest_sha256(policy, tdd.test_paths)
    if expected_test_manifest_sha256 is None:
        reasons.append("TDD test manifest cannot be derived from policy evidence")
    elif tdd.test_manifest_sha256 != expected_test_manifest_sha256:
        reasons.append("TDD test manifest SHA-256 does not match policy evidence")

    gate_counts = Counter(gate.acceptance_test_id for gate in gates)
    missing_gates = sorted(set(acceptance_by_id) - set(gate_counts))
    unknown_gates = sorted(set(gate_counts) - set(acceptance_by_id))
    duplicate_gates = sorted(gate_id for gate_id, count in gate_counts.items() if count != 1)
    if missing_gates:
        reasons.append(f"missing acceptance gates: {', '.join(missing_gates)}")
    if unknown_gates:
        reasons.append(f"unknown acceptance gates: {', '.join(unknown_gates)}")
    if duplicate_gates:
        reasons.append(f"acceptance gates must appear exactly once: {', '.join(duplicate_gates)}")
    for gate in gates:
        if gate.task_id != task.task_id:
            reasons.append(f"gate {gate.acceptance_test_id} task id does not match the task")
        if gate.task_sha256 != task_sha256:
            reasons.append(
                f"gate {gate.acceptance_test_id} raw task SHA-256 does not match the task input"
            )
        if gate.head_sha != policy.head_sha:
            reasons.append(
                f"gate {gate.acceptance_test_id} head SHA does not match policy evidence"
            )
        if gate.patch_sha256 != policy.patch_sha256:
            reasons.append(
                f"gate {gate.acceptance_test_id} candidate digest does not match policy evidence"
            )
        acceptance = acceptance_by_id.get(gate.acceptance_test_id)
        if acceptance is None:
            continue
        if gate.command != acceptance.command:
            reasons.append(f"gate {gate.acceptance_test_id} command does not match the task")
        if gate.expected_exit_code != acceptance.expected_exit_code:
            reasons.append(
                f"gate {gate.acceptance_test_id} expected exit code does not match the task"
            )
        if not gate.passed:
            reasons.append(f"gate failed: {gate.acceptance_test_id}")

    role_counts = Counter(review.role for review in reviews)
    missing_roles = sorted(REQUIRED_ROLES - set(role_counts))
    duplicate_roles = sorted(role for role, count in role_counts.items() if count != 1)
    if missing_roles:
        reasons.append(f"missing review roles: {', '.join(missing_roles)}")
    if duplicate_roles:
        reasons.append(f"review roles must appear exactly once: {', '.join(duplicate_roles)}")

    for review in reviews:
        if review.task_id != task.task_id:
            reasons.append(f"{review.role} task id does not match the task")
        if review.task_sha256 != task_sha256:
            reasons.append(f"{review.role} raw task SHA-256 does not match the task input")
        if review.base_sha != task.base_sha:
            reasons.append(f"{review.role} base SHA does not match the task")
        if review.head_sha != policy.head_sha:
            reasons.append(f"{review.role} head SHA does not match policy evidence")
        if review.patch_sha256 != policy.patch_sha256:
            reasons.append(f"{review.role} patch SHA-256 does not match policy evidence")
        expected_prompt_sha256 = (
            task.review_prompts.reviewer_sha256
            if review.role == "reviewer"
            else task.review_prompts.adversary_sha256
        )
        if review.prompt_sha256 != expected_prompt_sha256:
            reasons.append(f"{review.role} prompt SHA-256 does not match the task")
        if review.decision != "accept":
            reasons.append(f"{review.role} decision is {review.decision}")
        for finding in review.findings:
            if finding.requirement_id is not None and finding.requirement_id not in requirement_ids:
                reasons.append(
                    f"{review.role} finding {finding.id} references unknown requirement "
                    f"{finding.requirement_id}"
                )
            if finding.severity in {"critical", "high"}:
                blockers.append(f"{review.role}:{finding.id}")

    if len(reviews) == 2:
        if len({review.reviewer_id for review in reviews}) != 2:
            reasons.append("reviewer and adversary must use distinct reviewer ids")
        if len({review.session_id for review in reviews}) != 2:
            reasons.append("reviewer and adversary must use distinct session ids")

    reasons = list(dict.fromkeys(reasons))
    blockers = list(dict.fromkeys(blockers))
    if reasons or blockers:
        status = "fail"
    elif any(review.unverified for review in reviews) or any(
        finding.severity == "medium" for review in reviews for finding in review.findings
    ):
        status = "human_review"
        reasons = ["medium findings or unverified items require an explicit human decision"]
    else:
        status = "human_review"
        reasons = ["review provenance is self-reported until a trusted coordinator attests it"]

    return Verdict(
        task_id=task.task_id,
        task_sha256=task_sha256,
        trusted_harness_sha256=task.trusted_harness_sha256,
        base_sha=task.base_sha,
        head_sha=policy.head_sha,
        patch_sha256=policy.patch_sha256,
        status=status,
        gates=gates,
        blocking_findings=blockers,
        reasons=reasons,
        human_approval_required=True,
    )
