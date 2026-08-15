from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import re
import shlex
import sys
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from tools.ai_review.codex_adapter import CodexAdapter
from tools.ai_review.coordinator_runtime import CoordinatorRuntimeError
from tools.ai_review.coordinator_runtime import CoordinatorRuntimeEvidence
from tools.ai_review.coordinator_runtime import verify_coordinator_runtime
from tools.ai_review.judge import judge
from tools.ai_review.models import GateResult
from tools.ai_review.models import PolicyReport
from tools.ai_review.models import ReviewReport
from tools.ai_review.models import TaskSpec
from tools.ai_review.models import TddEvidence
from tools.ai_review.policy import GitInspectionError
from tools.ai_review.policy import inspect_git_diff
from tools.ai_review.preflight import PreflightError
from tools.ai_review.preflight import read_verified_fd_asset
from tools.ai_review.production_cli import register_production_subcommands
from tools.ai_review.phase_protocol import PhaseProtocolError
from tools.ai_review.path_safety import resolve_safe_input
from tools.ai_review.path_safety import resolve_safe_output
from tools.ai_review.path_safety import ensure_trusted_coordinator_directory
from tools.ai_review.path_safety import ensure_readonly_artifact_directory
from tools.ai_review.path_safety import write_text_exclusive
from tools.ai_review.trusted_runtime import RuntimeTrustError
from tools.ai_review.trusted_runtime import verify_trusted_zipapp


def _load_json(
    path: Path,
    *,
    trusted_root: Path | None = None,
    expected_sha256: str | None = None,
) -> Any:
    descriptor_input = re.fullmatch(r"/proc/self/fd/(?:0|[1-9][0-9]*)", str(path))
    if descriptor_input is not None:
        if expected_sha256 is None:
            raise ValueError("verified descriptor JSON requires an expected SHA-256")
        try:
            _evidence, raw = read_verified_fd_asset(
                path,
                expected_sha256=expected_sha256,
                label="structured evidence",
                max_bytes=16 * 1024 * 1024,
            )
        except PreflightError as exc:
            raise ValueError(str(exc)) from exc
    else:
        safe_path = resolve_safe_input(path)
        if trusted_root is not None:
            safe_root = ensure_trusted_coordinator_directory(trusted_root)
            if not safe_path.is_relative_to(safe_root):
                raise ValueError("structured evidence must be inside the trusted artifact root")
        raw = safe_path.read_bytes()

    def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate JSON key: {key}")
            result[key] = value
        return result

    if expected_sha256 is not None and descriptor_input is None:
        actual_sha256 = hashlib.sha256(raw).hexdigest()
        if not hmac.compare_digest(actual_sha256, expected_sha256):
            raise ValueError("task SHA-256 does not match the coordinator-fixed value")
    return json.loads(
        raw.decode("utf-8", errors="strict"),
        object_pairs_hook=reject_duplicate_keys,
    )


def _write_json(
    payload: Any,
    output: Path | None,
    *,
    trusted_root: Path | None = None,
) -> None:
    text = json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    if output is None:
        print(text, end="")
    else:
        if trusted_root is not None:
            safe_root = ensure_trusted_coordinator_directory(trusted_root)
            safe_output = resolve_safe_output(output)
            if not safe_output.is_relative_to(safe_root):
                raise ValueError("structured output must be inside the trusted artifact root")
        write_text_exclusive(output, text)


def _trusted_root(args: argparse.Namespace) -> Path:
    if _runtime_arguments_present(args):
        return ensure_readonly_artifact_directory(args.artifact_root)
    return ensure_trusted_coordinator_directory(args.artifact_root)


def _runtime_arguments_present(args: argparse.Namespace) -> bool:
    return any(
        getattr(args, name, None) is not None
        for name in (
            "runtime_root",
            "runtime_manifest",
            "expected_runtime_manifest_sha256",
            "expected_coordinator_image_digest",
        )
    )


def _verify_coordinator_inputs(args: argparse.Namespace) -> CoordinatorRuntimeEvidence | None:
    if not _runtime_arguments_present(args):
        return None
    values = (
        args.runtime_root,
        args.runtime_manifest,
        args.expected_runtime_manifest_sha256,
        args.expected_coordinator_image_digest,
    )
    if any(value is None for value in values):
        raise ValueError("coordinator runtime arguments must be supplied together")
    expected_task_path = Path(args.runtime_root) / "task.json"
    if Path(args.task).resolve(strict=True) != expected_task_path.resolve(strict=True):
        raise ValueError("coordinator task must use the fixed read-only runtime mount")
    return verify_coordinator_runtime(
        runtime_root=args.runtime_root,
        manifest_path=args.runtime_manifest,
        expected_manifest_sha256=args.expected_runtime_manifest_sha256,
        expected_coordinator_image_digest=args.expected_coordinator_image_digest,
        expected_task_sha256=args.expected_task_sha256,
    )


def _load_task(
    args: argparse.Namespace,
    *,
    trusted_root: Path,
    coordinator: CoordinatorRuntimeEvidence | None,
) -> TaskSpec:
    task = TaskSpec.model_validate(
        _load_json(
            args.task,
            trusted_root=None if coordinator is not None else trusted_root,
            expected_sha256=args.expected_task_sha256,
        )
    )
    if coordinator is not None:
        if task.trusted_harness_sha256 != coordinator.harness_sha256:
            raise ValueError("TaskSpec harness SHA-256 differs from the runtime manifest")
    return task


def _verify_handler_runtime(
    args: argparse.Namespace,
    *,
    task: TaskSpec,
    repo: Path,
    coordinator: CoordinatorRuntimeEvidence | None,
) -> None:
    if coordinator is None:
        verify_trusted_zipapp(
            expected_sha256=task.trusted_harness_sha256,
            candidate_repo=repo,
        )


def _reinspect_policy(
    repo: Path,
    task: TaskSpec,
    task_sha256: str,
    stored_policy: PolicyReport,
) -> PolicyReport:
    current_policy = inspect_git_diff(
        repo,
        task,
        task_sha256=task_sha256,
        head="HEAD",
        expected_patch_sha256=stored_policy.patch_sha256,
    )
    if current_policy != stored_policy:
        raise ValueError("stored policy evidence does not match the current candidate repository")
    return current_policy


def _policy(args: argparse.Namespace) -> int:
    trusted_root = _trusted_root(args)
    repo = args.repo.resolve(strict=True)
    if repo.is_relative_to(trusted_root) or trusted_root.is_relative_to(repo):
        raise ValueError("trusted artifact root and candidate repository must be separate")
    coordinator = _verify_coordinator_inputs(args)
    task = _load_task(args, trusted_root=trusted_root, coordinator=coordinator)
    _verify_handler_runtime(args, task=task, repo=repo, coordinator=coordinator)
    report = inspect_git_diff(
        repo,
        task,
        task_sha256=args.expected_task_sha256,
        head=args.head,
        expected_patch_sha256=args.expected_patch_sha256,
    )
    _write_json(report.model_dump(mode="json"), args.output, trusted_root=trusted_root)
    return 0 if report.passed else 1


def _judge(args: argparse.Namespace) -> int:
    trusted_root = _trusted_root(args)
    repo = args.repo.resolve(strict=True)
    if repo.is_relative_to(trusted_root) or trusted_root.is_relative_to(repo):
        raise ValueError("trusted artifact root and candidate repository must be separate")
    coordinator = _verify_coordinator_inputs(args)
    task = _load_task(args, trusted_root=trusted_root, coordinator=coordinator)
    _verify_handler_runtime(args, task=task, repo=repo, coordinator=coordinator)
    policy = PolicyReport.model_validate(_load_json(args.policy, trusted_root=trusted_root))
    _reinspect_policy(repo, task, args.expected_task_sha256, policy)
    reviews = [
        ReviewReport.model_validate(_load_json(path, trusted_root=trusted_root))
        for path in args.review
    ]
    gates = [
        GateResult.model_validate(_load_json(path, trusted_root=trusted_root)) for path in args.gate
    ]
    tdd = TddEvidence.model_validate(_load_json(args.tdd_evidence, trusted_root=trusted_root))
    verdict = judge(
        task,
        policy,
        reviews,
        gates,
        tdd,
        task_sha256=args.expected_task_sha256,
    )
    _write_json(verdict.model_dump(mode="json"), args.output, trusted_root=trusted_root)
    return 0 if verdict.status == "pass" else 1


def _codex(args: argparse.Namespace) -> int:
    verify_trusted_zipapp(
        expected_sha256=args.expected_harness_sha256,
        candidate_repo=args.candidate_repo,
    )
    adapter = CodexAdapter(executable=args.executable)
    result = adapter.run(
        prompt=args.prompt,
        output_schema=args.output_schema,
        output_path=args.output,
        cwd=args.coordinator_dir,
        candidate_repo=args.candidate_repo,
        execute=args.execute,
    )
    _write_json(
        {
            "dry_run": True,
            "argv": list(result.argv),
            "display": shlex.join(result.argv),
        },
        None,
    )
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Fail-closed AI review harness MVP")
    subparsers = parser.add_subparsers(dest="command", required=True)

    policy_parser = subparsers.add_parser("policy", help="validate a committed Git diff")
    policy_parser.add_argument("--task", type=Path, required=True)
    policy_parser.add_argument("--repo", type=Path, required=True)
    policy_parser.add_argument("--artifact-root", type=Path, required=True)
    policy_parser.add_argument("--expected-task-sha256", required=True)
    policy_parser.add_argument("--head", default="HEAD")
    policy_parser.add_argument("--expected-patch-sha256")
    policy_parser.add_argument("--output", type=Path)
    _add_coordinator_runtime_arguments(policy_parser)
    policy_parser.set_defaults(handler=_policy)

    judge_parser = subparsers.add_parser("judge", help="combine validated evidence")
    judge_parser.add_argument("--repo", type=Path, required=True)
    judge_parser.add_argument("--task", type=Path, required=True)
    judge_parser.add_argument("--artifact-root", type=Path, required=True)
    judge_parser.add_argument("--expected-task-sha256", required=True)
    judge_parser.add_argument("--policy", type=Path, required=True)
    judge_parser.add_argument("--review", type=Path, action="append", required=True)
    judge_parser.add_argument("--gate", type=Path, action="append", required=True)
    judge_parser.add_argument("--tdd-evidence", type=Path, required=True)
    judge_parser.add_argument("--output", type=Path)
    _add_coordinator_runtime_arguments(judge_parser)
    judge_parser.set_defaults(handler=_judge)

    codex_parser = subparsers.add_parser("codex", help="print a disabled-by-default Codex argv")
    codex_parser.add_argument("--candidate-repo", type=Path, required=True)
    codex_parser.add_argument("--expected-harness-sha256", required=True)
    codex_parser.add_argument("--coordinator-dir", type=Path, required=True)
    codex_parser.add_argument("--output-schema", type=Path, required=True)
    codex_parser.add_argument("--output", type=Path, required=True)
    codex_parser.add_argument("--prompt", required=True)
    codex_parser.add_argument("--executable", default="codex")
    codex_parser.add_argument(
        "--execute",
        action="store_true",
        help="reserved for a future isolated coordinator; currently rejected",
    )
    codex_parser.set_defaults(handler=_codex)
    register_production_subcommands(
        subparsers,
        add_runtime_arguments=_add_coordinator_runtime_arguments,
    )
    return parser


def _add_coordinator_runtime_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--runtime-root", type=Path)
    parser.add_argument("--runtime-manifest", type=Path)
    parser.add_argument("--expected-runtime-manifest-sha256")
    parser.add_argument("--expected-coordinator-image-digest")


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.handler(args)
    except ValidationError as error:
        summaries = [
            f"{'.'.join(str(item) for item in detail['loc'])}: {detail['type']}"
            for detail in error.errors(include_input=False, include_url=False)
        ]
        print("ai-review: invalid structured evidence: " + "; ".join(summaries), file=sys.stderr)
        return 2
    except (
        GitInspectionError,
        CoordinatorRuntimeError,
        RuntimeTrustError,
        PhaseProtocolError,
        OSError,
        ValueError,
        json.JSONDecodeError,
    ) as error:
        print(f"ai-review: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
