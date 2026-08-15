"""Canonical coordinator CLI surface for the production phase protocol."""

from __future__ import annotations

import argparse
import hashlib
import hmac
import sys
from pathlib import Path
from typing import Callable

from tools.ai_review.path_safety import resolve_safe_input
from tools.ai_review.phase_protocol import PHASE_ORDER
from tools.ai_review.phase_protocol import PhaseAction
from tools.ai_review.phase_protocol import PhaseChain
from tools.ai_review.phase_protocol import PhaseProtocolError
from tools.ai_review.phase_protocol import PhaseRequest
from tools.ai_review.phase_protocol import PhaseResult


_MAX_PHASE_PAYLOAD_BYTES = 6_000_000


def _read_payload(
    path: Path,
    *,
    artifact_root: Path,
    expected_sha256: str,
) -> bytes:
    safe = resolve_safe_input(path)
    if not safe.is_relative_to(artifact_root):
        raise PhaseProtocolError("phase payload must be inside the read-only artifact input")
    raw = safe.read_bytes()
    if not raw or len(raw) > _MAX_PHASE_PAYLOAD_BYTES:
        raise PhaseProtocolError("phase payload is empty or exceeds its byte limit")
    measured = hashlib.sha256(raw).hexdigest()
    if not hmac.compare_digest(measured, expected_sha256):
        raise PhaseProtocolError("phase payload SHA-256 does not match the outer request")
    return raw


def _production_phase(args: argparse.Namespace) -> int:
    if args.workflow_operation is not None:
        return _production_workflow_phase(args)
    if args.phase_payload is None or args.expected_phase_payload_sha256 is None:
        raise PhaseProtocolError("legacy phase action mode requires its bound payload")
    # Local import prevents a registration-time cycle with tools.ai_review.cli.
    from tools.ai_review.cli import _load_json
    from tools.ai_review.cli import _load_task
    from tools.ai_review.cli import _trusted_root
    from tools.ai_review.cli import _verify_coordinator_inputs
    from tools.ai_review.cli import _write_json

    artifact_root = _trusted_root(args)
    coordinator = _verify_coordinator_inputs(args)
    if coordinator is None:
        raise PhaseProtocolError("production phases require the pinned coordinator runtime")
    _load_task(args, trusted_root=artifact_root, coordinator=coordinator)
    request = PhaseRequest.model_validate(
        _load_json(
            args.phase_request,
            trusted_root=artifact_root,
            expected_sha256=args.expected_phase_request_file_sha256,
        )
    )
    if request.phase != args.production_phase:
        raise PhaseProtocolError("CLI command does not match the phase request")
    if request.task_sha256 != args.expected_task_sha256:
        raise PhaseProtocolError("phase request does not match the runtime TaskSpec")
    if request.runtime_manifest_sha256 != coordinator.manifest_sha256:
        raise PhaseProtocolError("phase request does not match the runtime manifest")
    if request.coordinator_public_key_sha256 != coordinator.coordinator_public_key_sha256:
        raise PhaseProtocolError("phase request does not match the coordinator public key")
    history = tuple(
        PhaseResult.model_validate(_load_json(path, trusted_root=artifact_root))
        for path in args.phase_history
    )
    PhaseChain(history).validate_request(request)
    payload = _read_payload(
        args.phase_payload,
        artifact_root=artifact_root,
        expected_sha256=args.expected_phase_payload_sha256,
    )
    if not hmac.compare_digest(
        request.input_artifacts_sha256,
        args.expected_phase_payload_sha256,
    ):
        raise PhaseProtocolError("phase request does not bind the supplied artifact payload")
    external_kind = (
        "offline"
        if request.phase == "offline"
        else "broker"
        if request.phase == "broker"
        else "none"
    )
    action = PhaseAction.create(
        request=request,
        external_kind=external_kind,
        payload_sha256=hashlib.sha256(payload).hexdigest(),
    )
    _write_json(action.model_dump(mode="json"), None)
    return 0


def _workflow_inputs(args: argparse.Namespace):
    """Validate the coordinator trust context and complete prior result chain."""

    from tools.ai_review.attestation import load_trusted_public_key
    from tools.ai_review.attestation import public_key_id
    from tools.ai_review.cli import _load_json
    from tools.ai_review.cli import _load_task
    from tools.ai_review.cli import _trusted_root
    from tools.ai_review.cli import _verify_coordinator_inputs
    from tools.ai_review.path_safety import ensure_trusted_coordinator_directory
    from tools.ai_review.phase_protocol import canonical_json_bytes
    from tools.ai_review.preflight import assert_candidate_cannot_mutate_tree

    required = {
        "phase output root": args.phase_output_root,
        "candidate uid": args.candidate_uid,
        "offline image": args.offline_image,
        "broker image": args.broker_image,
        "broker gateway image": args.broker_gateway_image,
        "runtime root": args.runtime_root,
    }
    missing = [label for label, value in required.items() if value is None]
    if missing:
        raise PhaseProtocolError("workflow operation lacks " + ", ".join(missing))
    artifact_root = _trusted_root(args)
    coordinator = _verify_coordinator_inputs(args)
    if coordinator is None:
        raise PhaseProtocolError("workflow operations require the pinned coordinator runtime")
    task = _load_task(args, trusted_root=artifact_root, coordinator=coordinator)
    if task.schema_version != "2.0":
        raise PhaseProtocolError("production workflow requires TaskSpec v2")
    request_raw = _read_payload(
        args.phase_request,
        artifact_root=artifact_root,
        expected_sha256=args.expected_phase_request_file_sha256,
    )
    request = PhaseRequest.model_validate_json(request_raw)
    if canonical_json_bytes(request) != request_raw:
        raise PhaseProtocolError("phase request must use canonical encoding")
    if request.phase != args.production_phase:
        raise PhaseProtocolError("CLI command does not match the phase request")
    if (
        request.task_sha256 != args.expected_task_sha256
        or request.runtime_manifest_sha256 != coordinator.manifest_sha256
        or request.coordinator_public_key_sha256 != coordinator.coordinator_public_key_sha256
    ):
        raise PhaseProtocolError("phase request differs from the pinned coordinator inputs")
    public_key = load_trusted_public_key(
        Path(args.runtime_root) / "coordinator-public-key.pem",
        expected_sha256=coordinator.coordinator_public_key_sha256,
        candidate_uid=args.candidate_uid,
    )
    if not hmac.compare_digest(request.coordinator_key_id, public_key_id(public_key)):
        raise PhaseProtocolError("phase request coordinator key id is invalid")

    history_paths = tuple(artifact_root.rglob("phase-result.json"))
    unordered_history = tuple(
        PhaseResult.model_validate(_load_json(path, trusted_root=artifact_root))
        for path in history_paths
    )
    history = tuple(sorted(unordered_history, key=lambda item: item.request.sequence))
    if len(history) != request.sequence - 1 or tuple(
        item.request.sequence for item in history
    ) != tuple(range(1, request.sequence)):
        raise PhaseProtocolError("workflow artifact tree has incomplete or duplicate history")
    PhaseChain(history).validate_request(request)
    output_root = ensure_trusted_coordinator_directory(args.phase_output_root)
    if any(output_root.iterdir()):
        raise PhaseProtocolError("coordinator workflow output root must start empty")
    snapshot_root = None
    if args.snapshot_artifact_root is not None:
        snapshot_root = assert_candidate_cannot_mutate_tree(
            args.snapshot_artifact_root,
            candidate_uid=args.candidate_uid,
        ).root
    if (request.phase != "snapshot" or args.workflow_operation == "finalize") and (
        snapshot_root is None
    ):
        raise PhaseProtocolError("workflow phase lacks its dedicated snapshot artifact mount")
    judge_prepare = request.phase == "attested-judge" and args.workflow_operation == "prepare"
    if (args.nonce_ledger is not None) != judge_prepare:
        raise PhaseProtocolError(
            "nonce ledger is required only for attested-judge workflow prepare"
        )
    if request.phase == "broker":
        broker_values = {
            "ledger identity": args.broker_ledger_identity_sha256,
            "egress policy": args.broker_egress_policy,
            "egress policy digest": args.expected_broker_egress_policy_sha256,
            "pricing policy": args.broker_pricing_policy,
            "pricing policy digest": args.expected_broker_pricing_policy_sha256,
            "packet reservation limit": args.broker_packet_reservation_limit,
            "packet cost limit": args.broker_packet_cost_limit_microusd,
            "runtime binding": args.broker_runtime_binding,
            "runtime binding digest": args.expected_broker_runtime_binding_sha256,
        }
        broker_missing = [label for label, value in broker_values.items() if value is None]
        if broker_missing:
            raise PhaseProtocolError("broker workflow lacks " + ", ".join(broker_missing))
        expected_paths = (
            (
                Path(args.broker_egress_policy).resolve(strict=True),
                (Path(args.runtime_root) / "broker-egress-policy.json").resolve(strict=True),
            ),
            (
                Path(args.broker_pricing_policy).resolve(strict=True),
                (Path(args.runtime_root) / "openai-pricing-policy.json").resolve(strict=True),
            ),
        )
        if any(actual != expected for actual, expected in expected_paths):
            raise PhaseProtocolError("broker policies must use their fixed runtime mounts")
        trusted_values = (
            (
                args.expected_broker_egress_policy_sha256,
                coordinator.broker_allowlist_policy_sha256,
            ),
            (
                args.expected_broker_pricing_policy_sha256,
                coordinator.broker_pricing_policy_sha256,
            ),
            (
                args.broker_packet_reservation_limit,
                coordinator.broker_packet_reservation_limit,
            ),
            (
                args.broker_packet_cost_limit_microusd,
                coordinator.broker_packet_cost_limit_microusd,
            ),
        )
        if any(actual != expected for actual, expected in trusted_values):
            raise PhaseProtocolError("broker CLI values differ from the runtime manifest")
    return artifact_root, output_root, snapshot_root, coordinator, task, request


def _production_workflow_phase(args: argparse.Namespace) -> int:
    """Execute one pinned-coordinator half-transition for the outer driver."""

    from tools.ai_review.coordinator_workflow_inputs import external_finalize_inputs
    from tools.ai_review.coordinator_workflow_inputs import external_prepare_inputs
    from tools.ai_review.coordinator_workflow_inputs import red_snapshot_finalize_inputs
    from tools.ai_review.coordinator_workflow_inputs import red_snapshot_prepare_inputs
    from tools.ai_review.coordinator_workflow_inputs import review_packet_finalize_inputs
    from tools.ai_review.coordinator_workflow_inputs import review_packet_prepare_inputs
    from tools.ai_review.coordinator_workflow_inputs import snapshot_finalize_inputs
    from tools.ai_review.coordinator_workflow_inputs import snapshot_prepare_inputs
    from tools.ai_review.coordinator_workflow_ops import finalize_workflow_transition
    from tools.ai_review.coordinator_workflow_ops import prepare_workflow_transition

    artifact_root, output_root, snapshot_root, coordinator, task, request = _workflow_inputs(args)
    if args.workflow_operation == "prepare":
        if request.phase == "snapshot":
            if args.candidate_repo != Path("/candidate"):
                raise PhaseProtocolError("snapshot prepare requires the fixed candidate mount")
            inputs = snapshot_prepare_inputs(
                request,
                task=task,
                candidate_repo=args.candidate_repo,
                output_root=output_root,
                candidate_uid=args.candidate_uid,
            )
            raw = prepare_workflow_transition(request, inputs=inputs)
            sys.stdout.buffer.write(raw)
            sys.stdout.buffer.flush()
            return 0
        if args.candidate_repo is not None:
            raise PhaseProtocolError("candidate mount is forbidden after snapshot prepare")
        if request.phase in {"sign", "attested-judge"}:
            assert snapshot_root is not None
            inputs = {
                "artifact_root": artifact_root,
                "candidate_uid": args.candidate_uid,
                "coordinator": coordinator,
                "nonce_ledger": (args.nonce_ledger if request.phase == "attested-judge" else None),
                "runtime_root": args.runtime_root,
                "signing_key": (
                    Path("/signing/coordinator-private-key.pem")
                    if request.phase == "sign"
                    else None
                ),
                "snapshot_artifact_root": snapshot_root,
            }
            raw = prepare_workflow_transition(request, inputs=inputs)
            sys.stdout.buffer.write(raw)
            sys.stdout.buffer.flush()
            return 0
        if request.phase == "red-snapshot":
            assert snapshot_root is not None
            inputs = red_snapshot_prepare_inputs(
                request,
                task=task,
                artifact_root=artifact_root,
                snapshot_artifact_root=snapshot_root,
                output_root=output_root,
                candidate_uid=args.candidate_uid,
            )
            raw = prepare_workflow_transition(request, inputs=inputs)
            sys.stdout.buffer.write(raw)
            sys.stdout.buffer.flush()
            return 0
        if request.phase == "review-packet":
            assert snapshot_root is not None
            inputs = review_packet_prepare_inputs(
                request,
                task=task,
                artifact_root=artifact_root,
                snapshot_artifact_root=snapshot_root,
                coordinator=coordinator,
                candidate_uid=args.candidate_uid,
                offline_image=args.offline_image,
            )
            raw = prepare_workflow_transition(request, inputs=inputs)
            sys.stdout.buffer.write(raw)
            sys.stdout.buffer.flush()
            return 0
        runtime_raw = None
        if args.broker_runtime_binding is not None:
            if args.expected_broker_runtime_binding_sha256 is None:
                raise PhaseProtocolError("broker runtime binding lacks its expected digest")
            runtime_raw = _read_payload(
                args.broker_runtime_binding,
                artifact_root=artifact_root,
                expected_sha256=args.expected_broker_runtime_binding_sha256,
            )
        inputs = external_prepare_inputs(
            request,
            task=task,
            artifact_root=artifact_root,
            snapshot_artifact_root=snapshot_root,
            output_root=output_root,
            runtime_root=args.runtime_root,
            coordinator=coordinator,
            candidate_uid=args.candidate_uid,
            offline_image=args.offline_image,
            broker_image=args.broker_image,
            broker_gateway_image=args.broker_gateway_image,
            broker_ledger_identity_sha256=args.broker_ledger_identity_sha256,
            broker_runtime_binding_raw=runtime_raw,
            expected_broker_runtime_binding_sha256=(args.expected_broker_runtime_binding_sha256),
        )
        raw = prepare_workflow_transition(request, inputs=inputs)
    else:
        if args.candidate_repo is not None:
            raise PhaseProtocolError("candidate mount is forbidden during workflow finalize")
        if args.prepared_transition is None or args.execution_evidence is None:
            raise PhaseProtocolError("workflow finalize lacks prepared or execution evidence")
        if (
            args.expected_prepared_transition_sha256 is None
            or args.expected_execution_evidence_sha256 is None
        ):
            raise PhaseProtocolError("workflow finalize lacks expected evidence digests")
        prepared = _read_payload(
            args.prepared_transition,
            artifact_root=artifact_root,
            expected_sha256=args.expected_prepared_transition_sha256,
        )
        execution = _read_payload(
            args.execution_evidence,
            artifact_root=artifact_root,
            expected_sha256=args.expected_execution_evidence_sha256,
        )
        if request.phase == "snapshot":
            assert snapshot_root is not None
            inputs = snapshot_finalize_inputs(
                request,
                snapshot_artifact_root=snapshot_root,
                candidate_uid=args.candidate_uid,
            )
        elif request.phase == "red-snapshot":
            assert snapshot_root is not None
            inputs = red_snapshot_finalize_inputs(
                request,
                task=task,
                artifact_root=artifact_root,
                snapshot_artifact_root=snapshot_root,
                candidate_uid=args.candidate_uid,
            )
        elif request.phase == "review-packet":
            inputs = review_packet_finalize_inputs(request)
        elif request.phase in {"sign", "attested-judge"}:
            inputs = {}
        else:
            inputs = external_finalize_inputs(
                request,
                artifact_root=artifact_root,
                snapshot_artifact_root=snapshot_root,
                runtime_root=args.runtime_root,
                coordinator=coordinator,
                candidate_uid=args.candidate_uid,
            )
        raw = finalize_workflow_transition(
            request,
            prepared_transition=prepared,
            execution_evidence=execution,
            inputs=inputs,
        )
    sys.stdout.buffer.write(raw)
    sys.stdout.buffer.flush()
    return 0


def register_production_subcommands(
    subparsers: argparse._SubParsersAction,
    *,
    add_runtime_arguments: Callable[[argparse.ArgumentParser], None],
) -> None:
    """Register only the seven digest-chained production entrypoints."""

    for phase in PHASE_ORDER:
        parser = subparsers.add_parser(
            phase,
            help=f"validate the {phase} production phase and emit its bound action",
        )
        parser.add_argument("--task", type=Path, required=True)
        parser.add_argument("--artifact-root", type=Path, required=True)
        parser.add_argument("--expected-task-sha256", required=True)
        parser.add_argument("--phase-request", type=Path, required=True)
        parser.add_argument("--expected-phase-request-file-sha256", required=True)
        parser.add_argument("--phase-history", type=Path, action="append", default=[])
        parser.add_argument("--phase-payload", type=Path)
        parser.add_argument("--expected-phase-payload-sha256")
        parser.add_argument("--workflow-operation", choices=("prepare", "finalize"))
        parser.add_argument("--phase-output-root", type=Path)
        parser.add_argument("--snapshot-artifact-root", type=Path)
        parser.add_argument("--candidate-repo", type=Path)
        parser.add_argument("--nonce-ledger", type=Path)
        parser.add_argument("--candidate-uid", type=int)
        parser.add_argument("--offline-image")
        parser.add_argument("--broker-image")
        parser.add_argument("--broker-gateway-image")
        parser.add_argument("--broker-ledger-identity-sha256")
        parser.add_argument("--broker-egress-policy", type=Path)
        parser.add_argument("--expected-broker-egress-policy-sha256")
        parser.add_argument("--broker-pricing-policy", type=Path)
        parser.add_argument("--expected-broker-pricing-policy-sha256")
        parser.add_argument("--broker-packet-reservation-limit", type=int)
        parser.add_argument("--broker-packet-cost-limit-microusd", type=int)
        parser.add_argument("--broker-runtime-binding", type=Path)
        parser.add_argument("--expected-broker-runtime-binding-sha256")
        parser.add_argument("--prepared-transition", type=Path)
        parser.add_argument("--expected-prepared-transition-sha256")
        parser.add_argument("--execution-evidence", type=Path)
        parser.add_argument("--expected-execution-evidence-sha256")
        add_runtime_arguments(parser)
        parser.set_defaults(handler=_production_phase, production_phase=phase)
