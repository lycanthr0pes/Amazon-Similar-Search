from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from tools.ai_review.phase_protocol import EXTERNAL_PHASES
from tools.ai_review.phase_protocol import EMPTY_INITIAL_ARTIFACTS_SHA256
from tools.ai_review.phase_protocol import PHASE_ORDER
from tools.ai_review.phase_protocol import CandidateMountPolicy
from tools.ai_review.phase_protocol import CoordinatorPhaseOutput
from tools.ai_review.phase_protocol import PhaseAction
from tools.ai_review.phase_protocol import PhaseChain
from tools.ai_review.phase_protocol import PhaseProtocolError
from tools.ai_review.phase_protocol import PhaseRequest
from tools.ai_review.phase_protocol import PhaseResult
from tools.ai_review.phase_protocol import PhaseOutputArtifact
from tools.ai_review.phase_protocol import SqlitePhaseLedger
from tools.ai_review.phase_protocol import canonical_json_bytes
from tools.ai_review.phase_protocol import execute_phase
from tools.ai_review.phase_protocol import persist_phase_output
from tools.ai_review.phase_protocol import run_claimed_phase
from tools.ai_review.phase_adapters import PhaseAdapters
from tools.ai_review.phase_adapters import PhaseAdapterError
from tools.ai_review.cli import build_parser
from tools.ai_review.build_zipapp import build_trusted_zipapp
from tools.ai_review.external_launcher import LauncherTrustError
from tools.ai_review.external_launcher import _assert_bootstrap_matches_preflight
from tools.ai_review.external_launcher import _run_production_workflow
from tools.ai_review.external_launcher import _validate_phase_request_stdlib
from tools.ai_review.external_launcher import validate_production_phase_launch
from tools.ai_review.outer_workflow_runtime import WorkflowImages


_PACKET_BODY = b'{"value":"review-packet"}'
_PACKET_SHA256 = hashlib.sha256(_PACKET_BODY).hexdigest()
_PACKET_RAW = (
    b'{"packet_sha256":"' + _PACKET_SHA256.encode("ascii") + b'","value":"review-packet"}\n'
)

SHA = {
    "task": "1" * 64,
    "runtime": "2" * 64,
    "candidate": "3" * 64,
    "snapshot": "4" * 64,
    "packet": _PACKET_SHA256,
    "input": "6" * 64,
    "output": "7" * 64,
}


def request_for(
    phase: str,
    *,
    previous: PhaseResult | None = None,
    workflow_id: str = "a" * 64,
) -> PhaseRequest:
    index = PHASE_ORDER.index(phase)
    return PhaseRequest.create(
        workflow_id=workflow_id,
        phase=phase,
        sequence=index + 1,
        previous_phase_sha256=None if previous is None else previous.phase_sha256,
        task_sha256=SHA["task"],
        runtime_manifest_sha256=SHA["runtime"],
        coordinator_key_id="b" * 64,
        coordinator_public_key_sha256="c" * 64,
        candidate_sha256=SHA["candidate"],
        candidate_snapshot_sha256=(None if index == 0 else SHA["snapshot"]),
        review_packet_sha256=(SHA["packet"] if index >= PHASE_ORDER.index("broker") else None),
        input_artifacts_sha256=(
            EMPTY_INITIAL_ARTIFACTS_SHA256 if previous is None else previous.output_artifacts_sha256
        ),
    )


def launcher_arguments(
    request: PhaseRequest,
    *,
    phase_request: str = "/artifacts/request.json",
    phase_request_file_sha256: str = "d" * 64,
) -> tuple[str, ...]:
    values = [
        request.phase,
        "--task",
        "@task-container",
        "--artifact-root",
        "@artifact-root-container",
        "--expected-task-sha256",
        "@task-sha256",
        "--phase-request",
        phase_request,
        "--expected-phase-request-file-sha256",
        phase_request_file_sha256,
    ]
    for sequence in range(1, request.sequence):
        values.extend(("--phase-history", f"/artifacts/{sequence:02d}-phase-result.json"))
    values.extend(
        (
            "--phase-payload",
            "/artifacts/phase-payload.json",
            "--expected-phase-payload-sha256",
            request.input_artifacts_sha256,
            "--runtime-root",
            "/runtime",
            "--runtime-manifest",
            "@runtime-manifest-container",
            "--expected-runtime-manifest-sha256",
            "@runtime-manifest-sha256",
            "--expected-coordinator-image-digest",
            "@coordinator-image-digest",
        )
    )
    return tuple(values)


def result_for(request: PhaseRequest) -> PhaseResult:
    output = phase_output_for(request)
    return PhaseResult.create(
        request=request,
        output_artifacts_sha256=output.output_artifacts_sha256,
        candidate_snapshot_sha256=output.candidate_snapshot_sha256,
        review_packet_sha256=output.review_packet_sha256,
        external_execution_sha256=("8" * 64 if request.phase in EXTERNAL_PHASES else None),
        coordinator_output_sha256=hashlib.sha256(canonical_json_bytes(output)).hexdigest(),
        artifacts=output.phase_artifacts(),
    )


def artifact_payloads_for(phase: str) -> tuple[PhaseOutputArtifact, ...]:
    names = {
        "snapshot": ("policy", "base-snapshot", "candidate-snapshot"),
        "red-snapshot": ("red-snapshot:AT-TEST",),
        "offline": ("gate:AT-TEST", "tdd-red:AT-TEST", "tdd-green:AT-TEST"),
        "review-packet": ("review-packet",),
        "broker": ("reviewer", "adversary"),
        "sign": (
            "task",
            "policy",
            "gate:AT-TEST",
            "tdd-red:AT-TEST",
            "tdd-green:AT-TEST",
            "reviewer",
            "adversary",
        ),
        "attested-judge": ("verdict",),
    }[phase]
    values = []
    for name in sorted(names):
        if name == "candidate-snapshot":
            content = SHA["snapshot"].encode("ascii")
        elif name == "base-snapshot":
            content = ("d" * 64).encode("ascii")
        elif name.startswith("red-snapshot:"):
            content = ("e" * 64).encode("ascii")
        elif name == "review-packet":
            content = _PACKET_RAW
        else:
            content = name.encode()
        values.append(PhaseOutputArtifact.create(name, content))
    return tuple(values)


def phase_output_for(request: PhaseRequest) -> CoordinatorPhaseOutput:
    return CoordinatorPhaseOutput.create(
        request=request,
        artifacts=artifact_payloads_for(request.phase),
    )


def test_phase_models_reject_unknown_fields_and_self_hash_tampering() -> None:
    request = request_for("snapshot")
    with pytest.raises(ValidationError, match="extra_forbidden"):
        PhaseRequest.model_validate({**request.model_dump(), "unknown": True})
    with pytest.raises(ValidationError, match="request_sha256"):
        PhaseRequest.model_validate({**request.model_dump(), "request_sha256": "f" * 64})


def test_first_phase_rejects_nonempty_bootstrap_artifact_digest() -> None:
    request = request_for("snapshot")

    with pytest.raises(ValidationError, match="canonical empty artifact set"):
        PhaseRequest.create(
            **{
                **request.model_dump(mode="json", exclude={"request_sha256"}),
                "input_artifacts_sha256": "f" * 64,
            }
        )


@pytest.mark.parametrize(
    ("phase", "sequence", "previous"),
    [("snapshot", 2, None), ("red-snapshot", 2, None), ("broker", 6, "9" * 64)],
)
def test_phase_request_rejects_sequence_skips_and_missing_derived_bindings(
    phase: str,
    sequence: int,
    previous: str | None,
) -> None:
    payload = {
        "schema_version": "1.0",
        "workflow_id": "a" * 64,
        "phase": phase,
        "sequence": sequence,
        "previous_phase_sha256": previous,
        "task_sha256": SHA["task"],
        "runtime_manifest_sha256": SHA["runtime"],
        "coordinator_key_id": "b" * 64,
        "coordinator_public_key_sha256": "c" * 64,
        "candidate_sha256": SHA["candidate"],
        "candidate_snapshot_sha256": None,
        "review_packet_sha256": None,
        "input_artifacts_sha256": SHA["input"],
    }
    payload["request_sha256"] = hashlib.sha256(canonical_json_bytes(payload)).hexdigest()
    with pytest.raises(ValidationError):
        PhaseRequest.model_validate(payload)


def test_phase_chain_rejects_anchor_changes_and_skips() -> None:
    chain = PhaseChain()
    snapshot = request_for("snapshot")
    snapshot_result = result_for(snapshot)
    chain.accept(snapshot_result)

    red = request_for("red-snapshot", previous=snapshot_result)
    chain.validate_request(red)
    with pytest.raises(PhaseProtocolError, match="task SHA-256"):
        chain.validate_request(replace_model(red, task_sha256="f" * 64))
    with pytest.raises(PhaseProtocolError, match="input artifacts"):
        chain.validate_request(replace_model(red, input_artifacts_sha256="e" * 64))
    with pytest.raises(PhaseProtocolError, match="next phase"):
        chain.validate_request(
            PhaseRequest.create(
                **{
                    **red.model_dump(exclude={"request_sha256"}),
                    "phase": "offline",
                    "sequence": 3,
                }
            )
        )


def replace_model(request: PhaseRequest, **updates: object) -> PhaseRequest:
    values = request.model_dump(exclude={"request_sha256"})
    values.update(updates)
    return PhaseRequest.create(**values)


def test_packet_binding_appears_exactly_when_review_packet_finishes() -> None:
    previous: PhaseResult | None = None
    chain = PhaseChain()
    for phase in PHASE_ORDER:
        request = request_for(phase, previous=previous)
        chain.validate_request(request)
        previous = result_for(request)
        chain.accept(previous)
    assert previous is not None
    assert previous.request.phase == "attested-judge"
    assert previous.review_packet_sha256 == SHA["packet"]


@pytest.mark.parametrize(
    ("phase", "missing"),
    [
        ("snapshot", "policy"),
        ("offline", "tdd-green:AT-TEST"),
        ("broker", "adversary"),
        ("sign", "reviewer"),
    ],
)
def test_phase_result_rejects_incomplete_multi_artifact_sets(
    phase: str,
    missing: str,
) -> None:
    previous: PhaseResult | None = None
    for current in PHASE_ORDER[: PHASE_ORDER.index(phase) + 1]:
        request = request_for(current, previous=previous)
        if current != phase:
            previous = result_for(request)
            continue
        artifacts = tuple(
            item for item in phase_output_for(request).phase_artifacts() if item.name != missing
        )
        with pytest.raises(ValidationError):
            PhaseResult.create(
                request=request,
                output_artifacts_sha256=SHA["output"],
                artifacts=artifacts,
                candidate_snapshot_sha256=(
                    SHA["snapshot"] if phase == "snapshot" else request.candidate_snapshot_sha256
                ),
                review_packet_sha256=(
                    SHA["packet"] if phase == "review-packet" else request.review_packet_sha256
                ),
                external_execution_sha256=("8" * 64 if phase in EXTERNAL_PHASES else None),
                coordinator_output_sha256="9" * 64,
            )


def test_phase_result_derives_artifact_set_and_snapshot_anchor_from_typed_output() -> None:
    request = request_for("snapshot")
    output = phase_output_for(request)
    with pytest.raises(ValidationError, match="artifact digest"):
        PhaseResult.create(
            request=request,
            output_artifacts_sha256="0" * 64,
            artifacts=output.phase_artifacts(),
            candidate_snapshot_sha256=output.candidate_snapshot_sha256,
            review_packet_sha256=None,
            external_execution_sha256=None,
            coordinator_output_sha256=hashlib.sha256(canonical_json_bytes(output)).hexdigest(),
        )
    with pytest.raises(ValidationError, match="snapshot anchor"):
        PhaseResult.create(
            request=request,
            output_artifacts_sha256=output.output_artifacts_sha256,
            artifacts=output.phase_artifacts(),
            candidate_snapshot_sha256="f" * 64,
            review_packet_sha256=None,
            external_execution_sha256=None,
            coordinator_output_sha256=hashlib.sha256(canonical_json_bytes(output)).hexdigest(),
        )


def test_typed_coordinator_output_rejects_semantic_content_tampering() -> None:
    request = request_for("snapshot")
    output = phase_output_for(request)
    forged = output.model_dump(mode="json")
    candidate = next(
        artifact for artifact in forged["artifacts"] if artifact["name"] == "candidate-snapshot"
    )
    candidate["content_base64"] = PhaseOutputArtifact.create(
        "candidate-snapshot",
        ("f" * 64).encode(),
    ).content_base64
    with pytest.raises(ValidationError):
        CoordinatorPhaseOutput.model_validate(forged)


def test_mount_and_external_action_policies_are_closed_sets() -> None:
    policy = CandidateMountPolicy()
    assert policy.allowed("snapshot") is True
    assert all(policy.allowed(phase) is False for phase in PHASE_ORDER[1:])
    assert EXTERNAL_PHASES == frozenset({"offline", "broker"})


def test_execute_phase_calls_coordinator_before_and_after_external_runner() -> None:
    request = request_for(
        "offline",
        previous=result_for(
            request_for("red-snapshot", previous=result_for(request_for("snapshot")))
        ),
    )
    calls: list[tuple[str, object]] = []
    payload = b'{"offline":"request"}\n'
    raw_evidence = b'{"offline":"evidence"}\n'
    verified = canonical_json_bytes(phase_output_for(request))

    def prepare(value: PhaseRequest, *, mount_candidate: bool) -> tuple[PhaseAction, bytes]:
        calls.append(("prepare", mount_candidate))
        return PhaseAction.create(
            request=value,
            external_kind="offline",
            payload_sha256=hashlib.sha256(payload).hexdigest(),
        ), payload

    def run(action: PhaseAction, raw: bytes) -> bytes:
        calls.append(("external", action.external_kind))
        assert raw == payload
        return raw_evidence

    def finalize(action: PhaseAction, evidence: bytes) -> bytes:
        calls.append(("finalize", action.action_sha256))
        assert evidence == raw_evidence
        return verified

    result = execute_phase(
        request,
        coordinator_prepare=prepare,
        coordinator_finalize=finalize,
        offline_execute=run,
        broker_execute=lambda *_args: pytest.fail("broker must not run"),
    )

    assert calls[0] == ("prepare", False)
    assert calls[1] == ("external", "offline")
    assert calls[2][0] == "finalize"
    assert result.verified_output == verified
    assert result.external_evidence_sha256 == hashlib.sha256(raw_evidence).hexdigest()


def test_execute_phase_never_calls_external_runner_for_coordinator_only_phase() -> None:
    request = request_for("snapshot")
    payload = b'{"snapshots":[]}\n'
    verified = canonical_json_bytes(phase_output_for(request))

    result = execute_phase(
        request,
        coordinator_prepare=lambda value, *, mount_candidate: (
            PhaseAction.create(
                request=value,
                external_kind="none",
                payload_sha256=hashlib.sha256(payload).hexdigest(),
            ),
            payload,
        ),
        coordinator_finalize=lambda _action, _evidence: verified,
        offline_execute=lambda *_args: pytest.fail("offline must not run"),
        broker_execute=lambda *_args: pytest.fail("broker must not run"),
    )

    assert result.verified_output == verified
    assert result.external_evidence_sha256 is None


def test_ledger_consumes_claim_before_execution_and_rejects_reuse(tmp_path: Path) -> None:
    ledger_root = tmp_path / "ledger"
    ledger_root.mkdir(mode=0o700)
    ledger = SqlitePhaseLedger(ledger_root / "phases.sqlite3", candidate_uid=other_uid())
    request = request_for("snapshot")
    ledger.claim(request)
    with pytest.raises(PhaseProtocolError, match="already claimed"):
        ledger.claim(request)
    result = result_for(request)
    ledger.commit(result)
    with pytest.raises(PhaseProtocolError, match="already claimed"):
        ledger.claim(request)


def test_phase_output_is_exclusive_bounded_and_digest_checked(tmp_path: Path) -> None:
    output = tmp_path / "phase.json"
    raw = b'{"ok":true}\n'
    digest = persist_phase_output(output, raw, expected_sha256=hashlib.sha256(raw).hexdigest())
    assert digest == hashlib.sha256(raw).hexdigest()
    assert output.read_bytes() == raw
    with pytest.raises(PhaseProtocolError, match="new exclusive"):
        persist_phase_output(output, raw, expected_sha256=digest)
    with pytest.raises(PhaseProtocolError, match="digest"):
        persist_phase_output(tmp_path / "bad.json", raw, expected_sha256="0" * 64)
    with pytest.raises(PhaseProtocolError, match="byte limit"):
        persist_phase_output(
            tmp_path / "large.json",
            b"x" * 1025,
            expected_sha256=hashlib.sha256(b"x" * 1025).hexdigest(),
            max_bytes=1024,
        )


def test_claimed_phase_is_persisted_and_committed_only_after_finalize(tmp_path: Path) -> None:
    ledger_root = tmp_path / "ledger"
    ledger_root.mkdir(mode=0o700)
    output_root = tmp_path / "output"
    output_root.mkdir(mode=0o700)
    ledger = SqlitePhaseLedger(ledger_root / "phases.sqlite3", candidate_uid=other_uid())
    request = request_for("snapshot")
    payload = b'{"snapshot":"prepared"}\n'
    verified = canonical_json_bytes(phase_output_for(request))

    result = run_claimed_phase(
        request,
        ledger=ledger,
        output=output_root / "snapshot.json",
        coordinator_prepare=lambda value, *, mount_candidate: (
            PhaseAction.create(
                request=value,
                external_kind="none",
                payload_sha256=hashlib.sha256(payload).hexdigest(),
            ),
            payload,
        ),
        coordinator_finalize=lambda _action, _evidence: verified,
        offline_execute=lambda *_args: pytest.fail("offline must not run"),
        broker_execute=lambda *_args: pytest.fail("broker must not run"),
    )

    assert result.output_artifacts_sha256 == phase_output_for(request).output_artifacts_sha256
    assert result.candidate_snapshot_sha256 == SHA["snapshot"]
    assert (
        PhaseResult.model_validate_json(output_root.joinpath("snapshot.json").read_bytes())
        == result
    )
    assert (output_root / "coordinator-output.json").read_bytes() == verified
    assert (
        hashlib.sha256(output_root.joinpath("artifact-manifest.json").read_bytes()).hexdigest()
        == result.output_artifacts_sha256
    )
    red = request_for("red-snapshot", previous=result)
    ledger.claim(red)


def test_external_phase_persists_prepared_and_raw_evidence_for_later_judge(
    tmp_path: Path,
) -> None:
    ledger_root = tmp_path / "external-ledger"
    ledger_root.mkdir(mode=0o700)
    output_root = tmp_path / "external-output"
    output_root.mkdir(mode=0o700)
    ledger = SqlitePhaseLedger(ledger_root / "phases.sqlite3", candidate_uid=other_uid())
    snapshot = request_for("snapshot")
    snapshot_result = result_for(snapshot)
    ledger.claim(snapshot)
    ledger.commit(snapshot_result)
    red = request_for("red-snapshot", previous=snapshot_result)
    red_result = result_for(red)
    ledger.claim(red)
    ledger.commit(red_result)
    request = request_for("offline", previous=red_result)
    prepared = b'{"prepared":"offline"}\n'
    external = b'{"raw":"offline-evidence"}\n'
    verified = canonical_json_bytes(phase_output_for(request))

    result = run_claimed_phase(
        request,
        ledger=ledger,
        output=output_root / "phase-result.json",
        coordinator_prepare=lambda value, *, mount_candidate: (
            PhaseAction.create(
                request=value,
                external_kind="offline",
                payload_sha256=hashlib.sha256(prepared).hexdigest(),
            ),
            prepared,
        ),
        coordinator_finalize=lambda _action, evidence: (
            verified if evidence == external else pytest.fail("wrong external evidence")
        ),
        offline_execute=lambda _action, payload: (
            external if payload == prepared else pytest.fail("wrong prepared payload")
        ),
        broker_execute=lambda *_args: pytest.fail("broker must not run"),
    )

    assert (output_root / "prepared-payload.json").read_bytes() == prepared
    assert (output_root / "external-evidence.json").read_bytes() == external
    assert result.external_execution_sha256 == hashlib.sha256(external).hexdigest()


def test_interrupted_claim_is_not_retried_in_place(tmp_path: Path) -> None:
    ledger_root = tmp_path / "ledger"
    ledger_root.mkdir(mode=0o700)
    output_root = tmp_path / "output"
    output_root.mkdir(mode=0o700)
    ledger = SqlitePhaseLedger(ledger_root / "phases.sqlite3", candidate_uid=other_uid())
    request = request_for("snapshot")
    payload = b'{"snapshot":"prepared"}\n'

    with pytest.raises(RuntimeError, match="crashed"):
        run_claimed_phase(
            request,
            ledger=ledger,
            output=output_root / "snapshot.json",
            coordinator_prepare=lambda value, *, mount_candidate: (
                PhaseAction.create(
                    request=value,
                    external_kind="none",
                    payload_sha256=hashlib.sha256(payload).hexdigest(),
                ),
                payload,
            ),
            coordinator_finalize=lambda *_args: (_ for _ in ()).throw(RuntimeError("crashed")),
            offline_execute=lambda *_args: b"unused",
            broker_execute=lambda *_args: b"unused",
        )
    with pytest.raises(PhaseProtocolError, match="already claimed"):
        ledger.claim(request)


def other_uid() -> int:
    return 65_534 if os.geteuid() != 65_534 else 65_533


def test_phase_request_canonical_json_round_trip() -> None:
    request = request_for("snapshot")
    encoded = canonical_json_bytes(request)
    assert PhaseRequest.model_validate_json(encoded) == request
    assert json.loads(encoded)["request_sha256"] == request.request_sha256


def test_phase_adapters_expose_every_canonical_public_api() -> None:
    from tools.ai_review.broker_outer_executor import execute_prepared_broker_outer

    adapters = PhaseAdapters.from_public_apis()
    assert tuple(adapters.names()) == PHASE_ORDER
    assert adapters.execution_domain("offline") == "outer"
    assert adapters.execution_domain("broker") == "outer"
    assert adapters.broker is execute_prepared_broker_outer
    assert all(
        adapters.execution_domain(phase) == "coordinator"
        for phase in PHASE_ORDER
        if phase not in EXTERNAL_PHASES
    )


def test_adapter_domains_cannot_cross_the_socket_boundary() -> None:
    calls: list[str] = []
    adapters = PhaseAdapters(
        snapshot=lambda **_kwargs: calls.append("snapshot"),
        red_snapshot=lambda **_kwargs: calls.append("red-snapshot"),
        offline=lambda **_kwargs: calls.append("offline"),
        review_packet=lambda **_kwargs: calls.append("review-packet"),
        broker=lambda **_kwargs: calls.append("broker"),
        sign=lambda **_kwargs: calls.append("sign"),
        attested_judge=lambda **_kwargs: calls.append("attested-judge"),
    )
    adapters.invoke_coordinator("snapshot")
    adapters.invoke_outer("offline")
    with pytest.raises(PhaseAdapterError, match="outer-only"):
        adapters.invoke_coordinator("broker")
    with pytest.raises(PhaseAdapterError, match="coordinator-only"):
        adapters.invoke_outer("attested-judge")
    assert calls == ["snapshot", "offline"]


def test_broker_adapter_rejects_candidate_or_mount_parameters_before_call() -> None:
    called = False

    def broker(**_kwargs):
        nonlocal called
        called = True

    adapters = PhaseAdapters(
        snapshot=lambda **_kwargs: None,
        red_snapshot=lambda **_kwargs: None,
        offline=lambda **_kwargs: None,
        review_packet=lambda **_kwargs: None,
        broker=broker,
        sign=lambda **_kwargs: None,
        attested_judge=lambda **_kwargs: None,
    )
    with pytest.raises(PhaseAdapterError, match="candidate filesystem"):
        adapters.invoke_outer("broker", candidate_repo=Path("/candidate"))
    with pytest.raises(PhaseAdapterError, match="candidate filesystem"):
        adapters.invoke_outer("broker", mounts=("/candidate",))
    assert called is False


@pytest.mark.parametrize("phase", PHASE_ORDER)
def test_cli_exposes_each_production_phase_as_a_canonical_entry(phase: str) -> None:
    parser = build_parser()
    args = parser.parse_args(
        [
            phase,
            "--task",
            "/runtime/task.json",
            "--artifact-root",
            "/artifacts",
            "--expected-task-sha256",
            SHA["task"],
            "--phase-request",
            "/artifacts/request.json",
            "--expected-phase-request-file-sha256",
            "d" * 64,
            "--phase-payload",
            "/artifacts/payload.json",
            "--expected-phase-payload-sha256",
            SHA["input"],
            "--runtime-root",
            "/runtime",
            "--runtime-manifest",
            "/runtime/runtime-manifest.json",
            "--expected-runtime-manifest-sha256",
            SHA["runtime"],
            "--expected-coordinator-image-digest",
            "sha256:" + "9" * 64,
        ]
    )
    assert args.production_phase == phase
    assert args.handler.__module__ == "tools.ai_review.production_cli"


def test_cli_accepts_outer_owned_workflow_operation_without_legacy_payload() -> None:
    args = build_parser().parse_args(
        [
            "offline",
            "--workflow-operation",
            "prepare",
            "--task",
            "/runtime/task.json",
            "--artifact-root",
            "/artifacts",
            "--expected-task-sha256",
            SHA["task"],
            "--phase-request",
            "/artifacts/phase-request.json",
            "--expected-phase-request-file-sha256",
            "d" * 64,
            "--phase-output-root",
            "/output",
            "--candidate-uid",
            "65534",
            "--offline-image",
            "example.invalid/offline@sha256:" + "1" * 64,
            "--broker-image",
            "example.invalid/broker@sha256:" + "2" * 64,
            "--broker-gateway-image",
            "example.invalid/gateway@sha256:" + "3" * 64,
            "--runtime-root",
            "/runtime",
            "--runtime-manifest",
            "/runtime/runtime-manifest.json",
            "--expected-runtime-manifest-sha256",
            SHA["runtime"],
            "--expected-coordinator-image-digest",
            "sha256:" + "9" * 64,
        ]
    )
    assert args.workflow_operation == "prepare"
    assert args.phase_payload is None
    assert args.production_phase == "offline"


def test_legacy_judge_and_codex_are_not_production_phase_entries() -> None:
    parser = build_parser()
    judge_args = parser.parse_args(
        [
            "judge",
            "--repo",
            "/candidate",
            "--task",
            "/runtime/task.json",
            "--artifact-root",
            "/artifacts",
            "--expected-task-sha256",
            SHA["task"],
            "--policy",
            "/artifacts/policy.json",
            "--review",
            "/artifacts/review.json",
            "--gate",
            "/artifacts/gate.json",
            "--tdd-evidence",
            "/artifacts/tdd.json",
        ]
    )
    codex_args = parser.parse_args(
        [
            "codex",
            "--candidate-repo",
            "/candidate",
            "--expected-harness-sha256",
            SHA["task"],
            "--coordinator-dir",
            "/artifacts",
            "--output-schema",
            "/artifacts/schema.json",
            "--output",
            "/artifacts/output.json",
            "--prompt",
            "review",
        ]
    )
    assert not hasattr(judge_args, "production_phase")
    assert not hasattr(codex_args, "production_phase")


def test_external_launcher_mounts_candidate_only_for_snapshot() -> None:
    snapshot = request_for("snapshot")
    assert (
        validate_production_phase_launch(
            snapshot,
            launcher_arguments(snapshot),
            candidate_repo=Path("/candidate"),
            container_phase_request="/artifacts/request.json",
            expected_phase_request_file_sha256="d" * 64,
        )
        is True
    )
    red = request_for("red-snapshot", previous=result_for(snapshot))
    assert (
        validate_production_phase_launch(
            red,
            launcher_arguments(red),
            candidate_repo=None,
            container_phase_request="/artifacts/request.json",
            expected_phase_request_file_sha256="d" * 64,
        )
        is False
    )
    with pytest.raises(LauncherTrustError, match="forbidden"):
        validate_production_phase_launch(
            red,
            launcher_arguments(red),
            candidate_repo=Path("/candidate"),
            container_phase_request="/artifacts/request.json",
            expected_phase_request_file_sha256="d" * 64,
        )


@pytest.mark.parametrize("legacy", ["judge", "codex"])
def test_external_launcher_rejects_legacy_commands_in_production_protocol(legacy: str) -> None:
    with pytest.raises(LauncherTrustError, match="does not match"):
        validate_production_phase_launch(
            request_for("snapshot"),
            (legacy,),
            candidate_repo=Path("/candidate"),
            container_phase_request="/artifacts/request.json",
            expected_phase_request_file_sha256="d" * 64,
        )


def test_external_launcher_rejects_a_different_inner_phase_request() -> None:
    request = request_for("snapshot")
    with pytest.raises(LauncherTrustError, match="phase-request"):
        validate_production_phase_launch(
            request,
            launcher_arguments(request, phase_request="/artifacts/other.json"),
            candidate_repo=Path("/candidate"),
            container_phase_request="/artifacts/request.json",
            expected_phase_request_file_sha256="d" * 64,
        )


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("--phase-request=", "/artifacts/forged.json"),
        ("--phase-request", "/artifacts/forged.json"),
        ("--expected-phase-request-file-sha256=", "e" * 64),
        ("--expected-phase-request-file-sha256", "e" * 64),
    ],
)
def test_external_launcher_rejects_duplicate_or_assigned_inner_bindings(
    name: str,
    value: str,
) -> None:
    request = request_for("snapshot")
    arguments = list(launcher_arguments(request))
    if name.endswith("="):
        arguments.append(name + value)
    else:
        arguments.extend((name, value))
    with pytest.raises(LauncherTrustError, match="coordinator command"):
        validate_production_phase_launch(
            request,
            tuple(arguments),
            candidate_repo=Path("/candidate"),
            container_phase_request="/artifacts/request.json",
            expected_phase_request_file_sha256="d" * 64,
        )


def test_external_launcher_binds_running_python_to_preflight_inode_and_digest() -> None:
    python = Path(sys.executable).resolve(strict=True)
    metadata = python.stat()
    expected = SimpleNamespace(
        path=python,
        device=metadata.st_dev,
        inode=metadata.st_ino,
        size=metadata.st_size,
        sha256=hashlib.sha256(python.read_bytes()).hexdigest(),
    )
    evidence = SimpleNamespace(python=expected)
    _assert_bootstrap_matches_preflight(evidence)
    forged = SimpleNamespace(python=SimpleNamespace(**{**vars(expected), "inode": 0}))
    with pytest.raises(LauncherTrustError, match="manifest Python"):
        _assert_bootstrap_matches_preflight(forged)


def test_stdlib_outer_phase_check_matches_strict_model_and_rejects_unknown() -> None:
    request = request_for("snapshot")
    assert _validate_phase_request_stdlib(canonical_json_bytes(request))["phase"] == "snapshot"
    forged = request.model_dump(mode="json")
    forged["unknown"] = True
    with pytest.raises(LauncherTrustError, match="unknown"):
        _validate_phase_request_stdlib(canonical_json_bytes(forged))


def test_external_launcher_phase_validation_does_not_import_pydantic(tmp_path: Path) -> None:
    launcher = Path(__file__).parents[1] / "tools" / "ai_review" / "external_launcher.py"
    raw = canonical_json_bytes(request_for("snapshot"))
    script = (
        "import importlib.util,sys;"
        "spec=importlib.util.spec_from_file_location('outer',sys.argv[1]);"
        "module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);"
        "module._validate_phase_request_stdlib(bytes.fromhex(sys.argv[2]));"
        "assert 'pydantic' not in sys.modules"
    )
    result = subprocess.run(
        [sys.executable, "-I", "-c", script, str(launcher), raw.hex()],
        cwd=tmp_path,
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 0, result.stderr


def test_verified_outer_coordinator_loader_remains_stdlib_only(tmp_path: Path) -> None:
    launcher = Path(__file__).parents[1] / "tools" / "ai_review" / "external_launcher.py"
    harness = tmp_path / "harness.pyz"
    build_trusted_zipapp(Path(__file__).parents[1], harness)
    script = (
        "import importlib.util,sys;"
        "spec=importlib.util.spec_from_file_location('outer',sys.argv[1]);"
        "module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);"
        "Evidence=type('Evidence',(),{'fd_path':lambda self,name:sys.argv[2]});"
        "module._load_verified_harness_module(Evidence(),'tools.ai_review.coordinator_launcher');"
        "module._load_verified_harness_module(Evidence(),'tools.ai_review.offline_outer_executor');"
        "assert 'pydantic' not in sys.modules;"
        "assert 'cryptography' not in sys.modules"
    )
    result = subprocess.run(
        [sys.executable, "-I", "-c", script, str(launcher), str(harness)],
        cwd=tmp_path,
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 0, result.stderr


def test_outer_bootstrap_requires_no_site_and_accepts_hermetic_i_s(tmp_path: Path) -> None:
    launcher = Path(__file__).parents[1] / "tools" / "ai_review" / "external_launcher.py"
    script = (
        "import importlib.util,sys;"
        "spec=importlib.util.spec_from_file_location('outer',sys.argv[1]);"
        "module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);"
        "module._assert_hermetic_python()"
    )
    bootstrap_python = "/usr/bin/python3"
    accepted = subprocess.run(
        [bootstrap_python, "-I", "-S", "-c", script, str(launcher)],
        cwd=tmp_path,
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert accepted.returncode == 0, accepted.stderr
    rejected = subprocess.run(
        [bootstrap_python, "-I", "-c", script, str(launcher)],
        cwd=tmp_path,
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert rejected.returncode != 0
    assert "no-site (-S)" in rejected.stderr


def test_external_launcher_workflow_entry_calls_only_fixed_public_outer_apis(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    import tools.ai_review.external_launcher as launcher

    credential_paths = []
    credential_fds = []
    for role in ("reviewer", "adversary"):
        path = tmp_path / f"{role}.credential"
        path.write_text(f"sk-test-{role}\n", encoding="ascii")
        path.chmod(0o600)
        credential_paths.append(path)
        credential_fds.append(os.open(path, os.O_RDONLY))
    broker_parent = tmp_path / "broker-ledger"
    broker_parent.mkdir(mode=0o700)
    nonce_ledger_root = tmp_path / "nonce-ledger"
    nonce_ledger_root.mkdir(mode=0o700)
    recorded: dict[str, object] = {}
    backend = SimpleNamespace(executable=tmp_path / "podman")
    runtime_binding = b'{"measured":"runtime"}\n'

    def execute_coordinator(**kwargs):
        recorded["coordinator"] = kwargs
        return SimpleNamespace(stdout=b'{"coordinator":"ok"}\n')

    coordinator_module = SimpleNamespace(
        detect_container_backend=lambda *, candidate_uid: backend,
        _validate_backend=lambda value, *, candidate_uid: value,
        execute_coordinator=execute_coordinator,
    )

    def run_workflow(_initial_request, **kwargs):
        call = SimpleNamespace(
            phase="snapshot",
            artifact_root=tmp_path,
            candidate_repo=tmp_path / "candidate",
            command=("snapshot", "--workflow-operation", "prepare"),
            output_root=tmp_path / "phase-output",
            signing_key=None,
            nonce_ledger_root=None,
            snapshot_artifact_root=None,
        )
        call.output_root.mkdir(mode=0o700)
        assert kwargs["coordinator_execute"](call) == b'{"coordinator":"ok"}\n'
        assert kwargs["offline_execute"](b"offline descriptor", tmp_path) == b"offline raw"
        assert kwargs["broker_execute"](b"broker descriptor") == b"broker raw"
        recorded["workflow"] = kwargs
        return SimpleNamespace(transitions=(SimpleNamespace(result={"phase_sha256": "f" * 64}),))

    workflow_module = SimpleNamespace(
        IMPLEMENTED_COORDINATOR_WORKFLOW_PHASES=PHASE_ORDER,
        PHASE_ORDER=PHASE_ORDER,
        WorkflowImages=WorkflowImages,
        run_production_workflow=run_workflow,
    )
    offline_module = SimpleNamespace(
        execute_prepared_offline_outer=lambda payload, **kwargs: (
            recorded.update(offline=(payload, kwargs)) or b"offline raw"
        )
    )
    broker_module = SimpleNamespace(
        measure_broker_outer_runtime=lambda executable, *, candidate_uid: (
            recorded.update(runtime_measurement=(executable, candidate_uid)) or runtime_binding
        ),
        prepare_broker_outer_ledger=lambda path, *, candidate_uid: "e" * 64,
        execute_prepared_broker_outer=lambda payload, **kwargs: (
            recorded.update(broker=(payload, kwargs)) or b"broker raw"
        ),
    )
    modules = {
        "tools.ai_review.coordinator_launcher": coordinator_module,
        "tools.ai_review.outer_workflow_runtime": workflow_module,
        "tools.ai_review.offline_outer_executor": offline_module,
        "tools.ai_review.broker_outer_executor": broker_module,
    }
    monkeypatch.setattr(
        launcher,
        "_load_verified_harness_module",
        lambda _evidence, name: modules[name],
    )
    evidence = SimpleNamespace(
        candidate_uid=65_534 if os.geteuid() != 65_534 else 65_533,
        coordinator_image_digest="sha256:" + "1" * 64,
        offline_runner_image_digest="sha256:" + "2" * 64,
        broker_image_digest="sha256:" + "3" * 64,
        broker_gateway_image_digest="sha256:" + "4" * 64,
    )
    args = SimpleNamespace(
        coordinator_image="example.invalid/coordinator@sha256:" + "1" * 64,
        offline_image="example.invalid/offline@sha256:" + "2" * 64,
        broker_image="example.invalid/broker@sha256:" + "3" * 64,
        broker_gateway_image="example.invalid/gateway@sha256:" + "4" * 64,
        artifact_root=tmp_path,
        phase_request=tmp_path / "phase-request.json",
        phase_output_root=tmp_path / "workflow-output",
        candidate_repo=tmp_path / "candidate",
        signing_key=tmp_path / "private.pem",
        broker_ledger=broker_parent / "ledger.sqlite3",
        attestation_nonce_ledger_root=nonce_ledger_root,
        reviewer_credential_fd=credential_fds[0],
        adversary_credential_fd=credential_fds[1],
        timeout_seconds=300,
    )
    try:
        assert _run_production_workflow(args, evidence) == 0
    finally:
        for descriptor in credential_fds:
            os.close(descriptor)

    assert recorded["coordinator"]["mount_candidate"] is True
    broker_kwargs = recorded["broker"][1]
    assert set(broker_kwargs["credentials"]) == {"reviewer", "adversary"}
    assert recorded["workflow"]["broker_runtime_binding"] == runtime_binding
    assert recorded["runtime_measurement"][0] == backend.executable
    assert all("sk-test" not in repr(value) for value in recorded["coordinator"].values())
    assert json.loads(capsys.readouterr().out) == {
        "final_phase_sha256": "f" * 64,
        "human_approval_required": True,
        "phase_count": 1,
        "status": "complete",
    }


def test_external_launcher_disables_incomplete_workflow_before_loading_executors(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import tools.ai_review.external_launcher as launcher
    import tools.ai_review.outer_workflow_runtime as workflow_runtime

    loaded: list[str] = []

    def load_module(_evidence, name: str):
        loaded.append(name)
        if name == "tools.ai_review.coordinator_launcher":
            return SimpleNamespace()
        if name == "tools.ai_review.outer_workflow_runtime":
            return SimpleNamespace(
                IMPLEMENTED_COORDINATOR_WORKFLOW_PHASES=tuple(workflow_runtime.PHASE_ORDER[:5]),
                PHASE_ORDER=workflow_runtime.PHASE_ORDER,
            )
        pytest.fail("external executors must not load before the seven-phase capability gate")

    monkeypatch.setattr(launcher, "_load_verified_harness_module", load_module)
    args = SimpleNamespace(
        coordinator_image="coordinator",
        offline_image="offline",
        broker_image="broker",
        broker_gateway_image="gateway",
        artifact_root=tmp_path,
        phase_request=tmp_path / "request.json",
        phase_output_root=tmp_path / "output",
        candidate_repo=tmp_path / "candidate",
        signing_key=tmp_path / "key",
        broker_ledger=tmp_path / "ledger",
        attestation_nonce_ledger_root=tmp_path / "nonces",
        reviewer_credential_fd=3,
        adversary_credential_fd=4,
        timeout_seconds=300,
    )
    with pytest.raises(launcher.LauncherTrustError, match="all seven"):
        launcher._run_production_workflow(args, SimpleNamespace(candidate_uid=65_534))
    assert loaded == [
        "tools.ai_review.coordinator_launcher",
        "tools.ai_review.outer_workflow_runtime",
    ]
