from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from tools.ai_review.coordinator_phase_protocol import finalize_transition_bytes
from tools.ai_review.coordinator_phase_protocol import prepare_transition_bytes
from tools.ai_review.outer_workflow_runtime import OuterWorkflowRuntimeError
from tools.ai_review.outer_workflow_runtime import WorkflowImages
from tools.ai_review.outer_workflow_runtime import run_production_workflow
from tools.ai_review.phase_protocol import CoordinatorPhaseOutput
from tools.ai_review.phase_protocol import EMPTY_INITIAL_ARTIFACTS_SHA256
from tools.ai_review.phase_protocol import PhaseAction
from tools.ai_review.phase_protocol import PhaseRequest
from tools.ai_review.phase_protocol import canonical_json_bytes
from tests.test_ai_review_phase_protocol import artifact_payloads_for


def _images() -> WorkflowImages:
    return WorkflowImages(
        coordinator="example.invalid/coordinator@sha256:" + "1" * 64,
        coordinator_digest="sha256:" + "1" * 64,
        offline="example.invalid/offline@sha256:" + "2" * 64,
        offline_digest="sha256:" + "2" * 64,
        broker="example.invalid/broker@sha256:" + "3" * 64,
        broker_digest="sha256:" + "3" * 64,
        broker_gateway="example.invalid/gateway@sha256:" + "4" * 64,
        broker_gateway_digest="sha256:" + "4" * 64,
    )


def _initial_request() -> PhaseRequest:
    return PhaseRequest.create(
        workflow_id="5" * 64,
        phase="snapshot",
        sequence=1,
        previous_phase_sha256=None,
        task_sha256="6" * 64,
        runtime_manifest_sha256="7" * 64,
        coordinator_key_id="8" * 64,
        coordinator_public_key_sha256="9" * 64,
        candidate_sha256="a" * 64,
        candidate_snapshot_sha256=None,
        review_packet_sha256=None,
        input_artifacts_sha256=EMPTY_INITIAL_ARTIFACTS_SHA256,
    )


def _broker_runtime_binding() -> bytes:
    security = {
        "name": "podman",
        "rootless": True,
        "seccomp_profile": "runtime/default",
        "user_namespace": True,
    }
    return canonical_json_bytes(
        {
            **security,
            "environment_sha256": "d" * 64,
            "executable_sha256": "e" * 64,
            "security_evidence_sha256": hashlib.sha256(canonical_json_bytes(security)).hexdigest(),
        }
    )


def _protected_inputs(tmp_path: Path) -> tuple[Path, Path, Path, Path, Path]:
    initial = tmp_path / "initial"
    initial.mkdir(mode=0o700)
    request = initial / "phase-request.json"
    request.write_bytes(canonical_json_bytes(_initial_request()))
    request.chmod(0o444)
    initial.chmod(0o555)
    output = tmp_path / "workflow-output"
    output.mkdir(mode=0o700)
    candidate = tmp_path / "candidate.git"
    candidate.mkdir(mode=0o555)
    key = tmp_path / "coordinator-private.pem"
    key.write_bytes(b"test-only-private-key\n")
    key.chmod(0o400)
    nonce_ledger_root = tmp_path / "nonce-ledger"
    nonce_ledger_root.mkdir(mode=0o700)
    return initial, output, candidate, key, nonce_ledger_root


def test_outer_runtime_commits_real_transition_envelopes_and_exact_mount_policy(
    tmp_path: Path,
) -> None:
    initial, output, candidate, key, nonce_ledger_root = _protected_inputs(tmp_path)
    calls = []
    prepared: dict[str, tuple[PhaseRequest, PhaseAction, bytes]] = {}
    external_calls: list[str] = []

    def coordinator(call) -> bytes:
        calls.append(call)
        assert call.command[0] == call.phase
        assert call.command[1:3] == ("--workflow-operation", call.operation)
        assert all("docker.sock" not in argument for argument in call.command)
        assert (call.candidate_repo is not None) == (
            call.phase == "snapshot" and call.operation == "prepare"
        )
        assert (call.signing_key is not None) == (
            call.phase == "sign" and call.operation == "prepare"
        )
        request = PhaseRequest.model_validate_json(
            (call.artifact_root / "phase-request.json").read_bytes()
        )
        marker = call.output_root / f"{call.operation}.txt"
        marker.write_text(call.phase + "\n", encoding="utf-8")
        if call.operation == "prepare":
            if call.phase == "snapshot":
                for digest in ("d" * 64, "4" * 64):
                    tree = call.output_root / "snapshots" / digest / "tree"
                    tree.mkdir(mode=0o700, parents=True)
                    (tree / "AGENTS.md").write_text("snapshot content\n", encoding="utf-8")
            elif call.phase == "red-snapshot":
                tree = call.output_root / "red-snapshots" / ("e" * 64) / "tree"
                tree.mkdir(mode=0o700, parents=True)
                (tree / "AGENTS.md").write_text("RED snapshot content\n", encoding="utf-8")
            payload = canonical_json_bytes(
                {"phase": call.phase, "request_sha256": request.request_sha256}
            )
            kind = (
                "offline"
                if call.phase == "offline"
                else "broker"
                if call.phase == "broker"
                else "none"
            )
            action = PhaseAction.create(
                request=request,
                external_kind=kind,
                payload_sha256=hashlib.sha256(payload).hexdigest(),
            )
            prepared[call.phase] = (request, action, payload)
            return prepare_transition_bytes(request, action, payload)
        stored_request, action, payload = prepared[call.phase]
        assert stored_request == request
        evidence = (call.artifact_root / "current-execution-evidence.json").read_bytes()
        phase_output = CoordinatorPhaseOutput.create(
            request=request,
            artifacts=artifact_payloads_for(call.phase),
        )
        return finalize_transition_bytes(request, action, payload, evidence, phase_output)

    def offline(payload: bytes, artifact_root: Path) -> bytes:
        external_calls.append("offline")
        assert artifact_root.name == "snapshot-artifacts"
        return canonical_json_bytes(
            {"kind": "offline", "payload_sha256": hashlib.sha256(payload).hexdigest()}
        )

    def broker(payload: bytes) -> bytes:
        external_calls.append("broker")
        return canonical_json_bytes(
            {"kind": "broker", "payload_sha256": hashlib.sha256(payload).hexdigest()}
        )

    result = run_production_workflow(
        initial / "phase-request.json",
        initial_artifact_root=initial,
        output_root=output,
        candidate_repo=candidate,
        signing_key=key,
        nonce_ledger_root=nonce_ledger_root,
        candidate_uid=65_534 if os.geteuid() != 65_534 else 65_533,
        images=_images(),
        broker_ledger_identity_sha256="c" * 64,
        broker_runtime_binding=_broker_runtime_binding(),
        coordinator_execute=coordinator,
        offline_execute=offline,
        broker_execute=broker,
    )

    assert len(result.transitions) == 7
    assert external_calls == ["offline", "broker"]
    assert [(call.phase, call.operation) for call in calls] == [
        (phase, operation)
        for phase in (
            "snapshot",
            "red-snapshot",
            "offline",
            "review-packet",
            "broker",
            "sign",
            "attested-judge",
        )
        for operation in ("prepare", "finalize")
    ]
    final = output / "07-attested-judge" / "committed"
    assert len(list(final.rglob("phase-result.json"))) == 7
    assert len(list(final.rglob("external-evidence.json"))) == 2
    runtime_bindings = list(final.rglob("broker-runtime-binding.json"))
    assert len(runtime_bindings) == 1
    assert runtime_bindings[0].read_bytes() == _broker_runtime_binding()
    broker_calls = [call for call in calls if call.phase == "broker"]
    assert all("--broker-runtime-binding" in call.command for call in broker_calls)
    assert all(
        (
            call.command[call.command.index("--expected-broker-runtime-binding-sha256") + 1]
            == hashlib.sha256(_broker_runtime_binding()).hexdigest()
        )
        for call in broker_calls
    )
    assert calls[0].snapshot_artifact_root is None
    assert all(call.snapshot_artifact_root == output / "snapshot-artifacts" for call in calls[1:])
    snapshot_prepare = calls[0]
    assert (
        snapshot_prepare.command[snapshot_prepare.command.index("--candidate-repo") + 1]
        == "/candidate"
    )
    assert all("--candidate-repo" not in call.command for call in calls[1:])
    judge_prepare = next(
        call for call in calls if call.phase == "attested-judge" and call.operation == "prepare"
    )
    assert judge_prepare.nonce_ledger_root == nonce_ledger_root
    assert (
        judge_prepare.command[judge_prepare.command.index("--nonce-ledger") + 1]
        == "/nonce-ledger/nonces.sqlite3"
    )
    assert all(call.nonce_ledger_root is None for call in calls if call is not judge_prepare)
    assert not list(final.rglob("AGENTS.md"))
    assert len(list((output / "snapshot-artifacts").rglob("AGENTS.md"))) == 3
    assert not (final / "phase-request.json").exists()
    assert all(not path.stat().st_mode & 0o222 for path in output.rglob("*"))


def test_outer_runtime_rejects_coordinator_output_symlink_before_target_chmod(
    tmp_path: Path,
) -> None:
    initial, output, candidate, key, nonce_ledger_root = _protected_inputs(tmp_path)
    victim = tmp_path / "victim"
    victim.write_bytes(b"unchanged\n")
    victim.chmod(0o600)

    def coordinator(call) -> bytes:
        call.output_root.joinpath("escape").symlink_to(victim)
        return b"{}\n"

    with pytest.raises(OuterWorkflowRuntimeError, match="symlink"):
        run_production_workflow(
            initial / "phase-request.json",
            initial_artifact_root=initial,
            output_root=output,
            candidate_repo=candidate,
            signing_key=key,
            nonce_ledger_root=nonce_ledger_root,
            candidate_uid=65_534 if os.geteuid() != 65_534 else 65_533,
            images=_images(),
            broker_ledger_identity_sha256="c" * 64,
            broker_runtime_binding=_broker_runtime_binding(),
            coordinator_execute=coordinator,
            offline_execute=lambda _payload, _root: pytest.fail("offline must not run"),
            broker_execute=lambda _payload: pytest.fail("broker must not run"),
        )
    assert victim.stat().st_mode & 0o777 == 0o600


def test_outer_runtime_rejects_tampered_broker_runtime_binding_before_phase_zero(
    tmp_path: Path,
) -> None:
    initial, output, candidate, key, nonce_ledger_root = _protected_inputs(tmp_path)
    tampered = bytearray(_broker_runtime_binding())
    tampered[tampered.index(ord("p"))] = ord("x")

    with pytest.raises(OuterWorkflowRuntimeError, match="runtime binding"):
        run_production_workflow(
            initial / "phase-request.json",
            initial_artifact_root=initial,
            output_root=output,
            candidate_repo=candidate,
            signing_key=key,
            nonce_ledger_root=nonce_ledger_root,
            candidate_uid=65_534 if os.geteuid() != 65_534 else 65_533,
            images=_images(),
            broker_ledger_identity_sha256="c" * 64,
            broker_runtime_binding=bytes(tampered),
            coordinator_execute=lambda _call: pytest.fail("phase zero must not run"),
            offline_execute=lambda _payload, _root: pytest.fail("offline must not run"),
            broker_execute=lambda _payload: pytest.fail("broker must not run"),
        )


@pytest.mark.parametrize(
    ("changed", "value"),
    (("name", "docker"), ("rootless", False), ("user_namespace", False)),
)
def test_outer_runtime_requires_rootless_podman_keep_id_before_phase_zero(
    tmp_path: Path,
    changed: str,
    value: object,
) -> None:
    initial, output, candidate, key, nonce_ledger_root = _protected_inputs(tmp_path)
    binding = json.loads(_broker_runtime_binding())
    binding[changed] = value
    security = {
        "name": binding["name"],
        "rootless": binding["rootless"],
        "seccomp_profile": binding["seccomp_profile"],
        "user_namespace": binding["user_namespace"],
    }
    binding["security_evidence_sha256"] = hashlib.sha256(canonical_json_bytes(security)).hexdigest()

    with pytest.raises(OuterWorkflowRuntimeError, match="runtime binding"):
        run_production_workflow(
            initial / "phase-request.json",
            initial_artifact_root=initial,
            output_root=output,
            candidate_repo=candidate,
            signing_key=key,
            nonce_ledger_root=nonce_ledger_root,
            candidate_uid=65_534 if os.geteuid() != 65_534 else 65_533,
            images=_images(),
            broker_ledger_identity_sha256="c" * 64,
            broker_runtime_binding=canonical_json_bytes(binding),
            coordinator_execute=lambda _call: pytest.fail("phase zero must not run"),
            offline_execute=lambda _payload, _root: pytest.fail("offline must not run"),
            broker_execute=lambda _payload: pytest.fail("broker must not run"),
        )


def test_outer_workflow_runtime_imports_without_site_dependencies(tmp_path: Path) -> None:
    project = Path(__file__).parents[1]
    script = (
        "import sys;"
        "sys.path.insert(0,sys.argv[1]);"
        "import tools.ai_review.outer_workflow_runtime;"
        "assert sys.flags.isolated and sys.flags.no_site;"
        "assert 'pydantic' not in sys.modules and 'cryptography' not in sys.modules"
    )
    result = subprocess.run(
        [sys.executable, "-I", "-S", "-c", script, str(project)],
        cwd=tmp_path,
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
        env={"PATH": os.defpath, "LC_ALL": "C"},
    )
    assert result.returncode == 0, result.stderr
