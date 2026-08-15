from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

from tools.ai_review.broker_outer_executor import _execute_prepared_broker_outer
from tools.ai_review.broker_outer_executor import _base_environment
from tools.ai_review.broker_outer_executor import prepare_broker_outer_ledger
from tools.ai_review.broker_phase_protocol import BrokerRuntimeBinding
from tools.ai_review.phase_execution_adapters import finalize_broker_phase_output
from tools.ai_review.phase_execution_adapters import prepare_broker_phase_action
from tools.ai_review.phase_protocol import CoordinatorPhaseOutput
from tools.ai_review.phase_protocol import PhaseRequest
from tests.test_ai_review_broker_egress_provisioner import FakeRuntime
from tests.test_ai_review_broker_egress_provisioner import broker_envelope
from tests.test_ai_review_broker_egress_provisioner import podman_probe
from tests.test_ai_review_broker_phase_protocol import _canonical
from tests.test_ai_review_broker_phase_protocol import _prepare_inputs


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def test_broker_phase_action_reaches_provisioned_outer_and_typed_finalize(
    tmp_path: Path,
) -> None:
    runtime_path = tmp_path / "podman"
    runtime_path.write_bytes(b"trusted runtime\n")
    runtime_path.chmod(0o555)
    security = {
        "name": "podman",
        "rootless": True,
        "seccomp_profile": "/usr/share/containers/seccomp.json",
        "user_namespace": True,
    }
    inputs = _prepare_inputs()
    inputs["runtime"] = BrokerRuntimeBinding(
        name="podman",
        executable_sha256=_sha256(runtime_path.read_bytes()),
        environment_sha256=_sha256(_canonical(_base_environment("podman"))),
        rootless=True,
        user_namespace=True,
        seccomp_profile="/usr/share/containers/seccomp.json",
        security_evidence_sha256=_sha256(_canonical(security) + b"\n"),
    )
    ledger_path = tmp_path / "ledger" / "broker.sqlite3"
    ledger_path.parent.mkdir(mode=0o700)
    candidate_uid = inputs["candidate_uid"]
    inputs["broker_ledger_identity_sha256"] = prepare_broker_outer_ledger(
        ledger_path,
        candidate_uid=candidate_uid,
    )
    request = PhaseRequest.create(
        workflow_id=inputs["workflow_id"],
        phase="broker",
        sequence=5,
        previous_phase_sha256="6" * 64,
        task_sha256=inputs["task_sha256"],
        runtime_manifest_sha256=inputs["runtime_manifest_sha256"],
        coordinator_key_id="7" * 64,
        coordinator_public_key_sha256="8" * 64,
        candidate_sha256="9" * 64,
        candidate_snapshot_sha256=inputs["candidate_snapshot_sha256"],
        review_packet_sha256=inputs["review_packet_sha256"],
        input_artifacts_sha256="e" * 64,
    )
    action, prepared_raw = prepare_broker_phase_action(
        request,
        invocations=inputs["invocations"],
        runtime=inputs["runtime"],
        gateway_image=inputs["gateway_image"],
        broker_gateway_image_digest=inputs["broker_gateway_image_digest"],
        allowlist_policy=inputs["allowlist_policy"],
        broker_allowlist_policy_sha256=inputs["broker_allowlist_policy_sha256"],
        pricing_policy=inputs["pricing_policy"],
        broker_pricing_policy_sha256=inputs["broker_pricing_policy_sha256"],
        broker_ledger_identity_sha256=inputs["broker_ledger_identity_sha256"],
        broker_packet_reservation_limit=inputs["broker_packet_reservation_limit"],
        broker_packet_cost_limit_microusd=inputs["broker_packet_cost_limit_microusd"],
        candidate_uid=candidate_uid,
    )
    action.validate_for(request, prepared_raw)
    fake = FakeRuntime()

    def stream_runner(argv, *, stdin_bytes, **_kwargs):
        return FakeRuntime._result(
            tuple(argv),
            0,
            stdout=broker_envelope(_sha256(stdin_bytes[:-1])),
        )

    outer_raw = _execute_prepared_broker_outer(
        prepared_raw,
        credentials={
            "reviewer": "sk-test-reviewer-never-recorded",
            "adversary": "sk-test-adversary-never-recorded",
        },
        ledger_path=ledger_path,
        runtime_executable=runtime_path,
        require_two=True,
        runner=fake,
        stream_runner=stream_runner,
        probe=podman_probe,
        broker_cleanup=lambda *_args: True,
    )
    assert "sk-test" not in outer_raw.decode()
    assert fake.networks == {}
    assert fake.containers == {}
    output = CoordinatorPhaseOutput.model_validate_json(
        finalize_broker_phase_output(
            request,
            action,
            prepared_raw,
            outer_raw,
            allowlist_policy=inputs["allowlist_policy"],
            pricing_policy=inputs["pricing_policy"],
        )
    )
    assert [artifact.name for artifact in output.artifacts] == ["adversary", "reviewer"]
    summaries = [json.loads(artifact.content()) for artifact in output.artifacts]
    assert [item["role"] for item in summaries] == ["adversary", "reviewer"]
    assert all(len(item["evidence_sha256"]) == 64 for item in summaries)
    assert all(
        item["prepared_batch_sha256"] == hashlib.sha256(prepared_raw).hexdigest()
        and item["outer_evidence_sha256"] == hashlib.sha256(outer_raw).hexdigest()
        for item in summaries
    )
    assert len({item["final_ledger_evidence_sha256"] for item in summaries}) == 1
    assert len({item["final_ledger_records_sha256"] for item in summaries}) == 1
    assert all("candidate" not in artifact.content().decode() for artifact in output.artifacts)
    assert os.stat(ledger_path).st_mode & 0o077 == 0
