from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from tools.ai_review.broker_executor import BrokerExecutionError
from tools.ai_review.broker_executor import EgressBoundaryEvidence
from tools.ai_review.broker_executor import broker_egress_boundary_sha256
from tools.ai_review.broker_executor import execute_isolated_broker
from tools.ai_review.broker_executor import measure_broker_ledger
from tools.ai_review.broker_executor import prepare_broker_ledger
from tools.ai_review.broker_executor import _run_bounded_broker
from tools.ai_review.broker_executor import validate_broker_execution_evidence
from tools.ai_review.broker_executor import validate_broker_ledger_evidence
from tools.ai_review.broker_executor import (
    validate_successful_broker_executions_against_final_ledger,
)
from tools.ai_review.codex_adapter import BROKER_CREDENTIAL_ENV
from tools.ai_review.codex_adapter import IsolatedBrokerInvocation
from tools.ai_review.codex_adapter import broker_container_name
from tools.ai_review.codex_adapter import broker_internal_network_name
from tools.ai_review.codex_adapter import build_isolated_broker_argv
from tools.ai_review.pricing_policy import APPROVED_OPENAI_PRICING_POLICY
from tools.ai_review.pricing_policy import canonical_openai_pricing_policy_bytes
from tools.ai_review.pricing_policy import reserve_request_cost_microusd


def canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def protected_file(path: Path, content: bytes, mode: int = 0o555) -> Path:
    path.write_bytes(content)
    path.chmod(mode)
    return path


def other_uid() -> int:
    return 65_534 if os.geteuid() != 65_534 else 65_533


def request_payload() -> dict:
    return {
        "input": [
            {
                "content": [{"text": "sanitized review packet", "type": "input_text"}],
                "role": "user",
            }
        ],
        "max_output_tokens": 12_000,
        "model": "gpt-5.6-sol",
        "service_tier": "default",
        "reasoning": {"effort": "high", "summary": "none"},
        "store": False,
        "text": {
            "format": {
                "name": "review_report",
                "schema": {"additionalProperties": False, "type": "object"},
                "strict": True,
                "type": "json_schema",
            },
            "verbosity": "low",
        },
        "tools": [],
    }


def make_invocation(
    *,
    packet_sha256: str = "a" * 64,
    role: str = "reviewer",
    attempt: int = 1,
    reserved_tokens: int = 20_000,
    runtime: str = "podman",
    rootless: bool = True,
    user_namespace: bool = True,
) -> IsolatedBrokerInvocation:
    payload = request_payload()
    if role == "adversary":
        payload["reasoning"]["effort"] = "xhigh"
    payload["input"][0]["content"][0]["text"] = ""
    canonical_request_overhead = len(canonical_json(payload))
    input_text_bytes = reserved_tokens - 12_000 - canonical_request_overhead
    if input_text_bytes < 1:
        raise ValueError("test reservation is too small for the canonical request")
    payload["input"][0]["content"][0]["text"] = "x" * input_text_bytes
    request = canonical_json(payload)
    assert len(request) + 12_000 == reserved_tokens
    stdin = request + b"\n"
    image_digest = f"sha256:{'b' * 64}"
    image = f"registry.invalid/review-broker@{image_digest}"
    name = broker_container_name(
        packet_sha256=packet_sha256,
        request_sha256=sha256(request),
        role=role,
        attempt=attempt,
    )
    network = broker_internal_network_name(
        packet_sha256=packet_sha256,
        request_sha256=sha256(request),
        role=role,
        attempt=attempt,
    )
    argv = build_isolated_broker_argv(
        container_runtime=runtime,
        image=image,
        container_name=name,
        broker_internal_network=network,
        runtime_rootless=rootless,
        runtime_user_namespace=user_namespace,
    )
    return IsolatedBrokerInvocation(
        argv=argv,
        stdin_text=stdin.decode("utf-8"),
        container_runtime=runtime,
        runtime_rootless=rootless,
        runtime_user_namespace=user_namespace,
        container_name=name,
        broker_internal_network=network,
        image=image,
        approved_image_digest=image_digest,
        credential_env_name=BROKER_CREDENTIAL_ENV,
        packet_sha256=packet_sha256,
        request_sha256=sha256(request),
        role=role,
        attempt=attempt,
        reserved_tokens=reserved_tokens,
        stdin_sha256=sha256(stdin),
        argv_sha256=sha256(canonical_json(list(argv))),
        boundary_evidence_sha256="c" * 64,
    )


def broker_envelope(request_sha256: str) -> bytes:
    response = {"id": "resp_test", "object": "response", "output": [], "status": "completed"}
    payload = {
        "request_id": "req_test",
        "request_sha256": request_sha256,
        "response": response,
        "response_sha256": sha256(canonical_json(response)),
        "schema_version": "1.0",
    }
    return canonical_json(payload) + b"\n"


def podman_probe(argv, **_kwargs):
    return subprocess.CompletedProcess(
        argv,
        0,
        stdout=(
            '{"host":{"security":{"rootless":true,"seccompEnabled":true,'
            '"seccompProfilePath":"/usr/share/containers/seccomp.json"}}}'
        ),
        stderr="",
    )


def make_egress_boundary(runtime: str, network: str) -> EgressBoundaryEvidence:
    gateway_digest = f"sha256:{'7' * 64}"
    gateway_name = "ai-review-egress-gateway-" + network.rsplit("-", 1)[-1][-16:]
    network_inspect = canonical_json([{"Internal": True, "Name": network}])
    gateway_inspect = canonical_json(
        [
            {
                "Config": {"Image": f"registry.invalid/gateway@{gateway_digest}"},
                "Mounts": [],
                "Name": gateway_name,
                "Networks": [network, "coordinator-external"],
            }
        ]
    )
    allowlist = canonical_json(
        {
            "destinations": [{"host": "api.openai.com", "port": 443}],
            "protocol": "tcp",
            "schema_version": "1.0",
        }
    )
    provisioning = canonical_json(
        {
            "broker_internal_network": network,
            "gateway_alias": "ai-review-egress-gateway",
            "gateway_port": 8443,
            "schema_version": "1.0",
        }
    )
    evidence = EgressBoundaryEvidence(
        schema_version="1.0",
        runtime_name=runtime,
        broker_internal_network=network,
        broker_network_inspect=network_inspect,
        broker_network_inspect_sha256=sha256(network_inspect),
        gateway_container_name=gateway_name,
        gateway_image=f"registry.invalid/gateway@{gateway_digest}",
        broker_gateway_image_digest=gateway_digest,
        gateway_container_inspect=gateway_inspect,
        gateway_container_inspect_sha256=sha256(gateway_inspect),
        allowlist_policy=allowlist,
        broker_allowlist_policy_sha256=sha256(allowlist),
        provisioning=provisioning,
        provisioning_sha256=sha256(provisioning),
        api_host="api.openai.com",
        api_port=443,
        gateway_network_alias="ai-review-egress-gateway",
        gateway_port=8443,
        broker_network_internal_verified=True,
        broker_external_network_absent=True,
        broker_network_only_gateway_peer_verified=True,
        gateway_dual_homed_verified=True,
        gateway_network_alias_verified=True,
        gateway_tcp_proxy_verified=True,
        gateway_candidate_mounts_absent=True,
        gateway_broker_credential_absent=True,
        fixed_destination_verified=True,
        broker_egress_boundary_sha256="0" * 64,
    )
    return replace(
        evidence,
        broker_egress_boundary_sha256=broker_egress_boundary_sha256(evidence),
    )


def executor_inputs(tmp_path: Path, invocation: IsolatedBrokerInvocation) -> dict:
    tmp_path.mkdir(parents=True, exist_ok=True)
    runtime = protected_file(tmp_path / invocation.container_runtime, b"runtime\n")
    ledger = tmp_path / "ledger" / "broker.sqlite3"
    ledger.parent.mkdir(mode=0o700, exist_ok=True)
    egress = make_egress_boundary(
        invocation.container_runtime,
        invocation.broker_internal_network,
    )
    candidate_uid = other_uid()
    ledger_identity = prepare_broker_ledger(ledger, candidate_uid=candidate_uid)
    return {
        "invocation": invocation,
        "expected_packet_sha256": invocation.packet_sha256,
        "expected_request_sha256": invocation.request_sha256,
        "expected_boundary_evidence_sha256": invocation.boundary_evidence_sha256,
        "expected_role": invocation.role,
        "expected_attempt": invocation.attempt,
        "approved_image_digest": invocation.approved_image_digest,
        "expected_argv_sha256": invocation.argv_sha256,
        "expected_stdin_sha256": invocation.stdin_sha256,
        "broker_egress_boundary": egress,
        "expected_broker_egress_boundary_sha256": egress.broker_egress_boundary_sha256,
        "expected_broker_gateway_image_digest": egress.broker_gateway_image_digest,
        "expected_broker_allowlist_policy_sha256": egress.broker_allowlist_policy_sha256,
        "credential": "sk-test-credential-never-record",
        "ledger_path": ledger,
        "expected_broker_ledger_identity_sha256": ledger_identity,
        "broker_packet_reservation_limit": 100_000,
        "candidate_uid": candidate_uid,
        "allow_external_ai": True,
        "allow_isolated_broker": True,
        "which": lambda name: str(runtime) if name == invocation.container_runtime else None,
        "probe": podman_probe,
    }


def test_executor_returns_raw_digest_bound_evidence_and_secret_only_enters_env(tmp_path):
    invocation = make_invocation()
    assert (
        invocation.broker_internal_network
        != make_invocation(role="adversary").broker_internal_network
    )
    assert invocation.broker_internal_network != make_invocation(attempt=2).broker_internal_network
    inputs = executor_inputs(tmp_path, invocation)
    observed: dict[str, object] = {}
    stdout = broker_envelope(invocation.request_sha256)

    def runner(argv, **kwargs):
        observed.update(argv=argv, kwargs=kwargs)
        return SimpleNamespace(
            exit_code=0,
            stdout=stdout,
            stderr=b"broker diagnostic\n",
            stdout_sha256=sha256(stdout),
            stderr_sha256=sha256(b"broker diagnostic\n"),
            duration_ms=17,
        )

    cleaned: list[str] = []
    cleanup_environments: list[dict[str, str]] = []

    def cleanup(_backend, name, environment):
        cleaned.append(name)
        cleanup_environments.append(environment)
        return True

    evidence = execute_isolated_broker(
        **inputs,
        stream_runner=runner,
        cleanup=cleanup,
    )

    actual_argv = tuple(observed["argv"])
    assert actual_argv[0] == str(evidence.runtime_executable)
    assert actual_argv[1:] == invocation.argv[1:]
    assert observed["kwargs"]["stdin_bytes"] == invocation.stdin_text.encode()
    environment = observed["kwargs"]["environment"]
    assert environment[BROKER_CREDENTIAL_ENV] == inputs["credential"]
    assert inputs["credential"] not in "\n".join(invocation.argv)
    assert inputs["credential"].encode() not in evidence.stdin + evidence.stdout + evidence.stderr
    assert evidence.canonical_envelope == stdout
    assert evidence.stdout_sha256 == sha256(stdout)
    assert evidence.argv == actual_argv
    assert evidence.argv_sha256 == sha256(canonical_json(list(actual_argv)))
    assert evidence.descriptor_argv == invocation.argv
    assert evidence.descriptor_argv_sha256 == invocation.argv_sha256
    assert evidence.stdin_sha256 == invocation.stdin_sha256
    assert evidence.runtime_seccomp_profile == "/usr/share/containers/seccomp.json"
    assert evidence.cleanup_succeeded is True
    assert cleaned == [invocation.container_name]
    assert BROKER_CREDENTIAL_ENV not in cleanup_environments[0]
    assert evidence.reserved_tokens == invocation.reserved_tokens
    expected_cost = reserve_request_cost_microusd(
        APPROVED_OPENAI_PRICING_POLICY,
        input_tokens=invocation.reserved_tokens - 12_000,
        output_tokens=12_000,
    )
    assert evidence.reserved_cost_microusd == expected_cost
    assert evidence.cumulative_reserved_cost_microusd == expected_cost
    assert evidence.broker_pricing_policy_sha256 == APPROVED_OPENAI_PRICING_POLICY.sha256
    assert evidence.ledger.broker_pricing_policy_sha256 == APPROVED_OPENAI_PRICING_POLICY.sha256
    assert evidence.cumulative_reserved_tokens == invocation.reserved_tokens
    assert evidence.broker_packet_reservation_limit == 100_000
    assert (
        evidence.broker_ledger_identity_sha256 == inputs["expected_broker_ledger_identity_sha256"]
    )
    assert (
        evidence.broker_egress_boundary_sha256 == inputs["expected_broker_egress_boundary_sha256"]
    )


def test_default_runner_executes_the_measured_absolute_runtime_outside_host_path(tmp_path):
    invocation = make_invocation()
    inputs = executor_inputs(tmp_path, invocation)
    stdout = broker_envelope(invocation.request_sha256)
    runtime = Path(inputs["which"](invocation.container_runtime))
    protected_file(
        runtime,
        (f"#!{sys.executable}\nimport os\nos.write(1, {stdout!r})\n").encode("utf-8"),
    )

    evidence = execute_isolated_broker(**inputs)

    assert str(runtime.parent) not in os.defpath.split(os.pathsep)
    assert evidence.argv[0] == str(runtime)
    assert evidence.argv[1:] == invocation.argv[1:]
    assert evidence.canonical_envelope == stdout
    assert evidence.cleanup_argv[0] == str(runtime)
    assert evidence.cleanup_exit_code == 0


def test_raw_execution_evidence_is_independently_revalidated(tmp_path):
    invocation = make_invocation()
    inputs = executor_inputs(tmp_path, invocation)
    stdout = broker_envelope(invocation.request_sha256)

    def runner(*_args, **_kwargs):
        return SimpleNamespace(
            exit_code=0,
            stdout=stdout,
            stderr=b"",
            stdout_sha256=sha256(stdout),
            stderr_sha256=sha256(b""),
            duration_ms=1,
        )

    evidence = execute_isolated_broker(
        **inputs,
        stream_runner=runner,
        cleanup=lambda *_args: True,
    )
    validation = {
        "invocation": invocation,
        "expected_packet_sha256": invocation.packet_sha256,
        "expected_request_sha256": invocation.request_sha256,
        "expected_boundary_evidence_sha256": invocation.boundary_evidence_sha256,
        "expected_role": invocation.role,
        "expected_attempt": invocation.attempt,
        "approved_image_digest": invocation.approved_image_digest,
        "expected_descriptor_argv_sha256": invocation.argv_sha256,
        "expected_stdin_sha256": invocation.stdin_sha256,
        "expected_broker_egress_boundary_sha256": inputs["expected_broker_egress_boundary_sha256"],
        "expected_broker_gateway_image_digest": inputs["expected_broker_gateway_image_digest"],
        "expected_broker_allowlist_policy_sha256": inputs[
            "expected_broker_allowlist_policy_sha256"
        ],
        "ledger_path": inputs["ledger_path"],
        "expected_broker_ledger_identity_sha256": inputs["expected_broker_ledger_identity_sha256"],
        "broker_packet_reservation_limit": 100_000,
        "candidate_uid": inputs["candidate_uid"],
        "which": inputs["which"],
        "probe": inputs["probe"],
    }
    assert validate_broker_execution_evidence(evidence, **validation) is evidence

    for forged in (
        replace(evidence, stdout_sha256="0" * 64),
        replace(evidence, runtime_post_sha256="0" * 64),
        replace(evidence, descriptor_argv=evidence.descriptor_argv + ("--mount=/tmp:/tmp",)),
        replace(evidence, cleanup_exit_code=1),
        replace(evidence, evidence_sha256="0" * 64),
    ):
        with pytest.raises(BrokerExecutionError, match="evidence validation failed"):
            validate_broker_execution_evidence(forged, **validation)

    final_ledger = measure_broker_ledger(
        inputs["ledger_path"],
        packet_sha256=invocation.packet_sha256,
        broker_packet_reservation_limit=100_000,
        candidate_uid=inputs["candidate_uid"],
    )
    assert (
        final_ledger.broker_ledger_identity_sha256 == evidence.ledger.broker_ledger_identity_sha256
    )
    assert final_ledger.records_sha256 == evidence.ledger.records_sha256
    assert (
        validate_broker_ledger_evidence(
            final_ledger,
            ledger_path=inputs["ledger_path"],
            expected_packet_sha256=invocation.packet_sha256,
            broker_packet_reservation_limit=100_000,
            expected_broker_ledger_identity_sha256=inputs["expected_broker_ledger_identity_sha256"],
            candidate_uid=inputs["candidate_uid"],
        )
        is final_ledger
    )


def test_executor_revalidates_mountless_exact_invocation_before_reservation_or_launch(tmp_path):
    invocation = make_invocation()
    inputs = executor_inputs(tmp_path, invocation)
    forged = object.__new__(IsolatedBrokerInvocation)
    forged_values = vars(invocation) | {
        "argv": invocation.argv[:-1] + ("--mount=/candidate:/workspace", invocation.image),
    }
    forged_values["argv_sha256"] = sha256(canonical_json(list(forged_values["argv"])))
    for key, value in forged_values.items():
        object.__setattr__(forged, key, value)
    called = False

    def forbidden_runner(*_args, **_kwargs):
        nonlocal called
        called = True
        raise AssertionError("invalid invocation must not launch")

    with pytest.raises(BrokerExecutionError, match="invocation validation failed"):
        execute_isolated_broker(
            **{
                **inputs,
                "invocation": forged,
                "expected_argv_sha256": forged.argv_sha256,
            },
            stream_runner=forbidden_runner,
        )

    assert called is False
    with sqlite3.connect(inputs["ledger_path"]) as connection:
        assert connection.execute("SELECT COUNT(*) FROM broker_reservations").fetchone() == (0,)


def test_executor_requires_double_opt_in_and_exact_trusted_bindings(tmp_path):
    invocation = make_invocation()
    inputs = executor_inputs(tmp_path, invocation)
    called = False

    def forbidden_runner(*_args, **_kwargs):
        nonlocal called
        called = True

    for override in (
        {"allow_external_ai": False},
        {"allow_isolated_broker": False},
        {"expected_stdin_sha256": "d" * 64},
        {"approved_image_digest": f"sha256:{'e' * 64}"},
        {"expected_broker_ledger_identity_sha256": "d" * 64},
    ):
        with pytest.raises(BrokerExecutionError):
            execute_isolated_broker(
                **{**inputs, **override},
                stream_runner=forbidden_runner,
            )
    assert called is False


def test_executor_requires_attested_internal_gateway_boundary_before_reservation(tmp_path):
    invocation = make_invocation()
    inputs = executor_inputs(tmp_path, invocation)
    called = False

    def forbidden_runner(*_args, **_kwargs):
        nonlocal called
        called = True

    forged = replace(
        inputs["broker_egress_boundary"],
        gateway_candidate_mounts_absent=False,
    )
    with pytest.raises(BrokerExecutionError, match="egress boundary validation failed"):
        execute_isolated_broker(
            **{
                **inputs,
                "broker_egress_boundary": forged,
                "expected_broker_egress_boundary_sha256": (forged.broker_egress_boundary_sha256),
            },
            stream_runner=forbidden_runner,
        )
    with pytest.raises(BrokerExecutionError, match="egress boundary validation failed"):
        execute_isolated_broker(
            **{**inputs, "expected_broker_allowlist_policy_sha256": "0" * 64},
            stream_runner=forbidden_runner,
        )
    assert called is False
    with sqlite3.connect(inputs["ledger_path"]) as connection:
        assert connection.execute("SELECT COUNT(*) FROM broker_reservations").fetchone() == (0,)


def test_failed_launch_consumes_atomic_attempt_reservation_and_error_is_secret_free(tmp_path):
    invocation = make_invocation()
    inputs = executor_inputs(tmp_path, invocation)
    secret = inputs["credential"]
    cleaned: list[str] = []

    def failed_runner(*_args, **_kwargs):
        raise BrokerExecutionError("broker process failed")

    with pytest.raises(BrokerExecutionError) as captured:
        execute_isolated_broker(
            **inputs,
            stream_runner=failed_runner,
            cleanup=lambda _backend, name, _environment: cleaned.append(name) or True,
        )
    assert secret not in str(captured.value)
    assert invocation.stdin_text not in str(captured.value)
    assert cleaned == [invocation.container_name]

    with pytest.raises(BrokerExecutionError, match="attempt reservation rejected"):
        execute_isolated_broker(**inputs, stream_runner=failed_runner)
    with sqlite3.connect(inputs["ledger_path"]) as connection:
        row = connection.execute(
            "SELECT attempt, reserved_tokens FROM broker_reservations"
        ).fetchone()
    assert row == (1, invocation.reserved_tokens)


def test_cost_cap_and_pricing_policy_are_checked_before_atomic_reservation(tmp_path):
    invocation = make_invocation(reserved_tokens=20_000)
    inputs = executor_inputs(tmp_path, invocation)
    reserved_cost = reserve_request_cost_microusd(
        APPROVED_OPENAI_PRICING_POLICY,
        input_tokens=invocation.reserved_tokens - 12_000,
        output_tokens=12_000,
    )

    with pytest.raises(BrokerExecutionError, match="cost reservation rejected"):
        execute_isolated_broker(
            **inputs,
            broker_packet_cost_limit_microusd=reserved_cost - 1,
        )
    with sqlite3.connect(inputs["ledger_path"]) as connection:
        assert connection.execute("SELECT COUNT(*) FROM broker_reservations").fetchone() == (0,)

    tampered_policy = canonical_openai_pricing_policy_bytes().replace(b"6250000", b"1250000")
    with pytest.raises(BrokerExecutionError, match="pricing policy validation failed"):
        execute_isolated_broker(
            **inputs,
            pricing_policy=tampered_policy,
        )
    with sqlite3.connect(inputs["ledger_path"]) as connection:
        assert connection.execute("SELECT COUNT(*) FROM broker_reservations").fetchone() == (0,)


def test_ledger_enforces_attempt_order_two_attempt_max_and_packet_token_sum(tmp_path):
    packet = "f" * 64
    runs: list[tuple[str, int]] = []

    def runner_factory(invocation):
        def runner(_argv, **_kwargs):
            runs.append((invocation.role, invocation.attempt))
            stdout = broker_envelope(invocation.request_sha256)
            return SimpleNamespace(
                exit_code=0,
                stdout=stdout,
                stderr=b"",
                stdout_sha256=sha256(stdout),
                stderr_sha256=sha256(b""),
                duration_ms=1,
            )

        return runner

    attempt_two_first = make_invocation(packet_sha256=packet, attempt=2, reserved_tokens=30_000)
    with pytest.raises(BrokerExecutionError, match="attempt reservation rejected"):
        execute_isolated_broker(
            **executor_inputs(tmp_path, attempt_two_first),
            stream_runner=runner_factory(attempt_two_first),
        )

    first = make_invocation(packet_sha256=packet, attempt=1, reserved_tokens=30_000)
    first_inputs = executor_inputs(tmp_path, first)
    first_evidence = execute_isolated_broker(
        **first_inputs,
        stream_runner=runner_factory(first),
        cleanup=lambda *_args: True,
    )
    second = make_invocation(packet_sha256=packet, attempt=2, reserved_tokens=30_000)
    second_evidence = execute_isolated_broker(
        **{**executor_inputs(tmp_path, second), "ledger_path": first_inputs["ledger_path"]},
        stream_runner=runner_factory(second),
        cleanup=lambda *_args: True,
    )
    adversary = make_invocation(
        packet_sha256=packet,
        role="adversary",
        attempt=1,
        reserved_tokens=50_000,
    )
    with pytest.raises(BrokerExecutionError, match="token reservation rejected"):
        execute_isolated_broker(
            **{
                **executor_inputs(tmp_path, adversary),
                "ledger_path": first_inputs["ledger_path"],
            },
            stream_runner=runner_factory(adversary),
        )
    assert runs == [("reviewer", 1), ("reviewer", 2)]
    final_ledger = measure_broker_ledger(
        first_inputs["ledger_path"],
        packet_sha256=packet,
        broker_packet_reservation_limit=100_000,
        candidate_uid=first_inputs["candidate_uid"],
    )
    records = json.loads(final_ledger.records)["records"]
    assert len(records) == 2
    assert final_ledger.cumulative_reserved_tokens == 60_000
    assert (
        first_evidence.ledger.broker_ledger_identity_sha256
        == second_evidence.ledger.broker_ledger_identity_sha256
        == final_ledger.broker_ledger_identity_sha256
        == first_inputs["expected_broker_ledger_identity_sha256"]
    )


def test_final_ledger_charges_failed_retry_but_rejects_reservation_after_success(tmp_path):
    packet = "e" * 64

    def failed_runner(*_args, **_kwargs):
        raise BrokerExecutionError("generic failure")

    def successful_runner(invocation):
        envelope = broker_envelope(invocation.request_sha256)

        def run(*_args, **_kwargs):
            return SimpleNamespace(
                exit_code=0,
                stdout=envelope,
                stderr=b"",
                stdout_sha256=sha256(envelope),
                stderr_sha256=sha256(b""),
                duration_ms=1,
            )

        return run

    reviewer_one = make_invocation(
        packet_sha256=packet,
        role="reviewer",
        attempt=1,
        reserved_tokens=20_000,
    )
    shared = executor_inputs(tmp_path, reviewer_one)
    with pytest.raises(BrokerExecutionError, match="isolated broker process failed"):
        execute_isolated_broker(
            **shared,
            stream_runner=failed_runner,
            cleanup=lambda *_args: True,
        )
    reviewer_two = make_invocation(
        packet_sha256=packet,
        role="reviewer",
        attempt=2,
        reserved_tokens=20_000,
    )
    reviewer_success = execute_isolated_broker(
        **{
            **executor_inputs(tmp_path, reviewer_two),
            "ledger_path": shared["ledger_path"],
        },
        stream_runner=successful_runner(reviewer_two),
        cleanup=lambda *_args: True,
    )
    adversary_one = make_invocation(
        packet_sha256=packet,
        role="adversary",
        attempt=1,
        reserved_tokens=20_000,
    )
    adversary_success = execute_isolated_broker(
        **{
            **executor_inputs(tmp_path, adversary_one),
            "ledger_path": shared["ledger_path"],
        },
        stream_runner=successful_runner(adversary_one),
        cleanup=lambda *_args: True,
    )
    final = measure_broker_ledger(
        shared["ledger_path"],
        packet_sha256=packet,
        broker_packet_reservation_limit=100_000,
        candidate_uid=shared["candidate_uid"],
    )
    assert final.cumulative_reserved_tokens == 60_000
    assert sum(item.reserved_tokens for item in (reviewer_success, adversary_success)) == 40_000
    assert (
        validate_successful_broker_executions_against_final_ledger(
            (reviewer_success, adversary_success),
            final,
        )
        == final
    )

    adversary_two = make_invocation(
        packet_sha256=packet,
        role="adversary",
        attempt=2,
        reserved_tokens=20_000,
    )
    with pytest.raises(BrokerExecutionError, match="isolated broker process failed"):
        execute_isolated_broker(
            **{
                **executor_inputs(tmp_path, adversary_two),
                "ledger_path": shared["ledger_path"],
            },
            stream_runner=failed_runner,
            cleanup=lambda *_args: True,
        )
    after_success_retry = measure_broker_ledger(
        shared["ledger_path"],
        packet_sha256=packet,
        broker_packet_reservation_limit=100_000,
        candidate_uid=shared["candidate_uid"],
    )
    with pytest.raises(BrokerExecutionError, match="final ledger validation failed"):
        validate_successful_broker_executions_against_final_ledger(
            (reviewer_success, adversary_success),
            after_success_retry,
        )


def test_concurrent_duplicate_attempt_is_atomically_reserved_once(tmp_path):
    invocation = make_invocation(reserved_tokens=30_000)
    inputs = executor_inputs(tmp_path, invocation)
    stdout = broker_envelope(invocation.request_sha256)
    launches: list[int] = []

    def runner(*_args, **_kwargs):
        launches.append(1)
        return SimpleNamespace(
            exit_code=0,
            stdout=stdout,
            stderr=b"",
            stdout_sha256=sha256(stdout),
            stderr_sha256=sha256(b""),
            duration_ms=1,
        )

    def execute_once():
        try:
            return execute_isolated_broker(
                **inputs,
                stream_runner=runner,
                cleanup=lambda *_args: True,
            )
        except BrokerExecutionError as exc:
            return exc

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(lambda _index: execute_once(), range(2)))

    assert len([result for result in results if not isinstance(result, Exception)]) == 1
    errors = [result for result in results if isinstance(result, BrokerExecutionError)]
    assert len(errors) == 1
    assert "attempt reservation rejected" in str(errors[0])
    assert launches == [1]


def test_backend_security_change_or_cleanup_failure_fails_closed(tmp_path):
    invocation = make_invocation()
    inputs = executor_inputs(tmp_path, invocation)
    probe_count = 0

    def changing_probe(argv, **_kwargs):
        nonlocal probe_count
        probe_count += 1
        rootless = "true" if probe_count == 1 else "false"
        return subprocess.CompletedProcess(
            argv,
            0,
            stdout=(
                '{"host":{"security":{"rootless":' + rootless + ',"seccompEnabled":true,'
                '"seccompProfilePath":"/usr/share/containers/seccomp.json"}}}'
            ),
            stderr="",
        )

    stdout = broker_envelope(invocation.request_sha256)

    def runner(*_args, **_kwargs):
        return SimpleNamespace(
            exit_code=0,
            stdout=stdout,
            stderr=b"",
            stdout_sha256=sha256(stdout),
            stderr_sha256=sha256(b""),
            duration_ms=1,
        )

    with pytest.raises(BrokerExecutionError, match="runtime security changed"):
        execute_isolated_broker(
            **{**inputs, "probe": changing_probe},
            stream_runner=runner,
            cleanup=lambda *_args: True,
        )

    another = make_invocation(packet_sha256="9" * 64)
    with pytest.raises(BrokerExecutionError, match="cleanup could not be attested"):
        execute_isolated_broker(
            **executor_inputs(tmp_path / "cleanup", another),
            stream_runner=runner,
            cleanup=lambda *_args: False,
        )


def test_bounded_broker_process_limits_output_and_stdin() -> None:
    with pytest.raises(BrokerExecutionError, match="process failed"):
        _run_bounded_broker(
            (sys.executable, "-c", "import os; os.write(1, b'x' * 8192)"),
            stdin_bytes=b"{}\n",
            environment={"PATH": os.defpath, "LC_ALL": "C"},
            timeout_seconds=5,
            max_stdin_bytes=1024,
            max_stdout_bytes=1024,
            max_stderr_bytes=1024,
        )
    with pytest.raises(BrokerExecutionError, match="process failed"):
        _run_bounded_broker(
            (sys.executable, "-c", "pass"),
            stdin_bytes=b"x" * 2048,
            environment={"PATH": os.defpath, "LC_ALL": "C"},
            timeout_seconds=5,
            max_stdin_bytes=1024,
            max_stdout_bytes=1024,
            max_stderr_bytes=1024,
        )
    started = time.monotonic()
    with pytest.raises(BrokerExecutionError, match="process failed"):
        _run_bounded_broker(
            (sys.executable, "-c", "import time; time.sleep(5)"),
            stdin_bytes=b"{}\n",
            environment={"PATH": os.defpath, "LC_ALL": "C"},
            timeout_seconds=1,
            max_stdin_bytes=1024,
            max_stdout_bytes=1024,
            max_stderr_bytes=1024,
        )
    assert time.monotonic() - started < 3


def test_noncanonical_envelope_is_rejected_after_cleanup(tmp_path):
    invocation = make_invocation()
    inputs = executor_inputs(tmp_path, invocation)
    cleaned: list[str] = []
    noncanonical = b'{"schema_version": "1.0"}\n'

    def runner(*_args, **_kwargs):
        return SimpleNamespace(
            exit_code=0,
            stdout=noncanonical,
            stderr=b"",
            stdout_sha256=sha256(noncanonical),
            stderr_sha256=sha256(b""),
            duration_ms=1,
        )

    with pytest.raises(BrokerExecutionError, match="canonical envelope"):
        execute_isolated_broker(
            **inputs,
            stream_runner=runner,
            cleanup=lambda _backend, name, _environment: cleaned.append(name) or True,
        )
    assert cleaned == [invocation.container_name]


def test_rootful_docker_requires_userns_and_builtin_seccomp_before_and_after(tmp_path):
    invocation = make_invocation(runtime="docker", rootless=False, user_namespace=True)
    inputs = executor_inputs(tmp_path, invocation)
    probe_count = 0

    def docker_probe(argv, **_kwargs):
        nonlocal probe_count
        probe_count += 1
        return subprocess.CompletedProcess(
            argv,
            0,
            stdout='["name=userns","name=seccomp,profile=builtin"]',
            stderr="",
        )

    stdout = broker_envelope(invocation.request_sha256)

    def runner(*_args, **_kwargs):
        return SimpleNamespace(
            exit_code=0,
            stdout=stdout,
            stderr=b"",
            stdout_sha256=sha256(stdout),
            stderr_sha256=sha256(b""),
            duration_ms=1,
        )

    evidence = execute_isolated_broker(
        **{**inputs, "probe": docker_probe},
        stream_runner=runner,
        cleanup=lambda *_args: True,
    )
    assert probe_count == 2
    assert evidence.runtime_name == "docker"
    assert evidence.runtime_rootless is False
    assert evidence.runtime_user_namespace is True
    assert evidence.runtime_seccomp_profile == "builtin"

    rejected = make_invocation(
        packet_sha256="8" * 64,
        runtime="docker",
        rootless=False,
        user_namespace=True,
    )
    rejected_inputs = executor_inputs(tmp_path / "reject", rejected)

    def no_userns_probe(argv, **_kwargs):
        return subprocess.CompletedProcess(
            argv,
            0,
            stdout='["name=seccomp,profile=builtin"]',
            stderr="",
        )

    with pytest.raises(BrokerExecutionError, match="runtime isolation validation failed"):
        execute_isolated_broker(
            **{**rejected_inputs, "probe": no_userns_probe},
            stream_runner=runner,
        )
    with sqlite3.connect(rejected_inputs["ledger_path"]) as connection:
        assert connection.execute("SELECT COUNT(*) FROM broker_reservations").fetchone() == (0,)
