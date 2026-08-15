from __future__ import annotations

import hashlib
import json
import os
import subprocess
from pathlib import Path

import pytest

from tools.ai_review.broker_phase_protocol import BrokerRuntimeBinding
from tools.ai_review.broker_phase_protocol import PreparedBrokerBatch
from tools.ai_review.broker_phase_protocol import canonical_prepared_broker_batch_bytes
from tools.ai_review.broker_phase_protocol import finalize_provisioned_broker_execution
from tools.ai_review.broker_phase_protocol import prepare_provisioned_broker_execution
from tools.ai_review.broker_outer_executor import OuterBrokerExecutionError
from tools.ai_review.broker_outer_executor import _base_environment
from tools.ai_review.broker_outer_executor import _execute_prepared_broker_outer
from tools.ai_review.broker_outer_executor import measure_broker_outer_runtime
from tools.ai_review.broker_outer_executor import prepare_broker_outer_ledger
from tools.ai_review.codex_adapter import BROKER_CREDENTIAL_ENV
from tools.ai_review.codex_adapter import IsolatedBrokerInvocation
from tools.ai_review.codex_adapter import broker_container_name
from tools.ai_review.codex_adapter import broker_internal_network_name
from tools.ai_review.codex_adapter import build_isolated_broker_argv
from tools.ai_review.egress_policy import canonical_broker_egress_policy_bytes
from tools.ai_review.pricing_policy import APPROVED_OPENAI_PRICING_POLICY
from tools.ai_review.pricing_policy import canonical_openai_pricing_policy_bytes
from tests.test_ai_review_broker_egress_provisioner import FakeRuntime
from tests.test_ai_review_broker_egress_provisioner import broker_envelope
from tests.test_ai_review_broker_egress_provisioner import podman_probe


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _invocation(role: str) -> IsolatedBrokerInvocation:
    effort = "high" if role == "reviewer" else "xhigh"
    payload = {
        "input": [{"content": [{"text": role, "type": "input_text"}], "role": "user"}],
        "max_output_tokens": 12_000,
        "model": "gpt-5.6-sol",
        "service_tier": "default",
        "reasoning": {"effort": effort, "summary": "none"},
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
    request = _canonical(payload)
    stdin = request + b"\n"
    packet_sha256 = "a" * 64
    request_sha256 = _sha256(request)
    image_digest = "sha256:" + "b" * 64
    image = f"registry.invalid/review-broker@{image_digest}"
    name = broker_container_name(
        packet_sha256=packet_sha256,
        request_sha256=request_sha256,
        role=role,
        attempt=1,
    )
    network = broker_internal_network_name(
        packet_sha256=packet_sha256,
        request_sha256=request_sha256,
        role=role,
        attempt=1,
    )
    argv = build_isolated_broker_argv(
        container_runtime="podman",
        image=image,
        container_name=name,
        broker_internal_network=network,
        runtime_rootless=True,
        runtime_user_namespace=True,
    )
    return IsolatedBrokerInvocation(
        argv=argv,
        stdin_text=stdin.decode(),
        container_runtime="podman",
        runtime_rootless=True,
        runtime_user_namespace=True,
        container_name=name,
        broker_internal_network=network,
        image=image,
        approved_image_digest=image_digest,
        credential_env_name=BROKER_CREDENTIAL_ENV,
        packet_sha256=packet_sha256,
        request_sha256=request_sha256,
        role=role,
        attempt=1,
        reserved_tokens=len(request) + 12_000,
        stdin_sha256=_sha256(stdin),
        argv_sha256=_sha256(_canonical(list(argv))),
        boundary_evidence_sha256="c" * 64,
    )


def _runtime_binding() -> BrokerRuntimeBinding:
    payload = {
        "name": "podman",
        "rootless": True,
        "seccomp_profile": "/usr/share/containers/seccomp.json",
        "user_namespace": True,
    }
    return BrokerRuntimeBinding(
        name="podman",
        executable_sha256="d" * 64,
        environment_sha256=_sha256(_canonical(_base_environment("podman"))),
        rootless=True,
        user_namespace=True,
        seccomp_profile="/usr/share/containers/seccomp.json",
        security_evidence_sha256=_sha256(_canonical(payload) + b"\n"),
    )


def _prepare_inputs() -> dict[str, object]:
    policy = canonical_broker_egress_policy_bytes()
    gateway_digest = "sha256:" + "7" * 64
    return {
        "workflow_id": "1" * 64,
        "phase_request_sha256": "2" * 64,
        "task_sha256": "3" * 64,
        "runtime_manifest_sha256": "4" * 64,
        "candidate_snapshot_sha256": "5" * 64,
        "review_packet_sha256": "a" * 64,
        "invocations": (_invocation("adversary"), _invocation("reviewer")),
        "runtime": _runtime_binding(),
        "gateway_image": f"registry.invalid/review-gateway@{gateway_digest}",
        "broker_gateway_image_digest": gateway_digest,
        "allowlist_policy": policy,
        "broker_allowlist_policy_sha256": _sha256(policy),
        "pricing_policy": canonical_openai_pricing_policy_bytes(),
        "broker_pricing_policy_sha256": APPROVED_OPENAI_PRICING_POLICY.sha256,
        "broker_ledger_identity_sha256": "8" * 64,
        "broker_packet_reservation_limit": 544_000,
        "broker_packet_cost_limit_microusd": 4_540_000,
        "candidate_uid": 65_534 if os.geteuid() != 65_534 else 65_533,
    }


def _prepare() -> PreparedBrokerBatch:
    return prepare_provisioned_broker_execution(**_prepare_inputs())  # type: ignore[arg-type]


def test_prepare_emits_exact_two_role_canonical_self_bound_descriptors() -> None:
    prepared = _prepare()
    assert tuple(run.role for run in prepared.runs) == ("reviewer", "adversary")
    raw = canonical_prepared_broker_batch_bytes(prepared)
    assert PreparedBrokerBatch.parse(raw) == prepared
    assert _sha256(raw) == prepared.canonical_sha256
    encoded = json.loads(raw)
    assert encoded["batch_sha256"] == prepared.batch_sha256
    assert "test-credential" not in raw.decode()
    assert "credential" not in encoded
    assert not any(key in encoded for key in ("candidate_path", "mount", "socket"))


def test_prepare_rejects_missing_duplicate_or_cross_packet_roles() -> None:
    inputs = _prepare_inputs()
    inputs["invocations"] = (_invocation("reviewer"),)
    with pytest.raises(ValueError, match="reviewer and adversary"):
        prepare_provisioned_broker_execution(**inputs)  # type: ignore[arg-type]


def test_stdlib_outer_broker_executor_imports_under_i_s(tmp_path: Path) -> None:
    module = Path(__file__).parents[1] / "tools" / "ai_review" / "broker_outer_executor.py"
    script = (
        "import importlib.util,sys;"
        "spec=importlib.util.spec_from_file_location('broker_outer',sys.argv[1]);"
        "value=importlib.util.module_from_spec(spec);sys.modules[spec.name]=value;"
        "spec.loader.exec_module(value);"
        "assert 'pydantic' not in sys.modules;assert 'cryptography' not in sys.modules"
    )
    result = subprocess.run(
        ["/usr/bin/python3", "-I", "-S", "-c", script, str(module)],
        cwd=tmp_path,
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
        env={"PATH": os.defpath, "LC_ALL": "C"},
    )
    assert result.returncode == 0, result.stderr


def _prepared_outer_fixture(tmp_path: Path):
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
        candidate_uid=candidate_uid,  # type: ignore[arg-type]
    )
    prepared = prepare_provisioned_broker_execution(**inputs)  # type: ignore[arg-type]
    raw_prepared = canonical_prepared_broker_batch_bytes(prepared)
    fake = FakeRuntime()
    return inputs, prepared, raw_prepared, ledger_path, runtime_path, fake


def test_outer_executes_exact_batch_reserves_atomically_and_rejects_replay(
    tmp_path: Path,
) -> None:
    inputs, prepared, raw_prepared, ledger_path, runtime_path, fake = _prepared_outer_fixture(
        tmp_path
    )

    def stream_runner(_argv, *, stdin_bytes, **_kwargs):
        stdout = broker_envelope(_sha256(stdin_bytes[:-1]))
        return FakeRuntime._result(tuple(_argv), 0, stdout=stdout)

    raw = _execute_prepared_broker_outer(
        raw_prepared,
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
    evidence = json.loads(raw)
    assert [run["role"] for run in evidence["runs"]] == ["reviewer", "adversary"]
    assert len(evidence["runs"][-1]["reservation"]["records"]) == 2
    assert len(evidence["final_ledger"]["records"]) == 2
    assert "sk-test" not in raw.decode()
    assert fake.networks == {}
    assert fake.containers == {}
    with pytest.raises(OuterBrokerExecutionError, match="reservation"):
        _execute_prepared_broker_outer(
            raw_prepared,
            credentials={"reviewer": "secret-one", "adversary": "secret-two"},
            ledger_path=ledger_path,
            runtime_executable=runtime_path,
            require_two=True,
            runner=fake,
            stream_runner=stream_runner,
            probe=podman_probe,
            broker_cleanup=lambda *_args: True,
        )
    ledger_path.unlink()
    finalized = finalize_provisioned_broker_execution(
        prepared,
        raw,
        allowlist_policy=inputs["allowlist_policy"],  # type: ignore[arg-type]
        pricing_policy=inputs["pricing_policy"],  # type: ignore[arg-type]
    )
    assert tuple(item.execution.role for item in finalized) == ("reviewer", "adversary")
    assert (
        finalized[-1].execution.cumulative_reserved_tokens
        > finalized[0].execution.cumulative_reserved_tokens
    )

    forged = json.loads(raw)
    forged["runs"][0]["unknown"] = True
    forged_raw = _canonical(forged)
    with pytest.raises(ValueError, match="unknown|binding"):
        finalize_provisioned_broker_execution(
            prepared,
            forged_raw,
            allowlist_policy=inputs["allowlist_policy"],  # type: ignore[arg-type]
            pricing_policy=inputs["pricing_policy"],  # type: ignore[arg-type]
        )


def test_finalize_rejects_tampered_frozen_final_ledger_without_live_host_path(
    tmp_path: Path,
) -> None:
    inputs, prepared, raw_prepared, ledger_path, runtime_path, fake = _prepared_outer_fixture(
        tmp_path
    )

    def stream_runner(argv, *, stdin_bytes, **_kwargs):
        return FakeRuntime._result(
            tuple(argv),
            0,
            stdout=broker_envelope(_sha256(stdin_bytes[:-1])),
        )

    raw = _execute_prepared_broker_outer(
        raw_prepared,
        credentials={"reviewer": "secret-one", "adversary": "secret-two"},
        ledger_path=ledger_path,
        runtime_executable=runtime_path,
        require_two=True,
        runner=fake,
        stream_runner=stream_runner,
        probe=podman_probe,
        broker_cleanup=lambda *_args: True,
    )
    ledger_path.unlink()
    forged = json.loads(raw)
    forged["final_ledger"]["records"][0]["reserved_tokens"] += 1
    unsigned = {key: value for key, value in forged.items() if key != "outer_evidence_sha256"}
    forged["outer_evidence_sha256"] = _sha256(
        b"amazon-explorer-outer-broker-batch-v1\0" + _canonical(unsigned)
    )

    with pytest.raises(ValueError, match="ledger"):
        finalize_provisioned_broker_execution(
            prepared,
            _canonical(forged),
            allowlist_policy=inputs["allowlist_policy"],  # type: ignore[arg-type]
            pricing_policy=inputs["pricing_policy"],  # type: ignore[arg-type]
        )


def test_outer_always_attempts_named_broker_cleanup_after_bounded_process_failure(
    tmp_path: Path,
) -> None:
    _inputs, _prepared, raw_prepared, ledger_path, runtime_path, fake = _prepared_outer_fixture(
        tmp_path
    )
    cleaned: list[str] = []

    def fail_after_start(*_args, **_kwargs):
        raise TimeoutError("candidate-controlled diagnostic must not escape")

    def cleanup(_runtime, name, _environment):
        cleaned.append(name)
        return True

    with pytest.raises(OuterBrokerExecutionError) as raised:
        _execute_prepared_broker_outer(
            raw_prepared,
            credentials={"reviewer": "secret-one", "adversary": "secret-two"},
            ledger_path=ledger_path,
            runtime_executable=runtime_path,
            require_two=True,
            runner=fake,
            stream_runner=fail_after_start,
            probe=podman_probe,
            broker_cleanup=cleanup,
        )

    assert len(cleaned) == 1
    assert "candidate-controlled" not in str(raised.value)
    assert fake.networks == {}
    assert fake.containers == {}


def test_prepare_broker_outer_ledger_creates_exact_private_schema_once(tmp_path: Path) -> None:
    parent = tmp_path / "outer-ledger"
    parent.mkdir(mode=0o700)
    ledger = parent / "broker.sqlite3"
    candidate_uid = 65_534 if os.geteuid() != 65_534 else 65_533

    module = Path(__file__).parents[1] / "tools" / "ai_review" / "broker_outer_executor.py"
    initialize = (
        "import importlib.util,pathlib,sys;"
        "spec=importlib.util.spec_from_file_location('broker_outer',sys.argv[1]);"
        "value=importlib.util.module_from_spec(spec);sys.modules[spec.name]=value;"
        "spec.loader.exec_module(value);"
        "print(value.prepare_broker_outer_ledger("
        "pathlib.Path(sys.argv[2]),candidate_uid=int(sys.argv[3])))"
    )
    initialized = subprocess.run(
        [
            "/usr/bin/python3",
            "-I",
            "-S",
            "-c",
            initialize,
            str(module),
            str(ledger),
            str(candidate_uid),
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
        env={"PATH": os.defpath, "LC_ALL": "C"},
    )
    assert initialized.returncode == 0, initialized.stderr
    identity = initialized.stdout.strip()

    assert len(identity) == 64
    assert ledger.stat().st_mode & 0o777 == 0o600
    script = (
        "import sqlite3,sys;"
        "c=sqlite3.connect('file:'+sys.argv[1]+'?mode=ro',uri=True);"
        "assert c.execute('PRAGMA integrity_check').fetchone()==('ok',);"
        'assert c.execute("SELECT strict FROM pragma_table_list '
        "WHERE name='broker_reservations'\").fetchone()==(1,);"
        "assert c.execute('SELECT COUNT(*) FROM broker_reservations').fetchone()==(0,)"
    )
    result = subprocess.run(
        ["/usr/bin/python3", "-I", "-S", "-c", script, str(ledger)],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
        env={"PATH": os.defpath, "LC_ALL": "C"},
    )
    assert result.returncode == 0, result.stderr
    with pytest.raises(OuterBrokerExecutionError, match="already exists"):
        prepare_broker_outer_ledger(ledger, candidate_uid=candidate_uid)


def test_prepare_broker_outer_ledger_rejects_public_parent_and_symlink(
    tmp_path: Path,
) -> None:
    candidate_uid = 65_534 if os.geteuid() != 65_534 else 65_533
    public = tmp_path / "public"
    public.mkdir(mode=0o755)
    with pytest.raises(OuterBrokerExecutionError, match="parent"):
        prepare_broker_outer_ledger(public / "broker.sqlite3", candidate_uid=candidate_uid)
    protected = tmp_path / "protected"
    protected.mkdir(mode=0o700)
    target = protected / "target.sqlite3"
    target.write_bytes(b"not sqlite")
    link = protected / "broker.sqlite3"
    link.symlink_to(target)
    with pytest.raises(OuterBrokerExecutionError, match="already exists"):
        prepare_broker_outer_ledger(link, candidate_uid=candidate_uid)


def test_prepare_broker_outer_ledger_removes_its_exact_partial_file_on_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from tools.ai_review import broker_outer_executor

    parent = tmp_path / "protected"
    parent.mkdir(mode=0o700)
    ledger = parent / "broker.sqlite3"
    candidate_uid = 65_534 if os.geteuid() != 65_534 else 65_533

    def fail_connect(*_args, **_kwargs):
        raise OSError("diagnostic must remain generic")

    monkeypatch.setattr(broker_outer_executor.sqlite3, "connect", fail_connect)
    with pytest.raises(OuterBrokerExecutionError, match="initialization") as raised:
        prepare_broker_outer_ledger(ledger, candidate_uid=candidate_uid)

    assert "diagnostic" not in str(raised.value)
    assert list(parent.iterdir()) == []


def _write_fake_podman(path: Path, *, seccomp_enabled: bool = True) -> None:
    payload = {
        "host": {
            "security": {
                "rootless": True,
                "seccompEnabled": seccomp_enabled,
                "seccompProfilePath": "/usr/share/containers/seccomp.json",
            }
        }
    }
    path.write_text(
        f"#!/usr/bin/python3\nimport json\nprint(json.dumps({payload!r}, sort_keys=True))\n",
        encoding="utf-8",
    )
    path.chmod(0o555)


def test_measure_broker_outer_runtime_returns_path_free_canonical_binding_under_i_s(
    tmp_path: Path,
) -> None:
    runtime = tmp_path / "podman"
    _write_fake_podman(runtime)
    candidate_uid = 65_534 if os.geteuid() != 65_534 else 65_533
    module = Path(__file__).parents[1] / "tools" / "ai_review" / "broker_outer_executor.py"
    script = (
        "import importlib.util,pathlib,sys;"
        "spec=importlib.util.spec_from_file_location('broker_outer',sys.argv[1]);"
        "value=importlib.util.module_from_spec(spec);sys.modules[spec.name]=value;"
        "spec.loader.exec_module(value);"
        "sys.stdout.buffer.write(value.measure_broker_outer_runtime("
        "pathlib.Path(sys.argv[2]),int(sys.argv[3])))"
    )
    measured = subprocess.run(
        [
            "/usr/bin/python3",
            "-I",
            "-S",
            "-c",
            script,
            str(module),
            str(runtime),
            str(candidate_uid),
        ],
        check=False,
        capture_output=True,
        timeout=10,
        env={"PATH": os.defpath, "LC_ALL": "C"},
    )

    assert measured.returncode == 0, measured.stderr.decode()
    payload = json.loads(measured.stdout)
    assert measured.stdout == _canonical(payload)
    assert set(payload) == {
        "environment_sha256",
        "executable_sha256",
        "name",
        "rootless",
        "seccomp_profile",
        "security_evidence_sha256",
        "user_namespace",
    }
    assert payload["name"] == "podman"
    assert payload["rootless"] is True
    assert payload["user_namespace"] is True
    assert str(runtime).encode() not in measured.stdout


def test_measure_broker_outer_runtime_rejects_inactive_seccomp(tmp_path: Path) -> None:
    runtime = tmp_path / "podman"
    _write_fake_podman(runtime, seccomp_enabled=False)
    candidate_uid = 65_534 if os.geteuid() != 65_534 else 65_533

    with pytest.raises(OuterBrokerExecutionError, match="security"):
        measure_broker_outer_runtime(runtime, candidate_uid)
