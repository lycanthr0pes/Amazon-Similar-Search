from __future__ import annotations

import hashlib
import json
import os
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from tools.ai_review.broker_egress_provisioner import BrokerEgressProvisioningError
from tools.ai_review.broker_egress_provisioner import broker_gateway_external_network_name
from tools.ai_review.broker_egress_provisioner import execute_provisioned_isolated_broker
from tools.ai_review.broker_egress_provisioner import provision_broker_egress
from tools.ai_review.broker_egress_provisioner import validate_broker_egress_lifecycle_evidence
from tools.ai_review.broker_egress_provisioner import (
    validate_provisioned_broker_execution_evidence,
)
from tools.ai_review.broker_executor import prepare_broker_ledger
from tools.ai_review.codex_adapter import BROKER_CREDENTIAL_ENV
from tools.ai_review.codex_adapter import IsolatedBrokerInvocation
from tools.ai_review.codex_adapter import broker_container_name
from tools.ai_review.codex_adapter import broker_internal_network_name
from tools.ai_review.codex_adapter import build_isolated_broker_argv
from tools.ai_review.egress_policy import canonical_broker_egress_policy_bytes


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


def other_uid() -> int:
    return 65_534 if os.geteuid() != 65_534 else 65_533


def protected_runtime(path: Path) -> Path:
    path.write_bytes(b"trusted container runtime\n")
    path.chmod(0o555)
    return path


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


def make_invocation() -> IsolatedBrokerInvocation:
    payload = {
        "input": [
            {
                "content": [{"text": "sanitized packet", "type": "input_text"}],
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
    request = canonical_json(payload)
    stdin = request + b"\n"
    packet_sha256 = "a" * 64
    request_sha256 = sha256(request)
    image_digest = "sha256:" + "b" * 64
    name = broker_container_name(
        packet_sha256=packet_sha256,
        request_sha256=request_sha256,
        role="reviewer",
        attempt=1,
    )
    network = broker_internal_network_name(
        packet_sha256=packet_sha256,
        request_sha256=request_sha256,
        role="reviewer",
        attempt=1,
    )
    image = f"registry.invalid/review-broker@{image_digest}"
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
        stdin_text=stdin.decode("utf-8"),
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
        role="reviewer",
        attempt=1,
        reserved_tokens=len(request) + 12_000,
        stdin_sha256=sha256(stdin),
        argv_sha256=sha256(canonical_json(list(argv))),
        boundary_evidence_sha256="c" * 64,
    )


class FakeRuntime:
    def __init__(
        self,
        *,
        extra_internal_peer: bool = False,
        fail_external_cleanup: bool = False,
        gateway_secret: bool = False,
        gateway_mount: bool = False,
    ):
        self.extra_internal_peer = extra_internal_peer
        self.fail_external_cleanup = fail_external_cleanup
        self.gateway_secret = gateway_secret
        self.gateway_mount = gateway_mount
        self.networks: dict[str, dict] = {}
        self.containers: dict[str, dict] = {}
        self.commands: list[tuple[str, ...]] = []

    @staticmethod
    def _result(argv: tuple[str, ...], exit_code: int, stdout: bytes = b"", stderr: bytes = b""):
        return SimpleNamespace(
            argv=argv,
            exit_code=exit_code,
            stdout=stdout,
            stderr=stderr,
            stdout_sha256=sha256(stdout),
            stderr_sha256=sha256(stderr),
            duration_ms=1,
        )

    @staticmethod
    def _option(argv: tuple[str, ...], prefix: str) -> str:
        return next(item.removeprefix(prefix) for item in argv if item.startswith(prefix))

    def __call__(self, argv, **_kwargs):
        command = tuple(argv)
        self.commands.append(command)
        if command[1:3] == ("network", "create"):
            name = command[-1]
            if name in self.networks:
                return self._result(command, 1, stderr=b"collision")
            labels = {
                item.removeprefix("--label=").split("=", 1)[0]: item.split("=", 2)[2]
                for item in command
                if item.startswith("--label=")
            }
            self.networks[name] = {
                "internal": "--internal" in command,
                "labels": labels,
                "containers": set(),
            }
            return self._result(command, 0, stdout=(name + "\n").encode())
        if command[1] == "run":
            name = self._option(command, "--name=")
            network = self._option(command, "--network=")
            labels = {
                item.removeprefix("--label=").split("=", 1)[0]: item.split("=", 2)[2]
                for item in command
                if item.startswith("--label=")
            }
            self.containers[name] = {
                "image": command[-1],
                "labels": labels,
                "networks": {network: {"Aliases": [name]}},
            }
            self.networks[network]["containers"].add(name)
            return self._result(command, 0, stdout=b"1" * 64 + b"\n")
        if command[1:3] == ("network", "connect"):
            network, name = command[-2:]
            alias = command[command.index("--alias") + 1]
            self.networks[network]["containers"].add(name)
            self.containers[name]["networks"][network] = {"Aliases": [name, alias]}
            return self._result(command, 0)
        if command[1:3] in {("container", "ls"), ("network", "ls")}:
            filtered = command[command.index("--filter") + 1]
            name = filtered.removeprefix("name=^").removesuffix("$")
            values = self.containers if command[1] == "container" else self.networks
            stdout = (name + "\n").encode() if name in values else b""
            return self._result(command, 0, stdout)
        if command[1:3] == ("network", "inspect"):
            name = command[-1]
            if name not in self.networks:
                return self._result(command, 1, stderr=b"absent")
            network = self.networks[name]
            members = set(network["containers"])
            if self.extra_internal_peer and network["internal"]:
                members.add("attacker")
            payload = [
                {
                    "Containers": {
                        sha256(member.encode()): {"Name": member} for member in sorted(members)
                    },
                    "Internal": network["internal"],
                    "Labels": network["labels"],
                    "Name": name,
                }
            ]
            return self._result(command, 0, canonical_json(payload))
        if command[1:3] == ("container", "inspect"):
            name = command[-1]
            if name not in self.containers:
                return self._result(command, 1, stderr=b"absent")
            container = self.containers[name]
            environment = ["AI_REVIEW_EGRESS_GATEWAY=1"]
            if self.gateway_secret:
                environment.append("OPENAI_API_KEY=must-never-be-inspected-as-trusted")
            payload = [
                {
                    "Config": {
                        "Entrypoint": ["/opt/ai-review/bin/egress-gateway"],
                        "Env": environment,
                        "Image": container["image"],
                        "Labels": container["labels"],
                        "User": "65532:65532",
                    },
                    "HostConfig": {
                        "Binds": None,
                        "CapDrop": ["ALL"],
                        "Privileged": False,
                        "ReadonlyRootfs": True,
                        "SecurityOpt": ["no-new-privileges"],
                    },
                    "Mounts": ([{"Source": "/candidate/.env"}] if self.gateway_mount else []),
                    "Name": "/" + name,
                    "NetworkSettings": {"Networks": container["networks"]},
                    "State": {"Running": True},
                }
            ]
            return self._result(command, 0, canonical_json(payload))
        if command[1:3] == ("container", "rm"):
            name = command[-1]
            container = self.containers.pop(name, None)
            if container is None:
                return self._result(command, 1)
            for network in container["networks"]:
                self.networks[network]["containers"].discard(name)
            return self._result(command, 0)
        if command[1:3] == ("network", "rm"):
            name = command[-1]
            if self.fail_external_cleanup and "egress" in name:
                return self._result(command, 1)
            if name not in self.networks or self.networks[name]["containers"]:
                return self._result(command, 1)
            del self.networks[name]
            return self._result(command, 0)
        raise AssertionError(command)


def provisioner_inputs(tmp_path: Path, runtime: FakeRuntime) -> dict:
    executable = protected_runtime(tmp_path / "podman")
    invocation = make_invocation()
    gateway_digest = "sha256:" + "7" * 64
    policy = canonical_broker_egress_policy_bytes()
    return {
        "invocation": invocation,
        "gateway_image": f"registry.invalid/review-gateway@{gateway_digest}",
        "expected_broker_gateway_image_digest": gateway_digest,
        "allowlist_policy": policy,
        "expected_broker_allowlist_policy_sha256": sha256(policy),
        "candidate_uid": other_uid(),
        "allow_external_ai": True,
        "allow_isolated_broker": True,
        "which": lambda name: str(executable) if name == "podman" else None,
        "probe": podman_probe,
        "command_runner": runtime,
    }


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


def test_provisioner_creates_measures_and_cleans_unique_gateway_topology(tmp_path: Path) -> None:
    runtime = FakeRuntime()
    inputs = provisioner_inputs(tmp_path, runtime)
    invocation = inputs["invocation"]
    external_network = broker_gateway_external_network_name(invocation)

    session = provision_broker_egress(**inputs)
    with session as active:
        boundary = active.boundary_evidence
        assert boundary.broker_internal_network == invocation.broker_internal_network
        assert active.gateway_external_network == external_network
        assert set(runtime.networks) == {invocation.broker_internal_network, external_network}
        assert len(runtime.containers) == 1

    lifecycle = session.lifecycle_evidence
    assert lifecycle is not None
    assert lifecycle.cleanup_succeeded is True
    assert runtime.networks == {}
    assert runtime.containers == {}
    assert all(Path(command[0]).is_absolute() for command in runtime.commands)
    assert any("--internal" in command for command in runtime.commands)
    assert all(BROKER_CREDENTIAL_ENV not in "\n".join(command) for command in runtime.commands)
    assert all(
        "--mount" not in command and "--volume" not in command for command in runtime.commands
    )
    assert (
        validate_broker_egress_lifecycle_evidence(
            lifecycle,
            invocation=invocation,
            expected_broker_gateway_image_digest=inputs["expected_broker_gateway_image_digest"],
            expected_broker_allowlist_policy_sha256=inputs[
                "expected_broker_allowlist_policy_sha256"
            ],
            candidate_uid=inputs["candidate_uid"],
            which=inputs["which"],
            probe=podman_probe,
            command_runner=runtime,
        )
        == lifecycle
    )


def test_provisioner_rejects_extra_internal_peer_and_cleans_owned_resources(tmp_path: Path) -> None:
    runtime = FakeRuntime(extra_internal_peer=True)
    inputs = provisioner_inputs(tmp_path, runtime)

    with pytest.raises(BrokerEgressProvisioningError) as raised:
        with provision_broker_egress(**inputs):
            pytest.fail("untrusted topology must never be yielded")

    assert str(raised.value) == "broker egress provisioning failed"
    assert runtime.networks == {}
    assert runtime.containers == {}


def test_provisioner_fails_closed_when_cleanup_cannot_be_attested(tmp_path: Path) -> None:
    runtime = FakeRuntime(fail_external_cleanup=True)
    inputs = provisioner_inputs(tmp_path, runtime)

    with pytest.raises(BrokerEgressProvisioningError, match="cleanup failed"):
        with provision_broker_egress(**inputs):
            pass


def test_preflight_collision_is_not_deleted_as_if_owned(tmp_path: Path) -> None:
    runtime = FakeRuntime()
    inputs = provisioner_inputs(tmp_path, runtime)
    network = inputs["invocation"].broker_internal_network
    runtime.networks[network] = {
        "internal": True,
        "labels": {"ai-review.owner-sha256": "foreign"},
        "containers": set(),
    }

    with pytest.raises(BrokerEgressProvisioningError, match="provisioning failed"):
        with provision_broker_egress(**inputs):
            pass

    assert set(runtime.networks) == {network}
    assert not any(command[1:3] == ("network", "rm") for command in runtime.commands)


@pytest.mark.parametrize("attack", ["secret", "mount"])
def test_raw_gateway_inspect_rejects_secret_or_candidate_mount(
    tmp_path: Path,
    attack: str,
) -> None:
    runtime = FakeRuntime(
        gateway_secret=attack == "secret",
        gateway_mount=attack == "mount",
    )
    inputs = provisioner_inputs(tmp_path, runtime)

    with pytest.raises(BrokerEgressProvisioningError) as raised:
        with provision_broker_egress(**inputs):
            pass

    assert str(raised.value) == "broker egress provisioning failed"
    assert "must-never" not in str(raised.value)
    assert runtime.networks == {}
    assert runtime.containers == {}


def test_production_entry_binds_execution_to_lifecycle_and_revalidates_live_absence(
    tmp_path: Path,
) -> None:
    runtime = FakeRuntime()
    provision = provisioner_inputs(tmp_path, runtime)
    invocation = provision["invocation"]
    ledger = tmp_path / "ledger" / "broker.sqlite3"
    ledger.parent.mkdir(mode=0o700)
    ledger_identity = prepare_broker_ledger(ledger, candidate_uid=provision["candidate_uid"])
    envelope = broker_envelope(invocation.request_sha256)

    def stream_runner(*_args, **_kwargs):
        return SimpleNamespace(
            exit_code=0,
            stdout=envelope,
            stderr=b"broker diagnostic\n",
            stdout_sha256=sha256(envelope),
            stderr_sha256=sha256(b"broker diagnostic\n"),
            duration_ms=2,
        )

    evidence = execute_provisioned_isolated_broker(
        **provision,
        expected_packet_sha256=invocation.packet_sha256,
        expected_request_sha256=invocation.request_sha256,
        expected_boundary_evidence_sha256=invocation.boundary_evidence_sha256,
        expected_role=invocation.role,
        expected_attempt=invocation.attempt,
        approved_image_digest=invocation.approved_image_digest,
        expected_argv_sha256=invocation.argv_sha256,
        expected_stdin_sha256=invocation.stdin_sha256,
        credential="unit-test-secret",
        ledger_path=ledger,
        expected_broker_ledger_identity_sha256=ledger_identity,
        broker_packet_reservation_limit=100_000,
        stream_runner=stream_runner,
        cleanup=lambda *_args: True,
    )

    assert evidence.execution.broker_egress_boundary == evidence.egress_lifecycle.boundary_evidence
    assert evidence.execution_evidence_sha256 == evidence.execution.evidence_sha256
    assert evidence.broker_egress_lifecycle_sha256 == evidence.egress_lifecycle.evidence_sha256
    assert runtime.networks == {}
    assert runtime.containers == {}
    assert (
        validate_provisioned_broker_execution_evidence(
            evidence,
            invocation=invocation,
            expected_packet_sha256=invocation.packet_sha256,
            expected_request_sha256=invocation.request_sha256,
            expected_boundary_evidence_sha256=invocation.boundary_evidence_sha256,
            expected_role=invocation.role,
            expected_attempt=invocation.attempt,
            approved_image_digest=invocation.approved_image_digest,
            expected_descriptor_argv_sha256=invocation.argv_sha256,
            expected_stdin_sha256=invocation.stdin_sha256,
            expected_broker_gateway_image_digest=provision["expected_broker_gateway_image_digest"],
            expected_broker_allowlist_policy_sha256=provision[
                "expected_broker_allowlist_policy_sha256"
            ],
            ledger_path=ledger,
            expected_broker_ledger_identity_sha256=ledger_identity,
            broker_packet_reservation_limit=100_000,
            candidate_uid=provision["candidate_uid"],
            which=provision["which"],
            probe=podman_probe,
            command_runner=runtime,
        )
        == evidence
    )


def test_post_execution_peer_swap_is_detected_before_cleanup(tmp_path: Path) -> None:
    runtime = FakeRuntime()
    provision = provisioner_inputs(tmp_path, runtime)
    invocation = provision["invocation"]
    ledger = tmp_path / "ledger" / "broker.sqlite3"
    ledger.parent.mkdir(mode=0o700)
    ledger_identity = prepare_broker_ledger(ledger, candidate_uid=provision["candidate_uid"])
    envelope = broker_envelope(invocation.request_sha256)

    def stream_runner(*_args, **_kwargs):
        runtime.networks[invocation.broker_internal_network]["containers"].add("attacker")
        return SimpleNamespace(
            exit_code=0,
            stdout=envelope,
            stderr=b"",
            stdout_sha256=sha256(envelope),
            stderr_sha256=sha256(b""),
            duration_ms=1,
        )

    with pytest.raises(BrokerEgressProvisioningError, match="provisioned broker execution failed"):
        execute_provisioned_isolated_broker(
            **provision,
            expected_packet_sha256=invocation.packet_sha256,
            expected_request_sha256=invocation.request_sha256,
            expected_boundary_evidence_sha256=invocation.boundary_evidence_sha256,
            expected_role=invocation.role,
            expected_attempt=invocation.attempt,
            approved_image_digest=invocation.approved_image_digest,
            expected_argv_sha256=invocation.argv_sha256,
            expected_stdin_sha256=invocation.stdin_sha256,
            credential="unit-test-secret",
            ledger_path=ledger,
            expected_broker_ledger_identity_sha256=ledger_identity,
            broker_packet_reservation_limit=100_000,
            stream_runner=stream_runner,
            cleanup=lambda *_args: True,
        )
