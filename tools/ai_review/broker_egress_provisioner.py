"""Root-owned lifecycle for the broker's one-shot, fixed-destination egress gateway.

The broker executor deliberately cannot infer a network boundary from caller booleans.  This
module creates uniquely named networks with the already measured absolute container runtime,
starts the pinned credential-free gateway, parses raw runtime inspect JSON, and derives the only
``EgressBoundaryEvidence`` accepted by the production wrapper.  It then re-inspects and removes
the gateway and both networks on every path.  No external API client exists here.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import secrets
import subprocess
import time
from dataclasses import dataclass
from dataclasses import replace
from pathlib import Path
from typing import Any
from typing import Callable

from tools.ai_review.broker_executor import BrokerExecutionEvidence
from tools.ai_review.broker_executor import BrokerExecutionError
from tools.ai_review.broker_executor import EgressBoundaryEvidence
from tools.ai_review.broker_executor import MAX_BROKER_STDERR_BYTES
from tools.ai_review.broker_executor import MAX_BROKER_STDIN_BYTES
from tools.ai_review.broker_executor import MAX_BROKER_STDOUT_BYTES
from tools.ai_review.broker_executor import _BrokerProcessResult
from tools.ai_review.broker_executor import _cleanup_named_container
from tools.ai_review.broker_executor import _detect_exact_backend
from tools.ai_review.broker_executor import _run_bounded_broker
from tools.ai_review.broker_executor import _same_backend
from tools.ai_review.broker_executor import _system_which
from tools.ai_review.broker_executor import broker_egress_boundary_sha256
from tools.ai_review.broker_executor import validate_broker_execution_evidence
from tools.ai_review.codex_adapter import BROKER_CONTAINER_GID
from tools.ai_review.codex_adapter import BROKER_CONTAINER_UID
from tools.ai_review.codex_adapter import BROKER_CREDENTIAL_ENV
from tools.ai_review.codex_adapter import IsolatedBrokerInvocation
from tools.ai_review.egress_policy import EgressPolicyError
from tools.ai_review.egress_policy import validate_broker_egress_policy
from tools.ai_review.offline_runner import ContainerBackend
from tools.ai_review.offline_runner import _base_host_environment
from tools.ai_review.pricing_policy import APPROVED_OPENAI_PRICING_POLICY
from tools.ai_review.pricing_policy import DEFAULT_PACKET_COST_LIMIT_MICROUSD
from tools.ai_review.pricing_policy import canonical_openai_pricing_policy_bytes


GATEWAY_ENTRYPOINT = "/opt/ai-review/bin/egress-gateway"
GATEWAY_ALIAS = "ai-review-egress-gateway"
GATEWAY_PORT = 8443
GATEWAY_EXTERNAL_NETWORK_PREFIX = "ai-review-egress-net-"
MAX_RUNTIME_INSPECT_BYTES = 64_000
MAX_RUNTIME_COMMAND_STDERR_BYTES = 16_000
MAX_RUNTIME_COMMAND_SECONDS = 30
_EXTERNAL_NETWORK_DOMAIN = b"amazon-explorer-broker-external-network-v1\0"
_OWNER_DOMAIN = b"amazon-explorer-broker-egress-owner-v1\0"
_SESSION_DOMAIN = b"amazon-explorer-broker-egress-session-v1\0"
_COMMAND_DOMAIN = b"amazon-explorer-broker-egress-command-v1\0"
_LIFECYCLE_DOMAIN = b"amazon-explorer-broker-egress-lifecycle-v1\0"
_PROVISIONED_EXECUTION_DOMAIN = b"amazon-explorer-provisioned-broker-execution-v1\0"
_EXTERNAL_NETWORK_RE = re.compile(r"^ai-review-egress-net-[0-9a-f]{24}$")
_PINNED_IMAGE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/:+-]*@(sha256:[0-9a-f]{64})$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_FORBIDDEN_GATEWAY_ENV = {
    "all_proxy",
    "aws_ca_bundle",
    "curl_ca_bundle",
    "http_proxy",
    "https_proxy",
    "ld_audit",
    "ld_library_path",
    "ld_preload",
    "netrc",
    "no_proxy",
    "openai_api_key",
    "openai_base_url",
    "pythonhome",
    "pythonpath",
    "requests_ca_bundle",
    "ssl_cert_dir",
    "ssl_cert_file",
}


class BrokerEgressProvisioningError(RuntimeError):
    """A generic lifecycle failure which never contains inspect or credential content."""


@dataclass(frozen=True)
class RuntimeCommandEvidence:
    """One exact, bounded container-runtime command and its raw streams."""

    argv: tuple[str, ...]
    exit_code: int
    stdout: bytes
    stderr: bytes
    stdout_sha256: str
    stderr_sha256: str
    duration_ms: int
    evidence_sha256: str


@dataclass(frozen=True)
class BrokerEgressLifecycleEvidence:
    """Measured create/inspect/post-inspect/cleanup lifecycle for one broker attempt."""

    schema_version: str
    runtime_name: str
    runtime_executable: Path
    runtime_pre_sha256: str
    runtime_pre_security_sha256: str
    runtime_post_sha256: str
    runtime_post_security_sha256: str
    runtime_rootless: bool
    runtime_user_namespace: bool
    runtime_seccomp_profile: str
    environment_sha256: str
    session_sha256: str
    broker_internal_network: str
    gateway_external_network: str
    gateway_container_name: str
    gateway_image: str
    broker_gateway_image_digest: str
    broker_allowlist_policy_sha256: str
    boundary_evidence: EgressBoundaryEvidence
    gateway_external_network_inspect: bytes
    gateway_external_network_inspect_sha256: str
    provisioning_commands: tuple[RuntimeCommandEvidence, ...]
    post_execution_inspect_commands: tuple[RuntimeCommandEvidence, ...]
    cleanup_commands: tuple[RuntimeCommandEvidence, ...]
    post_cleanup_absence_commands: tuple[RuntimeCommandEvidence, ...]
    started_unix_ns: int
    duration_ms: int
    cleanup_succeeded: bool
    evidence_sha256: str


@dataclass(frozen=True)
class ProvisionedBrokerExecutionEvidence:
    """Production evidence binding broker output to its measured egress lifecycle."""

    schema_version: str
    execution: BrokerExecutionEvidence
    egress_lifecycle: BrokerEgressLifecycleEvidence
    execution_evidence_sha256: str
    broker_egress_lifecycle_sha256: str
    evidence_sha256: str


def _canonical_json(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise BrokerEgressProvisioningError("broker egress evidence validation failed") from exc


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _is_sha256(value: object) -> bool:
    return isinstance(value, str) and _SHA256_RE.fullmatch(value) is not None


def _invocation_values(invocation: IsolatedBrokerInvocation) -> tuple[str, str, str, str]:
    try:
        measured = IsolatedBrokerInvocation(**vars(invocation))
    except (TypeError, ValueError, UnicodeError) as exc:
        raise BrokerEgressProvisioningError("broker egress invocation validation failed") from exc
    if measured != invocation:
        raise BrokerEgressProvisioningError("broker egress invocation validation failed")
    return (
        measured.packet_sha256,
        measured.request_sha256,
        measured.role,
        str(measured.attempt),
    )


def _domain_name(prefix: str, domain: bytes, values: tuple[str, ...]) -> str:
    digest = hashlib.sha256(domain)
    for value in values:
        raw = value.encode("ascii")
        digest.update(len(raw).to_bytes(4, "big"))
        digest.update(raw)
    return prefix + digest.hexdigest()[:24]


def broker_gateway_external_network_name(invocation: IsolatedBrokerInvocation) -> str:
    """Return the domain-separated external network name for one exact invocation."""

    return _domain_name(
        GATEWAY_EXTERNAL_NETWORK_PREFIX,
        _EXTERNAL_NETWORK_DOMAIN,
        _invocation_values(invocation),
    )


def _gateway_name(invocation: IsolatedBrokerInvocation) -> str:
    return "ai-review-egress-gateway-" + invocation.broker_internal_network.rsplit("-", 1)[-1][-16:]


def _owner_sha256(invocation: IsolatedBrokerInvocation) -> str:
    return _sha256(_OWNER_DOMAIN + _canonical_json(list(_invocation_values(invocation))))


def _new_session_sha256() -> str:
    return _sha256(_SESSION_DOMAIN + secrets.token_bytes(32))


def _environment_sha256(environment: dict[str, str]) -> str:
    return _sha256(_canonical_json(environment))


def _command_evidence_sha256(
    *,
    argv: tuple[str, ...],
    exit_code: int,
    stdout: bytes,
    stderr: bytes,
    duration_ms: int,
) -> str:
    payload = {
        "argv": list(argv),
        "duration_ms": duration_ms,
        "exit_code": exit_code,
        "stderr_base64": base64.b64encode(stderr).decode("ascii"),
        "stderr_sha256": _sha256(stderr),
        "stdout_base64": base64.b64encode(stdout).decode("ascii"),
        "stdout_sha256": _sha256(stdout),
    }
    return _sha256(_COMMAND_DOMAIN + _canonical_json(payload))


def _measure_command_result(
    raw: object,
    *,
    argv: tuple[str, ...],
    observed_duration_ms: int,
) -> RuntimeCommandEvidence:
    try:
        exit_code = raw.exit_code  # type: ignore[attr-defined]
        stdout = raw.stdout  # type: ignore[attr-defined]
        stderr = raw.stderr  # type: ignore[attr-defined]
        duration_ms = raw.duration_ms  # type: ignore[attr-defined]
        reported_stdout_sha256 = raw.stdout_sha256  # type: ignore[attr-defined]
        reported_stderr_sha256 = raw.stderr_sha256  # type: ignore[attr-defined]
    except (AttributeError, TypeError, ValueError) as exc:
        raise BrokerEgressProvisioningError("broker egress runtime command failed") from exc
    if (
        isinstance(exit_code, bool)
        or not isinstance(exit_code, int)
        or not isinstance(stdout, bytes)
        or not isinstance(stderr, bytes)
        or len(stdout) > MAX_RUNTIME_INSPECT_BYTES
        or len(stderr) > MAX_RUNTIME_COMMAND_STDERR_BYTES
        or isinstance(duration_ms, bool)
        or not isinstance(duration_ms, int)
        or not 0 <= duration_ms <= MAX_RUNTIME_COMMAND_SECONDS * 1_000
        or not 0 <= observed_duration_ms <= MAX_RUNTIME_COMMAND_SECONDS * 1_000
        or reported_stdout_sha256 != _sha256(stdout)
        or reported_stderr_sha256 != _sha256(stderr)
    ):
        raise BrokerEgressProvisioningError("broker egress runtime command failed")
    measured_duration = max(duration_ms, observed_duration_ms)
    return RuntimeCommandEvidence(
        argv=argv,
        exit_code=exit_code,
        stdout=stdout,
        stderr=stderr,
        stdout_sha256=_sha256(stdout),
        stderr_sha256=_sha256(stderr),
        duration_ms=measured_duration,
        evidence_sha256=_command_evidence_sha256(
            argv=argv,
            exit_code=exit_code,
            stdout=stdout,
            stderr=stderr,
            duration_ms=measured_duration,
        ),
    )


def _run_runtime_command(
    argv: tuple[str, ...],
    *,
    environment: dict[str, str],
    runner: Callable[..., object],
) -> RuntimeCommandEvidence:
    if (
        not argv
        or not Path(argv[0]).is_absolute()
        or any(not value or any(character in value for character in "\x00\r\n") for value in argv)
        or any(value in {"--mount", "--volume", "-v"} for value in argv)
        or any(value.startswith(("--mount=", "--volume=")) for value in argv)
        or any(BROKER_CREDENTIAL_ENV in value for value in argv)
    ):
        raise BrokerEgressProvisioningError("broker egress runtime command failed")
    started = time.monotonic_ns()
    try:
        raw = runner(
            argv,
            stdin_bytes=b"",
            environment=environment,
            timeout_seconds=MAX_RUNTIME_COMMAND_SECONDS,
            max_stdin_bytes=2,
            max_stdout_bytes=MAX_RUNTIME_INSPECT_BYTES,
            max_stderr_bytes=MAX_RUNTIME_COMMAND_STDERR_BYTES,
        )
    except Exception as exc:
        raise BrokerEgressProvisioningError("broker egress runtime command failed") from exc
    observed = max(0, (time.monotonic_ns() - started) // 1_000_000)
    return _measure_command_result(raw, argv=argv, observed_duration_ms=observed)


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise BrokerEgressProvisioningError("broker egress inspect validation failed")
        value[key] = item
    return value


def _parse_one_inspect(raw: bytes) -> tuple[dict[str, Any], bytes]:
    if not isinstance(raw, bytes) or not 2 <= len(raw) <= MAX_RUNTIME_INSPECT_BYTES:
        raise BrokerEgressProvisioningError("broker egress inspect validation failed")
    try:
        payload = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=_reject_duplicate_keys,
        )
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise BrokerEgressProvisioningError("broker egress inspect validation failed") from exc
    if not isinstance(payload, list) or len(payload) != 1 or not isinstance(payload[0], dict):
        raise BrokerEgressProvisioningError("broker egress inspect validation failed")
    return payload[0], _canonical_json(payload)


def _dict_field(value: dict[str, Any], *names: str) -> dict[str, Any]:
    for name in names:
        item = value.get(name)
        if isinstance(item, dict):
            return item
    raise BrokerEgressProvisioningError("broker egress inspect validation failed")


def _value_field(value: dict[str, Any], *names: str) -> Any:
    for name in names:
        if name in value:
            return value[name]
    raise BrokerEgressProvisioningError("broker egress inspect validation failed")


def _network_member_names(payload: dict[str, Any]) -> set[str]:
    containers = _value_field(payload, "Containers", "containers")
    if not isinstance(containers, dict):
        raise BrokerEgressProvisioningError("broker egress inspect validation failed")
    names: set[str] = set()
    for item in containers.values():
        if not isinstance(item, dict):
            raise BrokerEgressProvisioningError("broker egress inspect validation failed")
        name = item.get("Name", item.get("name"))
        if not isinstance(name, str) or not name or name in names:
            raise BrokerEgressProvisioningError("broker egress inspect validation failed")
        names.add(name.lstrip("/"))
    return names


def _validate_network_inspect(
    raw: bytes,
    *,
    expected_name: str,
    expected_internal: bool,
    expected_gateway_name: str,
    owner_sha256: str,
    session_sha256: str,
    kind: str,
) -> bytes:
    payload, canonical = _parse_one_inspect(raw)
    name = _value_field(payload, "Name", "name")
    internal = _value_field(payload, "Internal", "internal")
    labels = _dict_field(payload, "Labels", "labels")
    if (
        name != expected_name
        or internal is not expected_internal
        or labels.get("ai-review.owner-sha256") != owner_sha256
        or labels.get("ai-review.session-sha256") != session_sha256
        or labels.get("ai-review.kind") != kind
        or _network_member_names(payload) != {expected_gateway_name}
    ):
        raise BrokerEgressProvisioningError("broker egress inspect validation failed")
    return canonical


def _container_networks(payload: dict[str, Any]) -> dict[str, Any]:
    network_settings = _dict_field(payload, "NetworkSettings")
    return _dict_field(network_settings, "Networks", "networks")


def _validate_gateway_inspect(
    raw: bytes,
    *,
    gateway_name: str,
    gateway_image: str,
    internal_network: str,
    external_network: str,
    owner_sha256: str,
    session_sha256: str,
    require_running: bool,
) -> bytes:
    payload, canonical = _parse_one_inspect(raw)
    config = _dict_field(payload, "Config", "config")
    host_config = _dict_field(payload, "HostConfig", "hostConfig")
    state = _dict_field(payload, "State", "state")
    networks = _container_networks(payload)
    name = _value_field(payload, "Name", "name")
    mounts = _value_field(payload, "Mounts", "mounts")
    env = _value_field(config, "Env", "env")
    labels = _dict_field(config, "Labels", "labels")
    entrypoint = _value_field(config, "Entrypoint", "entrypoint")
    image = _value_field(config, "Image", "image")
    user = _value_field(config, "User", "user")
    running = _value_field(state, "Running", "running")
    binds = host_config.get("Binds", host_config.get("binds"))
    cap_drop = host_config.get("CapDrop", host_config.get("capDrop"))
    security_opt = host_config.get("SecurityOpt", host_config.get("securityOpt"))
    read_only = host_config.get("ReadonlyRootfs", host_config.get("readOnly"))
    privileged = host_config.get("Privileged", host_config.get("privileged"))
    if (
        not isinstance(env, list)
        or not all(isinstance(item, str) and "=" in item for item in env)
        or not isinstance(cap_drop, list)
        or not isinstance(security_opt, list)
        or not isinstance(running, bool)
    ):
        raise BrokerEgressProvisioningError("broker egress inspect validation failed")
    environment_names = {item.split("=", 1)[0].casefold() for item in env}
    internal_attachment = networks.get(internal_network)
    if not isinstance(internal_attachment, dict):
        raise BrokerEgressProvisioningError("broker egress inspect validation failed")
    aliases = internal_attachment.get("Aliases", internal_attachment.get("aliases"))
    if (
        name.lstrip("/") != gateway_name
        or image != gateway_image
        or entrypoint != [GATEWAY_ENTRYPOINT]
        or user != f"{BROKER_CONTAINER_UID}:{BROKER_CONTAINER_GID}"
        or mounts != []
        or binds not in (None, [])
        or {item.casefold() for item in cap_drop} != {"all"}
        or "no-new-privileges" not in {item.casefold() for item in security_opt}
        or read_only is not True
        or privileged is not False
        or set(networks) != {internal_network, external_network}
        or not isinstance(aliases, list)
        or GATEWAY_ALIAS not in aliases
        or "AI_REVIEW_EGRESS_GATEWAY=1" not in env
        or environment_names & _FORBIDDEN_GATEWAY_ENV
        or labels.get("ai-review.owner-sha256") != owner_sha256
        or labels.get("ai-review.session-sha256") != session_sha256
        or labels.get("ai-review.kind") != "gateway"
        or (require_running and running is not True)
    ):
        raise BrokerEgressProvisioningError("broker egress inspect validation failed")
    return canonical


def _validate_owned_resource_inspect(
    raw: bytes,
    *,
    resource_type: str,
    expected_name: str,
    expected_kind: str,
    owner_sha256: str,
    session_sha256: str,
) -> None:
    payload, _canonical = _parse_one_inspect(raw)
    name = _value_field(payload, "Name", "name")
    if resource_type == "container":
        labels = _dict_field(_dict_field(payload, "Config", "config"), "Labels", "labels")
    elif resource_type == "network":
        labels = _dict_field(payload, "Labels", "labels")
    else:
        raise BrokerEgressProvisioningError("broker egress inspect validation failed")
    if (
        not isinstance(name, str)
        or name.lstrip("/") != expected_name
        or labels.get("ai-review.owner-sha256") != owner_sha256
        or labels.get("ai-review.session-sha256") != session_sha256
        or labels.get("ai-review.kind") != expected_kind
    ):
        raise BrokerEgressProvisioningError("broker egress inspect validation failed")


def _gateway_user_namespace_argv(backend: ContainerBackend) -> tuple[str, ...]:
    if backend.name == "podman" and backend.rootless:
        return (f"--userns=keep-id:uid={BROKER_CONTAINER_UID},gid={BROKER_CONTAINER_GID}",)
    if backend.name == "podman":
        return ("--userns=auto",)
    return ()


def _network_create_argv(
    backend: ContainerBackend,
    *,
    name: str,
    internal: bool,
    owner_sha256: str,
    session_sha256: str,
    kind: str,
) -> tuple[str, ...]:
    internal_argv = ("--internal",) if internal else ()
    return (
        str(backend.executable),
        "network",
        "create",
        "--driver=bridge",
        *internal_argv,
        f"--label=ai-review.owner-sha256={owner_sha256}",
        f"--label=ai-review.session-sha256={session_sha256}",
        f"--label=ai-review.kind={kind}",
        name,
    )


def _gateway_run_argv(
    backend: ContainerBackend,
    *,
    gateway_name: str,
    external_network: str,
    gateway_image: str,
    owner_sha256: str,
    session_sha256: str,
) -> tuple[str, ...]:
    return (
        str(backend.executable),
        "run",
        "--detach",
        "--pull=never",
        f"--name={gateway_name}",
        f"--network={external_network}",
        "--read-only",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "--ipc=none",
        *_gateway_user_namespace_argv(backend),
        f"--user={BROKER_CONTAINER_UID}:{BROKER_CONTAINER_GID}",
        "--workdir=/",
        "--pids-limit=32",
        "--memory=128m",
        "--cpus=0.5",
        "--tmpfs=/tmp:rw,noexec,nosuid,nodev,size=4m,mode=1777",
        "--env=AI_REVIEW_EGRESS_GATEWAY=1",
        f"--label=ai-review.owner-sha256={owner_sha256}",
        f"--label=ai-review.session-sha256={session_sha256}",
        "--label=ai-review.kind=gateway",
        f"--entrypoint={GATEWAY_ENTRYPOINT}",
        gateway_image,
    )


def _network_connect_argv(
    backend: ContainerBackend,
    *,
    internal_network: str,
    gateway_name: str,
) -> tuple[str, ...]:
    return (
        str(backend.executable),
        "network",
        "connect",
        "--alias",
        GATEWAY_ALIAS,
        internal_network,
        gateway_name,
    )


def _network_inspect_argv(backend: ContainerBackend, name: str) -> tuple[str, ...]:
    return (str(backend.executable), "network", "inspect", "--", name)


def _container_inspect_argv(backend: ContainerBackend, name: str) -> tuple[str, ...]:
    return (str(backend.executable), "container", "inspect", "--", name)


def _container_absence_argv(backend: ContainerBackend, name: str) -> tuple[str, ...]:
    return (
        str(backend.executable),
        "container",
        "ls",
        "--all",
        "--filter",
        f"name=^{name}$",
        "--format={{.Names}}",
    )


def _network_absence_argv(backend: ContainerBackend, name: str) -> tuple[str, ...]:
    return (
        str(backend.executable),
        "network",
        "ls",
        "--filter",
        f"name=^{name}$",
        "--format={{.Name}}",
    )


def _container_remove_argv(backend: ContainerBackend, name: str) -> tuple[str, ...]:
    return (str(backend.executable), "container", "rm", "-f", "--", name)


def _network_remove_argv(backend: ContainerBackend, name: str) -> tuple[str, ...]:
    return (str(backend.executable), "network", "rm", "--", name)


def _command_record_payload(record: RuntimeCommandEvidence) -> dict[str, object]:
    return {
        "argv": list(record.argv),
        "duration_ms": record.duration_ms,
        "evidence_sha256": record.evidence_sha256,
        "exit_code": record.exit_code,
        "stderr_sha256": record.stderr_sha256,
        "stdout_sha256": record.stdout_sha256,
    }


def _validate_command_record(record: RuntimeCommandEvidence) -> None:
    if (
        type(record) is not RuntimeCommandEvidence
        or not record.argv
        or not Path(record.argv[0]).is_absolute()
        or isinstance(record.exit_code, bool)
        or not isinstance(record.exit_code, int)
        or not isinstance(record.stdout, bytes)
        or not isinstance(record.stderr, bytes)
        or record.stdout_sha256 != _sha256(record.stdout)
        or record.stderr_sha256 != _sha256(record.stderr)
        or BROKER_CREDENTIAL_ENV.encode("ascii") in record.stdout
        or BROKER_CREDENTIAL_ENV.encode("ascii") in record.stderr
        or isinstance(record.duration_ms, bool)
        or not isinstance(record.duration_ms, int)
        or not 0 <= record.duration_ms <= MAX_RUNTIME_COMMAND_SECONDS * 1_000
        or record.evidence_sha256
        != _command_evidence_sha256(
            argv=record.argv,
            exit_code=record.exit_code,
            stdout=record.stdout,
            stderr=record.stderr,
            duration_ms=record.duration_ms,
        )
    ):
        raise BrokerEgressProvisioningError("broker egress lifecycle validation failed")


def _lifecycle_sha256(evidence: BrokerEgressLifecycleEvidence) -> str:
    for records in (
        evidence.provisioning_commands,
        evidence.post_execution_inspect_commands,
        evidence.cleanup_commands,
        evidence.post_cleanup_absence_commands,
    ):
        for record in records:
            _validate_command_record(record)
    payload = {
        "boundary_evidence_sha256": evidence.boundary_evidence.broker_egress_boundary_sha256,
        "broker_allowlist_policy_sha256": evidence.broker_allowlist_policy_sha256,
        "broker_gateway_image_digest": evidence.broker_gateway_image_digest,
        "broker_internal_network": evidence.broker_internal_network,
        "cleanup_commands": [_command_record_payload(item) for item in evidence.cleanup_commands],
        "cleanup_succeeded": evidence.cleanup_succeeded,
        "duration_ms": evidence.duration_ms,
        "environment_sha256": evidence.environment_sha256,
        "session_sha256": evidence.session_sha256,
        "gateway_container_name": evidence.gateway_container_name,
        "gateway_external_network": evidence.gateway_external_network,
        "gateway_external_network_inspect_sha256": (
            evidence.gateway_external_network_inspect_sha256
        ),
        "gateway_image": evidence.gateway_image,
        "post_cleanup_absence_commands": [
            _command_record_payload(item) for item in evidence.post_cleanup_absence_commands
        ],
        "post_execution_inspect_commands": [
            _command_record_payload(item) for item in evidence.post_execution_inspect_commands
        ],
        "provisioning_commands": [
            _command_record_payload(item) for item in evidence.provisioning_commands
        ],
        "runtime_executable": str(evidence.runtime_executable),
        "runtime_name": evidence.runtime_name,
        "runtime_post_security_sha256": evidence.runtime_post_security_sha256,
        "runtime_post_sha256": evidence.runtime_post_sha256,
        "runtime_pre_security_sha256": evidence.runtime_pre_security_sha256,
        "runtime_pre_sha256": evidence.runtime_pre_sha256,
        "runtime_rootless": evidence.runtime_rootless,
        "runtime_seccomp_profile": evidence.runtime_seccomp_profile,
        "runtime_user_namespace": evidence.runtime_user_namespace,
        "schema_version": evidence.schema_version,
        "started_unix_ns": evidence.started_unix_ns,
    }
    return _sha256(_LIFECYCLE_DOMAIN + _canonical_json(payload))


class BrokerEgressSession:
    """Context manager which owns exactly one gateway and its two unique networks."""

    def __init__(
        self,
        *,
        invocation: IsolatedBrokerInvocation,
        gateway_image: str,
        expected_broker_gateway_image_digest: str,
        allowlist_policy: bytes,
        expected_broker_allowlist_policy_sha256: str,
        candidate_uid: int,
        allow_external_ai: bool,
        allow_isolated_broker: bool,
        which: Callable[[str], str | None],
        probe: Callable[..., subprocess.CompletedProcess] | None,
        command_runner: Callable[..., object],
    ) -> None:
        if allow_external_ai is not True or allow_isolated_broker is not True:
            raise BrokerEgressProvisioningError("broker egress provisioning requires double opt-in")
        self.invocation = invocation
        self.gateway_image = gateway_image
        self.expected_gateway_digest = expected_broker_gateway_image_digest
        self.allowlist_policy = allowlist_policy
        self.expected_policy_sha256 = expected_broker_allowlist_policy_sha256
        self.candidate_uid = candidate_uid
        self.which = which
        self.probe = probe
        self.command_runner = command_runner
        self.backend: ContainerBackend | None = None
        self.environment: dict[str, str] | None = None
        self.owner_sha256 = _owner_sha256(invocation)
        self.session_sha256 = _new_session_sha256()
        self.gateway_container_name = _gateway_name(invocation)
        self.gateway_external_network = broker_gateway_external_network_name(invocation)
        self._created_internal = False
        self._created_external = False
        self._created_gateway = False
        self._entered = False
        self._closed = False
        self._started_unix_ns = 0
        self._started_monotonic_ns = 0
        self._provisioning_commands: list[RuntimeCommandEvidence] = []
        self._post_commands: list[RuntimeCommandEvidence] = []
        self._cleanup_commands: list[RuntimeCommandEvidence] = []
        self._absence_commands: list[RuntimeCommandEvidence] = []
        self._boundary_evidence: EgressBoundaryEvidence | None = None
        self._external_inspect = b""
        self.lifecycle_evidence: BrokerEgressLifecycleEvidence | None = None

    @property
    def boundary_evidence(self) -> EgressBoundaryEvidence:
        if not self._entered or self._closed or self._boundary_evidence is None:
            raise BrokerEgressProvisioningError("broker egress session is not active")
        return self._boundary_evidence

    def _command(self, argv: tuple[str, ...]) -> RuntimeCommandEvidence:
        if self.environment is None:
            raise BrokerEgressProvisioningError("broker egress provisioning failed")
        return _run_runtime_command(
            argv,
            environment=self.environment,
            runner=self.command_runner,
        )

    @staticmethod
    def _require_success(record: RuntimeCommandEvidence) -> RuntimeCommandEvidence:
        if record.exit_code != 0:
            raise BrokerEgressProvisioningError("broker egress provisioning failed")
        return record

    def _provision(self) -> None:
        backend = _detect_exact_backend(
            self.invocation,
            candidate_uid=self.candidate_uid,
            which=self.which,
            probe=self.probe,
        )
        match = _PINNED_IMAGE_RE.fullmatch(self.gateway_image or "")
        try:
            policy_sha256 = validate_broker_egress_policy(self.allowlist_policy)
        except (EgressPolicyError, TypeError) as exc:
            raise BrokerEgressProvisioningError("broker egress provisioning failed") from exc
        if (
            match is None
            or match.group(1) != self.expected_gateway_digest
            or not _is_sha256(self.expected_policy_sha256)
            or not hmac.compare_digest(policy_sha256, self.expected_policy_sha256)
        ):
            raise BrokerEgressProvisioningError("broker egress provisioning failed")
        self.backend = backend
        self.environment = _base_host_environment(backend.name)
        self._started_unix_ns = time.time_ns()
        self._started_monotonic_ns = time.monotonic_ns()

        # Refuse collisions before any create.  Names are deterministic, while the random
        # session label distinguishes this coordinator-owned lifecycle from a concurrent one.
        preflight_absence = (
            self._command(_container_absence_argv(backend, self.gateway_container_name)),
            self._command(_network_absence_argv(backend, self.invocation.broker_internal_network)),
            self._command(_network_absence_argv(backend, self.gateway_external_network)),
        )
        if any(item.exit_code != 0 or item.stdout for item in preflight_absence):
            raise BrokerEgressProvisioningError("broker egress provisioning failed")
        self._provisioning_commands.extend(preflight_absence)

        self._created_internal = True
        internal_create = self._require_success(
            self._command(
                _network_create_argv(
                    backend,
                    name=self.invocation.broker_internal_network,
                    internal=True,
                    owner_sha256=self.owner_sha256,
                    session_sha256=self.session_sha256,
                    kind="broker-internal",
                )
            )
        )
        self._provisioning_commands.append(internal_create)
        self._created_external = True
        external_create = self._require_success(
            self._command(
                _network_create_argv(
                    backend,
                    name=self.gateway_external_network,
                    internal=False,
                    owner_sha256=self.owner_sha256,
                    session_sha256=self.session_sha256,
                    kind="gateway-external",
                )
            )
        )
        self._provisioning_commands.append(external_create)
        self._created_gateway = True
        gateway_run = self._require_success(
            self._command(
                _gateway_run_argv(
                    backend,
                    gateway_name=self.gateway_container_name,
                    external_network=self.gateway_external_network,
                    gateway_image=self.gateway_image,
                    owner_sha256=self.owner_sha256,
                    session_sha256=self.session_sha256,
                )
            )
        )
        self._provisioning_commands.append(gateway_run)
        connect = self._require_success(
            self._command(
                _network_connect_argv(
                    backend,
                    internal_network=self.invocation.broker_internal_network,
                    gateway_name=self.gateway_container_name,
                )
            )
        )
        self._provisioning_commands.append(connect)
        internal_inspect = self._require_success(
            self._command(_network_inspect_argv(backend, self.invocation.broker_internal_network))
        )
        external_inspect = self._require_success(
            self._command(_network_inspect_argv(backend, self.gateway_external_network))
        )
        gateway_inspect = self._require_success(
            self._command(_container_inspect_argv(backend, self.gateway_container_name))
        )
        self._provisioning_commands.extend((internal_inspect, external_inspect, gateway_inspect))
        canonical_internal = _validate_network_inspect(
            internal_inspect.stdout,
            expected_name=self.invocation.broker_internal_network,
            expected_internal=True,
            expected_gateway_name=self.gateway_container_name,
            owner_sha256=self.owner_sha256,
            session_sha256=self.session_sha256,
            kind="broker-internal",
        )
        self._external_inspect = _validate_network_inspect(
            external_inspect.stdout,
            expected_name=self.gateway_external_network,
            expected_internal=False,
            expected_gateway_name=self.gateway_container_name,
            owner_sha256=self.owner_sha256,
            session_sha256=self.session_sha256,
            kind="gateway-external",
        )
        canonical_gateway = _validate_gateway_inspect(
            gateway_inspect.stdout,
            gateway_name=self.gateway_container_name,
            gateway_image=self.gateway_image,
            internal_network=self.invocation.broker_internal_network,
            external_network=self.gateway_external_network,
            owner_sha256=self.owner_sha256,
            session_sha256=self.session_sha256,
            require_running=True,
        )
        provisioning = _canonical_json(
            {
                "broker_internal_network": self.invocation.broker_internal_network,
                "commands": [item.evidence_sha256 for item in self._provisioning_commands],
                "environment_sha256": _environment_sha256(self.environment),
                "gateway_alias": GATEWAY_ALIAS,
                "gateway_external_network": self.gateway_external_network,
                "gateway_external_network_inspect_sha256": _sha256(self._external_inspect),
                "gateway_port": GATEWAY_PORT,
                "owner_sha256": self.owner_sha256,
                "session_sha256": self.session_sha256,
                "runtime_executable": str(backend.executable),
                "runtime_security_sha256": backend.security_evidence_sha256,
                "runtime_sha256": backend.sha256,
                "schema_version": "1.0",
            }
        )
        boundary = EgressBoundaryEvidence(
            schema_version="1.0",
            runtime_name=backend.name,
            broker_internal_network=self.invocation.broker_internal_network,
            broker_network_inspect=canonical_internal,
            broker_network_inspect_sha256=_sha256(canonical_internal),
            gateway_container_name=self.gateway_container_name,
            gateway_image=self.gateway_image,
            broker_gateway_image_digest=self.expected_gateway_digest,
            gateway_container_inspect=canonical_gateway,
            gateway_container_inspect_sha256=_sha256(canonical_gateway),
            allowlist_policy=self.allowlist_policy,
            broker_allowlist_policy_sha256=self.expected_policy_sha256,
            provisioning=provisioning,
            provisioning_sha256=_sha256(provisioning),
            api_host="api.openai.com",
            api_port=443,
            gateway_network_alias=GATEWAY_ALIAS,
            gateway_port=GATEWAY_PORT,
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
        self._boundary_evidence = replace(
            boundary,
            broker_egress_boundary_sha256=broker_egress_boundary_sha256(boundary),
        )

    def _post_execution_inspect(self) -> bool:
        if self.backend is None or self._boundary_evidence is None:
            return False
        try:
            internal = self._command(
                _network_inspect_argv(self.backend, self.invocation.broker_internal_network)
            )
            external = self._command(
                _network_inspect_argv(self.backend, self.gateway_external_network)
            )
            gateway = self._command(
                _container_inspect_argv(self.backend, self.gateway_container_name)
            )
            self._post_commands.extend((internal, external, gateway))
            if any(item.exit_code != 0 for item in self._post_commands):
                return False
            if (
                _validate_network_inspect(
                    internal.stdout,
                    expected_name=self.invocation.broker_internal_network,
                    expected_internal=True,
                    expected_gateway_name=self.gateway_container_name,
                    owner_sha256=self.owner_sha256,
                    session_sha256=self.session_sha256,
                    kind="broker-internal",
                )
                != self._boundary_evidence.broker_network_inspect
                or _validate_network_inspect(
                    external.stdout,
                    expected_name=self.gateway_external_network,
                    expected_internal=False,
                    expected_gateway_name=self.gateway_container_name,
                    owner_sha256=self.owner_sha256,
                    session_sha256=self.session_sha256,
                    kind="gateway-external",
                )
                != self._external_inspect
            ):
                return False
            _validate_gateway_inspect(
                gateway.stdout,
                gateway_name=self.gateway_container_name,
                gateway_image=self.gateway_image,
                internal_network=self.invocation.broker_internal_network,
                external_network=self.gateway_external_network,
                owner_sha256=self.owner_sha256,
                session_sha256=self.session_sha256,
                require_running=False,
            )
            return True
        except BrokerEgressProvisioningError:
            return False

    def _cleanup(self, *, require_post_inspect: bool) -> bool:
        if self.backend is None or self.environment is None:
            return True
        post_ok = not require_post_inspect or self._post_execution_inspect()
        cleanup_ok = True
        cleanup_targets: list[tuple[bool, str, str, str, tuple[str, ...], tuple[str, ...]]] = [
            (
                self._created_gateway,
                "container",
                self.gateway_container_name,
                "gateway",
                _container_inspect_argv(self.backend, self.gateway_container_name),
                _container_remove_argv(self.backend, self.gateway_container_name),
            ),
            (
                self._created_internal,
                "network",
                self.invocation.broker_internal_network,
                "broker-internal",
                _network_inspect_argv(self.backend, self.invocation.broker_internal_network),
                _network_remove_argv(self.backend, self.invocation.broker_internal_network),
            ),
            (
                self._created_external,
                "network",
                self.gateway_external_network,
                "gateway-external",
                _network_inspect_argv(self.backend, self.gateway_external_network),
                _network_remove_argv(self.backend, self.gateway_external_network),
            ),
        ]
        for created, resource_type, name, kind, inspect_argv, remove_argv in cleanup_targets:
            if not created:
                continue
            try:
                inspected = self._command(inspect_argv)
                self._cleanup_commands.append(inspected)
                if inspected.exit_code != 0:
                    cleanup_ok = False
                    continue
                _validate_owned_resource_inspect(
                    inspected.stdout,
                    resource_type=resource_type,
                    expected_name=name,
                    expected_kind=kind,
                    owner_sha256=self.owner_sha256,
                    session_sha256=self.session_sha256,
                )
                removed = self._command(remove_argv)
                self._cleanup_commands.append(removed)
                cleanup_ok = cleanup_ok and removed.exit_code == 0
            except BrokerEgressProvisioningError:
                cleanup_ok = False
        absence_targets: list[tuple[bool, tuple[str, ...]]] = [
            (
                self._created_gateway,
                _container_absence_argv(self.backend, self.gateway_container_name),
            ),
            (
                self._created_internal,
                _network_absence_argv(self.backend, self.invocation.broker_internal_network),
            ),
            (
                self._created_external,
                _network_absence_argv(self.backend, self.gateway_external_network),
            ),
        ]
        for created, argv in absence_targets:
            if not created:
                continue
            try:
                record = self._command(argv)
                self._absence_commands.append(record)
                cleanup_ok = cleanup_ok and record.exit_code == 0 and not record.stdout
            except BrokerEgressProvisioningError:
                cleanup_ok = False
        after: ContainerBackend | None = None
        try:
            after = _detect_exact_backend(
                self.invocation,
                candidate_uid=self.candidate_uid,
                which=self.which,
                probe=self.probe,
                enforce_invocation_mode=False,
            )
        except BrokerExecutionError:
            pass
        runtime_ok = (
            self.backend is not None and after is not None and _same_backend(self.backend, after)
        )
        if (
            self._boundary_evidence is not None
            and after is not None
            and self.environment is not None
        ):
            duration_ms = max(
                0,
                (time.monotonic_ns() - self._started_monotonic_ns) // 1_000_000,
            )
            lifecycle = BrokerEgressLifecycleEvidence(
                schema_version="1.0",
                runtime_name=after.name,
                runtime_executable=after.executable,
                runtime_pre_sha256=self.backend.sha256,
                runtime_pre_security_sha256=self.backend.security_evidence_sha256,
                runtime_post_sha256=after.sha256,
                runtime_post_security_sha256=after.security_evidence_sha256,
                runtime_rootless=after.rootless,
                runtime_user_namespace=after.user_namespace,
                runtime_seccomp_profile=after.seccomp_profile,
                environment_sha256=_environment_sha256(self.environment),
                session_sha256=self.session_sha256,
                broker_internal_network=self.invocation.broker_internal_network,
                gateway_external_network=self.gateway_external_network,
                gateway_container_name=self.gateway_container_name,
                gateway_image=self.gateway_image,
                broker_gateway_image_digest=self.expected_gateway_digest,
                broker_allowlist_policy_sha256=self.expected_policy_sha256,
                boundary_evidence=self._boundary_evidence,
                gateway_external_network_inspect=self._external_inspect,
                gateway_external_network_inspect_sha256=_sha256(self._external_inspect),
                provisioning_commands=tuple(self._provisioning_commands),
                post_execution_inspect_commands=tuple(self._post_commands),
                cleanup_commands=tuple(self._cleanup_commands),
                post_cleanup_absence_commands=tuple(self._absence_commands),
                started_unix_ns=self._started_unix_ns,
                duration_ms=duration_ms,
                cleanup_succeeded=post_ok and cleanup_ok and runtime_ok,
                evidence_sha256="0" * 64,
            )
            self.lifecycle_evidence = replace(
                lifecycle,
                evidence_sha256=_lifecycle_sha256(lifecycle),
            )
        return post_ok and cleanup_ok and runtime_ok

    def __enter__(self) -> BrokerEgressSession:
        if self._entered or self._closed:
            raise BrokerEgressProvisioningError("broker egress session cannot be reused")
        self._entered = True
        try:
            self._provision()
            return self
        except Exception as exc:
            cleanup_ok = self._cleanup(require_post_inspect=False)
            self._closed = True
            if not cleanup_ok:
                raise BrokerEgressProvisioningError("broker egress cleanup failed") from exc
            raise BrokerEgressProvisioningError("broker egress provisioning failed") from exc

    def __exit__(self, exc_type, exc_value, traceback) -> bool:
        if self._closed:
            raise BrokerEgressProvisioningError("broker egress session cannot be reused")
        cleanup_ok = self._cleanup(require_post_inspect=True)
        self._closed = True
        if not cleanup_ok:
            raise BrokerEgressProvisioningError("broker egress cleanup failed")
        return False


def provision_broker_egress(
    *,
    invocation: IsolatedBrokerInvocation,
    gateway_image: str,
    expected_broker_gateway_image_digest: str,
    allowlist_policy: bytes,
    expected_broker_allowlist_policy_sha256: str,
    candidate_uid: int,
    allow_external_ai: bool,
    allow_isolated_broker: bool,
    which: Callable[[str], str | None] = _system_which,
    probe: Callable[..., subprocess.CompletedProcess] | None = None,
    command_runner: Callable[..., object] = _run_bounded_broker,
) -> BrokerEgressSession:
    """Return a single-use context which owns and attests the full gateway lifecycle."""

    return BrokerEgressSession(
        invocation=invocation,
        gateway_image=gateway_image,
        expected_broker_gateway_image_digest=expected_broker_gateway_image_digest,
        allowlist_policy=allowlist_policy,
        expected_broker_allowlist_policy_sha256=expected_broker_allowlist_policy_sha256,
        candidate_uid=candidate_uid,
        allow_external_ai=allow_external_ai,
        allow_isolated_broker=allow_isolated_broker,
        which=which,
        probe=probe,
        command_runner=command_runner,
    )


def _validate_lifecycle_shape(
    evidence: BrokerEgressLifecycleEvidence,
    *,
    invocation: IsolatedBrokerInvocation,
    expected_gateway_digest: str,
    expected_policy_sha256: str,
) -> None:
    if type(evidence) is not BrokerEgressLifecycleEvidence:
        raise BrokerEgressProvisioningError("broker egress lifecycle validation failed")
    expected_external = broker_gateway_external_network_name(invocation)
    expected_gateway = _gateway_name(invocation)
    if (
        evidence.schema_version != "1.0"
        or evidence.broker_internal_network != invocation.broker_internal_network
        or evidence.gateway_external_network != expected_external
        or _EXTERNAL_NETWORK_RE.fullmatch(evidence.gateway_external_network) is None
        or evidence.gateway_container_name != expected_gateway
        or evidence.broker_gateway_image_digest != expected_gateway_digest
        or evidence.broker_allowlist_policy_sha256 != expected_policy_sha256
        or evidence.gateway_external_network_inspect_sha256
        != _sha256(evidence.gateway_external_network_inspect)
        or len(evidence.provisioning_commands) != 10
        or len(evidence.post_execution_inspect_commands) != 3
        or len(evidence.cleanup_commands) != 6
        or len(evidence.post_cleanup_absence_commands) != 3
        or evidence.cleanup_succeeded is not True
        or not _is_sha256(evidence.environment_sha256)
        or not _is_sha256(evidence.session_sha256)
        or isinstance(evidence.started_unix_ns, bool)
        or not isinstance(evidence.started_unix_ns, int)
        or evidence.started_unix_ns <= 0
        or isinstance(evidence.duration_ms, bool)
        or not isinstance(evidence.duration_ms, int)
        or not 0 <= evidence.duration_ms <= 10 * 60 * 1_000
        or evidence.evidence_sha256 != _lifecycle_sha256(evidence)
    ):
        raise BrokerEgressProvisioningError("broker egress lifecycle validation failed")


def validate_broker_egress_lifecycle_evidence(
    evidence: BrokerEgressLifecycleEvidence,
    *,
    invocation: IsolatedBrokerInvocation,
    expected_broker_gateway_image_digest: str,
    expected_broker_allowlist_policy_sha256: str,
    candidate_uid: int,
    which: Callable[[str], str | None] = _system_which,
    probe: Callable[..., subprocess.CompletedProcess] | None = None,
    command_runner: Callable[..., object] = _run_bounded_broker,
) -> BrokerEgressLifecycleEvidence:
    """Reparse raw evidence, remeasure runtime, and prove all owned resources are absent."""

    try:
        _validate_lifecycle_shape(
            evidence,
            invocation=invocation,
            expected_gateway_digest=expected_broker_gateway_image_digest,
            expected_policy_sha256=expected_broker_allowlist_policy_sha256,
        )
        backend = _detect_exact_backend(
            invocation,
            candidate_uid=candidate_uid,
            which=which,
            probe=probe,
            enforce_invocation_mode=False,
        )
        if (
            backend.name != evidence.runtime_name
            or backend.executable != evidence.runtime_executable
            or backend.sha256 != evidence.runtime_pre_sha256
            or backend.sha256 != evidence.runtime_post_sha256
            or backend.security_evidence_sha256 != evidence.runtime_pre_security_sha256
            or backend.security_evidence_sha256 != evidence.runtime_post_security_sha256
            or backend.rootless is not evidence.runtime_rootless
            or backend.user_namespace is not evidence.runtime_user_namespace
            or backend.seccomp_profile != evidence.runtime_seccomp_profile
            or evidence.environment_sha256
            != _environment_sha256(_base_host_environment(backend.name))
        ):
            raise BrokerEgressProvisioningError("broker egress lifecycle validation failed")
        owner_sha256 = _owner_sha256(invocation)
        boundary = evidence.boundary_evidence
        if (
            boundary.broker_egress_boundary_sha256 != broker_egress_boundary_sha256(boundary)
            or boundary.broker_internal_network != invocation.broker_internal_network
            or boundary.gateway_container_name != evidence.gateway_container_name
            or boundary.gateway_image != evidence.gateway_image
        ):
            raise BrokerEgressProvisioningError("broker egress lifecycle validation failed")
        canonical_internal = _validate_network_inspect(
            boundary.broker_network_inspect,
            expected_name=invocation.broker_internal_network,
            expected_internal=True,
            expected_gateway_name=evidence.gateway_container_name,
            owner_sha256=owner_sha256,
            session_sha256=evidence.session_sha256,
            kind="broker-internal",
        )
        canonical_external = _validate_network_inspect(
            evidence.gateway_external_network_inspect,
            expected_name=evidence.gateway_external_network,
            expected_internal=False,
            expected_gateway_name=evidence.gateway_container_name,
            owner_sha256=owner_sha256,
            session_sha256=evidence.session_sha256,
            kind="gateway-external",
        )
        canonical_gateway = _validate_gateway_inspect(
            boundary.gateway_container_inspect,
            gateway_name=evidence.gateway_container_name,
            gateway_image=evidence.gateway_image,
            internal_network=invocation.broker_internal_network,
            external_network=evidence.gateway_external_network,
            owner_sha256=owner_sha256,
            session_sha256=evidence.session_sha256,
            require_running=True,
        )
        if (
            canonical_internal != boundary.broker_network_inspect
            or canonical_external != evidence.gateway_external_network_inspect
            or canonical_gateway != boundary.gateway_container_inspect
        ):
            raise BrokerEgressProvisioningError("broker egress lifecycle validation failed")
        pre_internal, pre_external, pre_gateway = evidence.provisioning_commands[-3:]
        if (
            _validate_network_inspect(
                pre_internal.stdout,
                expected_name=invocation.broker_internal_network,
                expected_internal=True,
                expected_gateway_name=evidence.gateway_container_name,
                owner_sha256=owner_sha256,
                session_sha256=evidence.session_sha256,
                kind="broker-internal",
            )
            != boundary.broker_network_inspect
            or _validate_network_inspect(
                pre_external.stdout,
                expected_name=evidence.gateway_external_network,
                expected_internal=False,
                expected_gateway_name=evidence.gateway_container_name,
                owner_sha256=owner_sha256,
                session_sha256=evidence.session_sha256,
                kind="gateway-external",
            )
            != evidence.gateway_external_network_inspect
            or _validate_gateway_inspect(
                pre_gateway.stdout,
                gateway_name=evidence.gateway_container_name,
                gateway_image=evidence.gateway_image,
                internal_network=invocation.broker_internal_network,
                external_network=evidence.gateway_external_network,
                owner_sha256=owner_sha256,
                session_sha256=evidence.session_sha256,
                require_running=True,
            )
            != boundary.gateway_container_inspect
        ):
            raise BrokerEgressProvisioningError("broker egress lifecycle validation failed")
        post_internal, post_external, post_gateway = evidence.post_execution_inspect_commands
        _validate_network_inspect(
            post_internal.stdout,
            expected_name=invocation.broker_internal_network,
            expected_internal=True,
            expected_gateway_name=evidence.gateway_container_name,
            owner_sha256=owner_sha256,
            session_sha256=evidence.session_sha256,
            kind="broker-internal",
        )
        _validate_network_inspect(
            post_external.stdout,
            expected_name=evidence.gateway_external_network,
            expected_internal=False,
            expected_gateway_name=evidence.gateway_container_name,
            owner_sha256=owner_sha256,
            session_sha256=evidence.session_sha256,
            kind="gateway-external",
        )
        _validate_gateway_inspect(
            post_gateway.stdout,
            gateway_name=evidence.gateway_container_name,
            gateway_image=evidence.gateway_image,
            internal_network=invocation.broker_internal_network,
            external_network=evidence.gateway_external_network,
            owner_sha256=owner_sha256,
            session_sha256=evidence.session_sha256,
            require_running=False,
        )
        expected_provisioning = _canonical_json(
            {
                "broker_internal_network": invocation.broker_internal_network,
                "commands": [item.evidence_sha256 for item in evidence.provisioning_commands],
                "environment_sha256": evidence.environment_sha256,
                "gateway_alias": GATEWAY_ALIAS,
                "gateway_external_network": evidence.gateway_external_network,
                "gateway_external_network_inspect_sha256": (
                    evidence.gateway_external_network_inspect_sha256
                ),
                "gateway_port": GATEWAY_PORT,
                "owner_sha256": owner_sha256,
                "runtime_executable": str(backend.executable),
                "runtime_security_sha256": backend.security_evidence_sha256,
                "runtime_sha256": backend.sha256,
                "schema_version": "1.0",
                "session_sha256": evidence.session_sha256,
            }
        )
        if boundary.provisioning != expected_provisioning:
            raise BrokerEgressProvisioningError("broker egress lifecycle validation failed")

        expected_preflight_absence = (
            _container_absence_argv(backend, evidence.gateway_container_name),
            _network_absence_argv(backend, invocation.broker_internal_network),
            _network_absence_argv(backend, evidence.gateway_external_network),
        )
        expected_provision = (
            *expected_preflight_absence,
            _network_create_argv(
                backend,
                name=invocation.broker_internal_network,
                internal=True,
                owner_sha256=owner_sha256,
                session_sha256=evidence.session_sha256,
                kind="broker-internal",
            ),
            _network_create_argv(
                backend,
                name=evidence.gateway_external_network,
                internal=False,
                owner_sha256=owner_sha256,
                session_sha256=evidence.session_sha256,
                kind="gateway-external",
            ),
            _gateway_run_argv(
                backend,
                gateway_name=evidence.gateway_container_name,
                external_network=evidence.gateway_external_network,
                gateway_image=evidence.gateway_image,
                owner_sha256=owner_sha256,
                session_sha256=evidence.session_sha256,
            ),
            _network_connect_argv(
                backend,
                internal_network=invocation.broker_internal_network,
                gateway_name=evidence.gateway_container_name,
            ),
            _network_inspect_argv(backend, invocation.broker_internal_network),
            _network_inspect_argv(backend, evidence.gateway_external_network),
            _container_inspect_argv(backend, evidence.gateway_container_name),
        )
        expected_post = expected_provision[-3:]
        expected_cleanup = (
            _container_inspect_argv(backend, evidence.gateway_container_name),
            _container_remove_argv(backend, evidence.gateway_container_name),
            _network_inspect_argv(backend, invocation.broker_internal_network),
            _network_remove_argv(backend, invocation.broker_internal_network),
            _network_inspect_argv(backend, evidence.gateway_external_network),
            _network_remove_argv(backend, evidence.gateway_external_network),
        )
        expected_absence = (
            _container_absence_argv(backend, evidence.gateway_container_name),
            _network_absence_argv(backend, invocation.broker_internal_network),
            _network_absence_argv(backend, evidence.gateway_external_network),
        )
        if (
            tuple(item.argv for item in evidence.provisioning_commands) != expected_provision
            or any(
                item.exit_code != 0 or item.stdout for item in evidence.provisioning_commands[:3]
            )
            or any(item.exit_code != 0 for item in evidence.provisioning_commands[3:])
        ):
            raise BrokerEgressProvisioningError("broker egress lifecycle validation failed")
        groups = (
            (evidence.post_execution_inspect_commands, expected_post, True),
            (evidence.cleanup_commands, expected_cleanup, True),
            (evidence.post_cleanup_absence_commands, expected_absence, True),
        )
        for records, expected_argv, success_expected in groups:
            if tuple(item.argv for item in records) != expected_argv or any(
                (item.exit_code == 0) is not success_expected for item in records
            ):
                raise BrokerEgressProvisioningError("broker egress lifecycle validation failed")
        _validate_gateway_inspect(
            evidence.cleanup_commands[0].stdout,
            gateway_name=evidence.gateway_container_name,
            gateway_image=evidence.gateway_image,
            internal_network=invocation.broker_internal_network,
            external_network=evidence.gateway_external_network,
            owner_sha256=owner_sha256,
            session_sha256=evidence.session_sha256,
            require_running=False,
        )
        _validate_owned_resource_inspect(
            evidence.cleanup_commands[2].stdout,
            resource_type="network",
            expected_name=invocation.broker_internal_network,
            expected_kind="broker-internal",
            owner_sha256=owner_sha256,
            session_sha256=evidence.session_sha256,
        )
        _validate_owned_resource_inspect(
            evidence.cleanup_commands[4].stdout,
            resource_type="network",
            expected_name=evidence.gateway_external_network,
            expected_kind="gateway-external",
            owner_sha256=owner_sha256,
            session_sha256=evidence.session_sha256,
        )
        if any(item.stdout for item in evidence.post_cleanup_absence_commands):
            raise BrokerEgressProvisioningError("broker egress lifecycle validation failed")

        environment = _base_host_environment(backend.name)
        for argv in expected_absence:
            current = _run_runtime_command(
                argv,
                environment=environment,
                runner=command_runner,
            )
            if current.exit_code != 0 or current.stdout:
                raise BrokerEgressProvisioningError("broker egress lifecycle validation failed")
        return evidence
    except BrokerEgressProvisioningError:
        raise
    except (BrokerExecutionError, OSError, TypeError, ValueError) as exc:
        raise BrokerEgressProvisioningError("broker egress lifecycle validation failed") from exc


def _provisioned_execution_sha256(evidence: ProvisionedBrokerExecutionEvidence) -> str:
    payload = {
        "broker_egress_lifecycle_sha256": evidence.broker_egress_lifecycle_sha256,
        "execution_evidence_sha256": evidence.execution_evidence_sha256,
        "schema_version": evidence.schema_version,
    }
    return _sha256(_PROVISIONED_EXECUTION_DOMAIN + _canonical_json(payload))


def execute_provisioned_isolated_broker(
    *,
    invocation: IsolatedBrokerInvocation,
    expected_packet_sha256: str,
    expected_request_sha256: str,
    expected_boundary_evidence_sha256: str,
    expected_role: str,
    expected_attempt: int,
    approved_image_digest: str,
    expected_argv_sha256: str,
    expected_stdin_sha256: str,
    gateway_image: str,
    expected_broker_gateway_image_digest: str,
    allowlist_policy: bytes,
    expected_broker_allowlist_policy_sha256: str,
    credential: str,
    ledger_path: Path,
    expected_broker_ledger_identity_sha256: str,
    broker_packet_reservation_limit: int,
    candidate_uid: int,
    allow_external_ai: bool,
    allow_isolated_broker: bool,
    pricing_policy: bytes = canonical_openai_pricing_policy_bytes(),
    expected_broker_pricing_policy_sha256: str = APPROVED_OPENAI_PRICING_POLICY.sha256,
    broker_packet_cost_limit_microusd: int = DEFAULT_PACKET_COST_LIMIT_MICROUSD,
    timeout_seconds: int = 240,
    max_stdin_bytes: int = MAX_BROKER_STDIN_BYTES,
    max_stdout_bytes: int = MAX_BROKER_STDOUT_BYTES,
    max_stderr_bytes: int = MAX_BROKER_STDERR_BYTES,
    which: Callable[[str], str | None] = _system_which,
    probe: Callable[..., subprocess.CompletedProcess] | None = None,
    command_runner: Callable[..., object] = _run_bounded_broker,
    stream_runner: Callable[..., _BrokerProcessResult] = _run_bounded_broker,
    cleanup: Callable[[ContainerBackend, str, dict[str, str]], object] = _cleanup_named_container,
) -> ProvisionedBrokerExecutionEvidence:
    """Compatibility one-run wrapper over prepare -> stdlib outer -> finalize.

    Production phase orchestration uses the exact two-role public batch API.  This retained
    one-run entry exists for callers/tests that have not migrated, but it no longer owns a
    separate side-effect path and therefore cannot bypass the stdlib outer executor.
    """

    try:
        if allow_external_ai is not True or allow_isolated_broker is not True:
            raise BrokerEgressProvisioningError("provisioned broker execution requires opt-in")
        trusted = IsolatedBrokerInvocation(**vars(invocation))
        pairs = (
            (trusted.packet_sha256, expected_packet_sha256),
            (trusted.request_sha256, expected_request_sha256),
            (trusted.boundary_evidence_sha256, expected_boundary_evidence_sha256),
            (trusted.approved_image_digest, approved_image_digest),
            (trusted.argv_sha256, expected_argv_sha256),
            (trusted.stdin_sha256, expected_stdin_sha256),
        )
        if (
            any(not _is_sha256(expected) for _actual, expected in pairs[:3])
            or any(not hmac.compare_digest(actual, expected) for actual, expected in pairs)
            or trusted.role != expected_role
            or trusted.attempt != expected_attempt
        ):
            raise BrokerEgressProvisioningError("provisioned broker binding validation failed")
        backend = _detect_exact_backend(
            trusted,
            candidate_uid=candidate_uid,
            which=which,
            probe=probe,
        )
        from tools.ai_review.broker_outer_executor import _execute_prepared_broker_outer
        from tools.ai_review.broker_phase_protocol import BrokerRuntimeBinding
        from tools.ai_review.broker_phase_protocol import _finalize_provisioned_broker_execution
        from tools.ai_review.broker_phase_protocol import _prepare_batch
        from tools.ai_review.broker_phase_protocol import canonical_prepared_broker_batch_bytes

        runtime_binding = BrokerRuntimeBinding(
            name=backend.name,
            executable_sha256=backend.sha256,
            environment_sha256=_environment_sha256(_base_host_environment(backend.name)),
            rootless=backend.rootless,
            user_namespace=backend.user_namespace,
            seccomp_profile=backend.seccomp_profile,
            security_evidence_sha256=backend.security_evidence_sha256,
        )
        compatibility_binding = _sha256(
            b"amazon-explorer-single-broker-compat-v1\0"
            + _canonical_json(
                {
                    "boundary_evidence_sha256": expected_boundary_evidence_sha256,
                    "gateway_image_digest": expected_broker_gateway_image_digest,
                    "packet_sha256": expected_packet_sha256,
                    "pricing_policy_sha256": expected_broker_pricing_policy_sha256,
                    "request_sha256": expected_request_sha256,
                    "runtime_sha256": backend.sha256,
                }
            )
        )
        prepared = _prepare_batch(
            workflow_id=compatibility_binding,
            phase_request_sha256=compatibility_binding,
            task_sha256=expected_boundary_evidence_sha256,
            runtime_manifest_sha256=compatibility_binding,
            candidate_snapshot_sha256=expected_boundary_evidence_sha256,
            review_packet_sha256=expected_packet_sha256,
            invocations=(trusted,),
            runtime=runtime_binding,
            gateway_image=gateway_image,
            broker_gateway_image_digest=expected_broker_gateway_image_digest,
            allowlist_policy=allowlist_policy,
            broker_allowlist_policy_sha256=expected_broker_allowlist_policy_sha256,
            pricing_policy=pricing_policy,
            broker_pricing_policy_sha256=expected_broker_pricing_policy_sha256,
            broker_ledger_identity_sha256=expected_broker_ledger_identity_sha256,
            broker_packet_reservation_limit=broker_packet_reservation_limit,
            broker_packet_cost_limit_microusd=broker_packet_cost_limit_microusd,
            candidate_uid=candidate_uid,
            timeout_seconds=timeout_seconds,
            max_stdin_bytes=max_stdin_bytes,
            max_stdout_bytes=min(max_stdout_bytes, 1_000_000),
            max_stderr_bytes=max_stderr_bytes,
            require_two=False,
        )
        raw_prepared = canonical_prepared_broker_batch_bytes(prepared)

        def compatibility_cleanup(_runtime, name, environment):
            return cleanup(backend, name, environment)

        raw_outer = _execute_prepared_broker_outer(
            raw_prepared,
            credentials={trusted.role: credential},
            ledger_path=ledger_path,
            runtime_executable=backend.executable,
            require_two=False,
            runner=command_runner,
            stream_runner=stream_runner,
            probe=probe,
            broker_cleanup=compatibility_cleanup,
        )
        finalized = _finalize_provisioned_broker_execution(
            prepared,
            raw_outer,
            allowlist_policy=allowlist_policy,
            pricing_policy=pricing_policy,
            require_two=False,
        )
        return finalized[0]
    except (OSError, TypeError, ValueError, RuntimeError) as exc:
        raise BrokerEgressProvisioningError("provisioned broker execution failed") from exc


def validate_provisioned_broker_execution_evidence(
    evidence: ProvisionedBrokerExecutionEvidence,
    *,
    invocation: IsolatedBrokerInvocation,
    expected_packet_sha256: str,
    expected_request_sha256: str,
    expected_boundary_evidence_sha256: str,
    expected_role: str,
    expected_attempt: int,
    approved_image_digest: str,
    expected_descriptor_argv_sha256: str,
    expected_stdin_sha256: str,
    expected_broker_gateway_image_digest: str,
    expected_broker_allowlist_policy_sha256: str,
    ledger_path: Path,
    expected_broker_ledger_identity_sha256: str,
    broker_packet_reservation_limit: int,
    candidate_uid: int,
    pricing_policy: bytes = canonical_openai_pricing_policy_bytes(),
    expected_broker_pricing_policy_sha256: str = APPROVED_OPENAI_PRICING_POLICY.sha256,
    broker_packet_cost_limit_microusd: int = DEFAULT_PACKET_COST_LIMIT_MICROUSD,
    which: Callable[[str], str | None] = _system_which,
    probe: Callable[..., subprocess.CompletedProcess] | None = None,
    command_runner: Callable[..., object] = _run_bounded_broker,
) -> ProvisionedBrokerExecutionEvidence:
    """Independently validate both the broker result and the live-cleaned lifecycle."""

    try:
        if (
            type(evidence) is not ProvisionedBrokerExecutionEvidence
            or evidence.schema_version != "1.0"
            or evidence.execution_evidence_sha256 != evidence.execution.evidence_sha256
            or evidence.broker_egress_lifecycle_sha256 != evidence.egress_lifecycle.evidence_sha256
            or evidence.execution.broker_egress_boundary
            != evidence.egress_lifecycle.boundary_evidence
            or evidence.evidence_sha256 != _provisioned_execution_sha256(evidence)
        ):
            raise BrokerEgressProvisioningError("provisioned broker evidence validation failed")
        lifecycle = validate_broker_egress_lifecycle_evidence(
            evidence.egress_lifecycle,
            invocation=invocation,
            expected_broker_gateway_image_digest=expected_broker_gateway_image_digest,
            expected_broker_allowlist_policy_sha256=expected_broker_allowlist_policy_sha256,
            candidate_uid=candidate_uid,
            which=which,
            probe=probe,
            command_runner=command_runner,
        )
        validate_broker_execution_evidence(
            evidence.execution,
            invocation=invocation,
            expected_packet_sha256=expected_packet_sha256,
            expected_request_sha256=expected_request_sha256,
            expected_boundary_evidence_sha256=expected_boundary_evidence_sha256,
            expected_role=expected_role,
            expected_attempt=expected_attempt,
            approved_image_digest=approved_image_digest,
            expected_descriptor_argv_sha256=expected_descriptor_argv_sha256,
            expected_stdin_sha256=expected_stdin_sha256,
            expected_broker_egress_boundary_sha256=(
                lifecycle.boundary_evidence.broker_egress_boundary_sha256
            ),
            expected_broker_gateway_image_digest=expected_broker_gateway_image_digest,
            expected_broker_allowlist_policy_sha256=expected_broker_allowlist_policy_sha256,
            ledger_path=ledger_path,
            expected_broker_ledger_identity_sha256=expected_broker_ledger_identity_sha256,
            broker_packet_reservation_limit=broker_packet_reservation_limit,
            candidate_uid=candidate_uid,
            pricing_policy=pricing_policy,
            expected_broker_pricing_policy_sha256=(expected_broker_pricing_policy_sha256),
            broker_packet_cost_limit_microusd=broker_packet_cost_limit_microusd,
            which=which,
            probe=probe,
        )
        return evidence
    except BrokerEgressProvisioningError:
        raise
    except (BrokerExecutionError, OSError, TypeError, ValueError) as exc:
        raise BrokerEgressProvisioningError(
            "provisioned broker evidence validation failed"
        ) from exc
