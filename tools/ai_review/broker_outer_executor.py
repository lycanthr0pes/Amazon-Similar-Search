"""Stdlib-only outer executor for a prepared two-role broker batch.

This file is loaded directly by the root-owned ``python -I -S`` launcher.  It intentionally has
no project imports.  The coordinator descriptor contains only packet data and immutable digests;
credentials, the protected SQLite ledger pathname, and the measured runtime pathname arrive on
separate trusted channels.  Candidate paths, mounts, and runtime sockets are not accepted.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import selectors
import signal
import sqlite3
import stat
import subprocess
import threading
import time
from pathlib import Path
from typing import Any
from typing import Callable
from typing import Mapping


_RUN_DOMAIN = b"amazon-explorer-prepared-broker-run-v1\0"
_BATCH_DOMAIN = b"amazon-explorer-prepared-broker-batch-v1\0"
_OUTER_RUN_DOMAIN = b"amazon-explorer-outer-broker-run-v1\0"
_OUTER_BATCH_DOMAIN = b"amazon-explorer-outer-broker-batch-v1\0"
_FROZEN_LEDGER_DOMAIN = b"amazon-explorer-frozen-broker-ledger-v1\0"
_LEDGER_IDENTITY_DOMAIN = b"amazon-explorer-broker-ledger-identity-v1\0"
_CONTAINER_NAME_DOMAIN = b"amazon-explorer-isolated-broker-name-v1\0"
_INTERNAL_NETWORK_DOMAIN = b"amazon-explorer-isolated-broker-network-v1\0"
_EXTERNAL_NETWORK_DOMAIN = b"amazon-explorer-broker-external-network-v1\0"
_OWNER_DOMAIN = b"amazon-explorer-broker-egress-owner-v1\0"
_SESSION_DOMAIN = b"amazon-explorer-broker-egress-session-v1\0"
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_IMAGE_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_PINNED_IMAGE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/:+-]*@(sha256:[0-9a-f]{64})$")
_CONTAINER_RE = re.compile(r"^ai-review-broker-[0-9a-f]{24}$")
_INTERNAL_NETWORK_RE = re.compile(r"^ai-review-broker-net-[0-9a-f]{24}$")
_EXTERNAL_NETWORK_RE = re.compile(r"^ai-review-egress-net-[0-9a-f]{24}$")
_GATEWAY_ENTRYPOINT = "/opt/ai-review/bin/egress-gateway"
_BROKER_ENTRYPOINT = "/opt/ai-review/bin/responses-broker"
_GATEWAY_ALIAS = "ai-review-egress-gateway"
_CREDENTIAL_ENV = "OPENAI_API_KEY"
_CONTAINER_UID = 65_532
_CONTAINER_GID = 65_532
_ROLE_ORDER = ("reviewer", "adversary")
_MAX_BATCH_BYTES = 2_000_000
_MAX_OUTER_EVIDENCE_BYTES = 6_000_000
_MAX_RUNTIME_BYTES = 128 * 1024 * 1024
_MAX_INSPECT_BYTES = 64_000
_MAX_COMMAND_STDERR_BYTES = 64_000
_MAX_TIMEOUT_SECONDS = 300
_LEDGER_SCHEMA_SQL = (
    "CREATE TABLE broker_reservations ("
    "packet_sha256 TEXT NOT NULL,"
    "role TEXT NOT NULL CHECK (role IN ('reviewer', 'adversary')),"
    "attempt INTEGER NOT NULL CHECK (attempt BETWEEN 1 AND 2),"
    "reserved_tokens INTEGER NOT NULL CHECK (reserved_tokens > 0),"
    "reserved_cost_microusd INTEGER NOT NULL CHECK (reserved_cost_microusd > 0),"
    "reservation_unix_ns INTEGER NOT NULL CHECK (reservation_unix_ns > 0),"
    "PRIMARY KEY (packet_sha256, role, attempt)"
    ") STRICT"
)
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


class OuterBrokerExecutionError(RuntimeError):
    """Secret-free fail-closed outer broker failure."""


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise OuterBrokerExecutionError("outer broker artifact is not canonical JSON") from exc


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _domain_sha256(domain: bytes, payload: dict[str, object]) -> str:
    return _sha256(domain + _canonical(payload))


def _strict_json(raw: bytes, *, label: str) -> dict[str, Any]:
    def pairs(values: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in values:
            if key in result:
                raise OuterBrokerExecutionError(f"{label} contains a duplicate key")
            result[key] = value
        return result

    if not isinstance(raw, bytes) or not raw or len(raw) > _MAX_BATCH_BYTES:
        raise OuterBrokerExecutionError(f"{label} is empty or exceeds its byte limit")
    try:
        value = json.loads(raw.decode("utf-8", errors="strict"), object_pairs_hook=pairs)
    except OuterBrokerExecutionError:
        raise
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise OuterBrokerExecutionError(f"{label} is not strict JSON") from exc
    if not isinstance(value, dict) or raw != _canonical(value):
        raise OuterBrokerExecutionError(f"{label} must use canonical JSON encoding")
    return value


def _is_sha256(value: object) -> bool:
    return isinstance(value, str) and _SHA256_RE.fullmatch(value) is not None


def _exact_fields(value: object, expected: set[str], *, label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        raise OuterBrokerExecutionError(f"{label} has missing or unknown fields")
    return value


def _domain_name(prefix: str, domain: bytes, values: tuple[str, ...]) -> str:
    digest = hashlib.sha256(domain)
    for value in values:
        raw = value.encode("ascii")
        digest.update(len(raw).to_bytes(4, "big"))
        digest.update(raw)
    return prefix + digest.hexdigest()[:24]


def _invocation_values(run: dict[str, Any]) -> tuple[str, str, str, str]:
    return (run["packet_sha256"], run["request_sha256"], run["role"], str(run["attempt"]))


def _expected_broker_argv(run: dict[str, Any]) -> tuple[str, ...]:
    userns: tuple[str, ...] = ()
    if run["container_runtime"] == "podman" and run["runtime_rootless"] is True:
        userns = (f"--userns=keep-id:uid={_CONTAINER_UID},gid={_CONTAINER_GID}",)
    elif run["container_runtime"] == "podman":
        userns = ("--userns=auto",)
    return (
        run["container_runtime"],
        "run",
        "--pull=never",
        f"--name={run['container_name']}",
        f"--network={run['broker_internal_network']}",
        "--read-only",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "--ipc=none",
        *userns,
        f"--user={_CONTAINER_UID}:{_CONTAINER_GID}",
        "--workdir=/",
        "--pids-limit=64",
        "--memory=512m",
        "--cpus=1",
        "--tmpfs=/tmp:rw,noexec,nosuid,nodev,size=16m,mode=1777",
        f"--env={_CREDENTIAL_ENV}",
        "--env=AI_REVIEW_EXECUTE=1",
        "--env=AI_REVIEW_EXTERNAL_AI=1",
        "--env=PYTHONDONTWRITEBYTECODE=1",
        "--env=PYTHONNOUSERSITE=1",
        f"--entrypoint={_BROKER_ENTRYPOINT}",
        run["image"],
    )


def _validate_run(payload: object) -> dict[str, Any]:
    fields = {
        "approved_image_digest",
        "attempt",
        "boundary_evidence_sha256",
        "broker_internal_network",
        "container_name",
        "container_runtime",
        "credential_env_name",
        "descriptor_argv",
        "descriptor_argv_sha256",
        "descriptor_sha256",
        "image",
        "packet_sha256",
        "request_sha256",
        "reserved_cost_microusd",
        "reserved_tokens",
        "role",
        "runtime_rootless",
        "runtime_user_namespace",
        "schema_version",
        "stdin_base64",
        "stdin_sha256",
    }
    run = _exact_fields(payload, fields, label="prepared broker run")
    unsigned = {key: value for key, value in run.items() if key != "descriptor_sha256"}
    if not _is_sha256(run["descriptor_sha256"]) or not hmac.compare_digest(
        run["descriptor_sha256"], _domain_sha256(_RUN_DOMAIN, unsigned)
    ):
        raise OuterBrokerExecutionError("prepared broker run digest is invalid")
    try:
        stdin = base64.b64decode(run["stdin_base64"], validate=True)
        descriptor_argv = tuple(run["descriptor_argv"])
    except (TypeError, ValueError) as exc:
        raise OuterBrokerExecutionError("prepared broker run encoding is invalid") from exc
    values = _invocation_values(run)
    expected_name = _domain_name("ai-review-broker-", _CONTAINER_NAME_DOMAIN, values)
    expected_network = _domain_name("ai-review-broker-net-", _INTERNAL_NETWORK_DOMAIN, values)
    image_match = _PINNED_IMAGE_RE.fullmatch(run["image"] if isinstance(run["image"], str) else "")
    if (
        run["schema_version"] != "1.0"
        or run["role"] not in _ROLE_ORDER
        or isinstance(run["attempt"], bool)
        or not isinstance(run["attempt"], int)
        or not 1 <= run["attempt"] <= 2
        or run["container_runtime"] not in {"podman", "docker"}
        or type(run["runtime_rootless"]) is not bool
        or type(run["runtime_user_namespace"]) is not bool
        or (not run["runtime_rootless"] and not run["runtime_user_namespace"])
        or run["credential_env_name"] != _CREDENTIAL_ENV
        or any(
            not _is_sha256(run[key])
            for key in (
                "packet_sha256",
                "request_sha256",
                "boundary_evidence_sha256",
                "descriptor_argv_sha256",
                "stdin_sha256",
            )
        )
        or _IMAGE_DIGEST_RE.fullmatch(
            run["approved_image_digest"] if isinstance(run["approved_image_digest"], str) else ""
        )
        is None
        or image_match is None
        or image_match.group(1) != run["approved_image_digest"]
        or _CONTAINER_RE.fullmatch(run["container_name"] or "") is None
        or run["container_name"] != expected_name
        or _INTERNAL_NETWORK_RE.fullmatch(run["broker_internal_network"] or "") is None
        or run["broker_internal_network"] != expected_network
        or descriptor_argv != _expected_broker_argv(run)
        or _sha256(_canonical(list(descriptor_argv))) != run["descriptor_argv_sha256"]
        or not stdin
        or len(stdin) > 1_000_001
        or _sha256(stdin) != run["stdin_sha256"]
        or not stdin.endswith(b"\n")
        or isinstance(run["reserved_tokens"], bool)
        or not isinstance(run["reserved_tokens"], int)
        or not 12_000 <= run["reserved_tokens"] <= 272_000
        or run["reserved_tokens"] != len(stdin[:-1]) + 12_000
        or isinstance(run["reserved_cost_microusd"], bool)
        or not isinstance(run["reserved_cost_microusd"], int)
        or run["reserved_cost_microusd"] <= 0
    ):
        raise OuterBrokerExecutionError("prepared broker run is invalid")
    try:
        request = json.loads(stdin[:-1].decode("utf-8", errors="strict"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise OuterBrokerExecutionError("prepared broker stdin is invalid") from exc
    effort = "high" if run["role"] == "reviewer" else "xhigh"
    if (
        not isinstance(request, dict)
        or _canonical(request) != stdin[:-1]
        or _sha256(stdin[:-1]) != run["request_sha256"]
        or request.get("model") != "gpt-5.6-sol"
        or request.get("tools") != []
        or request.get("store") is not False
        or request.get("max_output_tokens") != 12_000
        or not isinstance(request.get("reasoning"), dict)
        or request["reasoning"].get("effort") != effort
    ):
        raise OuterBrokerExecutionError("prepared broker stdin is invalid")
    run = dict(run)
    run["_stdin"] = stdin
    run["_descriptor_argv"] = descriptor_argv
    return run


def _validate_runtime(payload: object) -> dict[str, Any]:
    fields = {
        "environment_sha256",
        "executable_sha256",
        "name",
        "rootless",
        "seccomp_profile",
        "security_evidence_sha256",
        "user_namespace",
    }
    runtime = _exact_fields(payload, fields, label="prepared broker runtime")
    security = _sha256(
        _canonical(
            {
                "name": runtime["name"],
                "rootless": runtime["rootless"],
                "seccomp_profile": runtime["seccomp_profile"],
                "user_namespace": runtime["user_namespace"],
            }
        )
        + b"\n"
    )
    if (
        runtime["name"] not in {"podman", "docker"}
        or not _is_sha256(runtime["environment_sha256"])
        or not _is_sha256(runtime["executable_sha256"])
        or type(runtime["rootless"]) is not bool
        or type(runtime["user_namespace"]) is not bool
        or (not runtime["rootless"] and not runtime["user_namespace"])
        or not isinstance(runtime["seccomp_profile"], str)
        or not runtime["seccomp_profile"]
        or "unconfined" in runtime["seccomp_profile"].casefold()
        or runtime["security_evidence_sha256"] != security
    ):
        raise OuterBrokerExecutionError("prepared broker runtime is invalid")
    return runtime


def _parse_prepared_batch(raw: bytes, *, require_two: bool = True) -> dict[str, Any]:
    payload = _strict_json(raw, label="prepared broker batch")
    fields = {
        "batch_sha256",
        "broker_allowlist_policy_sha256",
        "broker_gateway_image_digest",
        "broker_ledger_identity_sha256",
        "broker_packet_cost_limit_microusd",
        "broker_packet_reservation_limit",
        "broker_pricing_policy_sha256",
        "candidate_snapshot_sha256",
        "candidate_uid",
        "gateway_image",
        "max_stderr_bytes",
        "max_stdin_bytes",
        "max_stdout_bytes",
        "phase_request_sha256",
        "review_packet_sha256",
        "runs",
        "runtime",
        "runtime_manifest_sha256",
        "schema_version",
        "task_sha256",
        "timeout_seconds",
        "workflow_id",
    }
    batch = _exact_fields(payload, fields, label="prepared broker batch")
    unsigned = {key: value for key, value in batch.items() if key != "batch_sha256"}
    if not _is_sha256(batch["batch_sha256"]) or not hmac.compare_digest(
        batch["batch_sha256"], _domain_sha256(_BATCH_DOMAIN, unsigned)
    ):
        raise OuterBrokerExecutionError("prepared broker batch digest is invalid")
    runtime = _validate_runtime(batch["runtime"])
    if not isinstance(batch["runs"], list):
        raise OuterBrokerExecutionError("prepared broker runs are invalid")
    runs = tuple(_validate_run(run) for run in batch["runs"])
    gateway_match = _PINNED_IMAGE_RE.fullmatch(
        batch["gateway_image"] if isinstance(batch["gateway_image"], str) else ""
    )
    digest_fields = (
        "workflow_id",
        "phase_request_sha256",
        "task_sha256",
        "runtime_manifest_sha256",
        "candidate_snapshot_sha256",
        "review_packet_sha256",
        "broker_allowlist_policy_sha256",
        "broker_pricing_policy_sha256",
        "broker_ledger_identity_sha256",
    )
    int_limits = (
        (batch["timeout_seconds"], 1, _MAX_TIMEOUT_SECONDS),
        (batch["max_stdin_bytes"], 2, 1_000_001),
        (batch["max_stdout_bytes"], 2, 1_000_000),
        (batch["max_stderr_bytes"], 1, 64_000),
        (batch["broker_packet_reservation_limit"], 12_000, 1_088_000),
        (batch["broker_packet_cost_limit_microusd"], 1, 7_940_000),
    )
    if (
        batch["schema_version"] != "1.0"
        or any(not _is_sha256(batch[name]) for name in digest_fields)
        or isinstance(batch["candidate_uid"], bool)
        or not isinstance(batch["candidate_uid"], int)
        or batch["candidate_uid"] <= 0
        or batch["candidate_uid"] == os.geteuid()
        or gateway_match is None
        or gateway_match.group(1) != batch["broker_gateway_image_digest"]
        or any(
            isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum
            for value, minimum, maximum in int_limits
        )
        or (require_two and tuple(run["role"] for run in runs) != _ROLE_ORDER)
        or (not require_two and not 1 <= len(runs) <= 2)
        or len({run["role"] for run in runs}) != len(runs)
        or any(run["packet_sha256"] != batch["review_packet_sha256"] for run in runs)
        or any(run["container_runtime"] != runtime["name"] for run in runs)
        or any(run["runtime_rootless"] is not runtime["rootless"] for run in runs)
        or any(run["runtime_user_namespace"] is not runtime["user_namespace"] for run in runs)
        or sum(run["reserved_tokens"] for run in runs) > batch["broker_packet_reservation_limit"]
        or sum(run["reserved_cost_microusd"] for run in runs)
        > batch["broker_packet_cost_limit_microusd"]
    ):
        raise OuterBrokerExecutionError("prepared broker batch is invalid")
    batch = dict(batch)
    batch["_runtime"] = runtime
    batch["_runs"] = runs
    return batch


def _candidate_may_write(metadata: os.stat_result, candidate_uid: int) -> bool:
    mode = stat.S_IMODE(metadata.st_mode)
    if metadata.st_uid == candidate_uid and mode & stat.S_IWUSR:
        return True
    return bool(mode & (stat.S_IWGRP | stat.S_IWOTH))


def _assert_protected(path: Path, *, candidate_uid: int, regular: bool) -> os.stat_result:
    absolute = Path(os.path.abspath(path))
    if not absolute.is_absolute() or absolute == Path(absolute.anchor):
        raise OuterBrokerExecutionError("outer protected asset is invalid")
    try:
        parent = os.lstat(absolute.anchor)
        current = Path(absolute.anchor)
        for part in absolute.parts[1:]:
            current /= part
            child = os.lstat(current)
            if stat.S_ISLNK(child.st_mode):
                raise OuterBrokerExecutionError("outer protected asset contains a symlink")
            if _candidate_may_write(parent, candidate_uid) and not (
                stat.S_IMODE(parent.st_mode) & stat.S_ISVTX
                and candidate_uid not in {parent.st_uid, child.st_uid}
            ):
                raise OuterBrokerExecutionError("outer protected asset is replaceable")
            attributes = set(os.listxattr(current, follow_symlinks=False))
            if attributes & {"system.posix_acl_access", "system.posix_acl_default"}:
                raise OuterBrokerExecutionError("outer protected asset has an ACL")
            parent = child
        metadata = os.lstat(absolute)
    except OuterBrokerExecutionError:
        raise
    except OSError as exc:
        raise OuterBrokerExecutionError("outer protected asset could not be inspected") from exc
    if metadata.st_uid == candidate_uid or _candidate_may_write(metadata, candidate_uid):
        raise OuterBrokerExecutionError("outer protected asset is candidate-accessible")
    if regular and (not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1):
        raise OuterBrokerExecutionError("outer protected asset must be a regular single-link file")
    return metadata


def _measure_runtime(path: Path, *, candidate_uid: int) -> tuple[str, os.stat_result]:
    before = _assert_protected(path, candidate_uid=candidate_uid, regular=True)
    if not stat.S_IMODE(before.st_mode) & 0o111 or before.st_size > _MAX_RUNTIME_BYTES:
        raise OuterBrokerExecutionError("outer runtime executable is invalid")
    digest = hashlib.sha256()
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            opened = os.fstat(descriptor)
            if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
                raise OuterBrokerExecutionError("outer runtime executable changed")
            while chunk := os.read(descriptor, 1024 * 1024):
                digest.update(chunk)
            after = os.fstat(descriptor)
        finally:
            os.close(descriptor)
    except OuterBrokerExecutionError:
        raise
    except OSError as exc:
        raise OuterBrokerExecutionError("outer runtime executable could not be measured") from exc
    stable = ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_size", "st_mtime_ns")
    if any(getattr(before, field) != getattr(after, field) for field in stable):
        raise OuterBrokerExecutionError("outer runtime executable changed")
    return digest.hexdigest(), after


def _base_environment(runtime_name: str) -> dict[str, str]:
    environment = {"PATH": os.defpath, "LC_ALL": "C"}
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        runtime_dir = Path(f"/run/user/{os.geteuid()}")
        if runtime_dir.is_dir() and not runtime_dir.is_symlink():
            environment["XDG_RUNTIME_DIR"] = str(runtime_dir)
            docker_socket = runtime_dir / "docker.sock"
            if (
                runtime_name == "docker"
                and docker_socket.exists()
                and not docker_socket.is_symlink()
            ):
                environment["DOCKER_HOST"] = f"unix://{docker_socket}"
    return environment


def _kill_group(process: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except (OSError, ProcessLookupError):
        try:
            process.kill()
        except OSError:
            pass


def _real_run(
    argv: tuple[str, ...],
    *,
    stdin_bytes: bytes,
    environment: dict[str, str],
    timeout_seconds: int,
    max_stdin_bytes: int,
    max_stdout_bytes: int,
    max_stderr_bytes: int,
) -> dict[str, object]:
    if len(stdin_bytes) > max_stdin_bytes:
        raise OuterBrokerExecutionError("outer broker stdin exceeds its byte limit")
    started = time.monotonic_ns()
    try:
        process = subprocess.Popen(
            argv,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=environment,
            shell=False,
            start_new_session=True,
        )
    except OSError as exc:
        raise OuterBrokerExecutionError("outer broker command could not start") from exc
    if process.stdin is None or process.stdout is None or process.stderr is None:
        _kill_group(process)
        raise OuterBrokerExecutionError("outer broker command pipes were not created")
    write_errors: list[BaseException] = []

    def writer() -> None:
        try:
            process.stdin.write(stdin_bytes)
            process.stdin.close()
        except (BrokenPipeError, OSError) as exc:
            write_errors.append(exc)

    thread = threading.Thread(target=writer, daemon=True)
    thread.start()
    selector = selectors.DefaultSelector()
    buffers = {process.stdout: bytearray(), process.stderr: bytearray()}
    limits = {process.stdout: max_stdout_bytes, process.stderr: max_stderr_bytes}
    try:
        for stream in buffers:
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ)
        deadline = time.monotonic() + timeout_seconds
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                _kill_group(process)
                raise OuterBrokerExecutionError("outer broker command timed out")
            for key, _mask in selector.select(min(remaining, 0.25)):
                stream = key.fileobj
                try:
                    chunk = os.read(stream.fileno(), 64 * 1024)
                except BlockingIOError:
                    continue
                if not chunk:
                    selector.unregister(stream)
                    continue
                buffers[stream].extend(chunk)
                if len(buffers[stream]) > limits[stream]:
                    _kill_group(process)
                    raise OuterBrokerExecutionError(
                        "outer broker command output exceeded its limit"
                    )
        exit_code = process.wait(timeout=max(0.1, deadline - time.monotonic()))
        thread.join(timeout=1)
        if thread.is_alive() or write_errors:
            raise OuterBrokerExecutionError("outer broker stdin delivery failed")
        return {
            "exit_code": exit_code,
            "stdout": bytes(buffers[process.stdout]),
            "stderr": bytes(buffers[process.stderr]),
            "duration_ms": max(0, (time.monotonic_ns() - started) // 1_000_000),
        }
    finally:
        selector.close()
        for stream in buffers:
            stream.close()
        if process.poll() is None:
            _kill_group(process)
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                pass


def _measure_runner_result(raw: object, *, observed_ms: int) -> dict[str, object]:
    try:
        exit_code = raw.exit_code  # type: ignore[attr-defined]
        stdout = raw.stdout  # type: ignore[attr-defined]
        stderr = raw.stderr  # type: ignore[attr-defined]
        duration_ms = raw.duration_ms  # type: ignore[attr-defined]
    except AttributeError:
        if not isinstance(raw, dict):
            raise OuterBrokerExecutionError("outer broker command result is invalid") from None
        exit_code = raw.get("exit_code")
        stdout = raw.get("stdout")
        stderr = raw.get("stderr")
        duration_ms = raw.get("duration_ms")
    if (
        isinstance(exit_code, bool)
        or not isinstance(exit_code, int)
        or not isinstance(stdout, bytes)
        or not isinstance(stderr, bytes)
        or isinstance(duration_ms, bool)
        or not isinstance(duration_ms, int)
        or duration_ms < 0
        or observed_ms < 0
    ):
        raise OuterBrokerExecutionError("outer broker command result is invalid")
    return {
        "exit_code": exit_code,
        "stdout": stdout,
        "stderr": stderr,
        "duration_ms": max(duration_ms, observed_ms),
    }


def _run(
    argv: tuple[str, ...],
    *,
    stdin_bytes: bytes,
    environment: dict[str, str],
    timeout_seconds: int,
    max_stdin_bytes: int,
    max_stdout_bytes: int,
    max_stderr_bytes: int,
    runner: Callable[..., object] | None,
) -> dict[str, object]:
    if (
        not argv
        or not Path(argv[0]).is_absolute()
        or any(
            not isinstance(value, str) or not value or any(c in value for c in "\x00\r\n")
            for value in argv
        )
        or any("docker.sock" in value or "podman.sock" in value for value in argv)
        or any(
            value in {"--mount", "--volume", "-v", "--privileged", "--network=host"}
            for value in argv
        )
    ):
        raise OuterBrokerExecutionError("outer broker command argv is invalid")
    if runner is None:
        result = _real_run(
            argv,
            stdin_bytes=stdin_bytes,
            environment=environment,
            timeout_seconds=timeout_seconds,
            max_stdin_bytes=max_stdin_bytes,
            max_stdout_bytes=max_stdout_bytes,
            max_stderr_bytes=max_stderr_bytes,
        )
        observed = int(result["duration_ms"])
    else:
        started = time.monotonic_ns()
        try:
            raw = runner(
                argv,
                stdin_bytes=stdin_bytes,
                environment=environment,
                timeout_seconds=timeout_seconds,
                max_stdin_bytes=max_stdin_bytes,
                max_stdout_bytes=max_stdout_bytes,
                max_stderr_bytes=max_stderr_bytes,
            )
        except Exception as exc:
            raise OuterBrokerExecutionError("outer broker command failed") from exc
        observed = max(0, (time.monotonic_ns() - started) // 1_000_000)
        result = _measure_runner_result(raw, observed_ms=observed)
    stdout = result["stdout"]
    stderr = result["stderr"]
    if (
        len(stdout) > max_stdout_bytes  # type: ignore[arg-type]
        or len(stderr) > max_stderr_bytes  # type: ignore[arg-type]
        or int(result["duration_ms"]) > timeout_seconds * 1_000
    ):
        raise OuterBrokerExecutionError("outer broker command result exceeded its limit")
    return result


def _command_record(argv: tuple[str, ...], result: dict[str, object]) -> dict[str, object]:
    stdout = result["stdout"]
    stderr = result["stderr"]
    return {
        "argv": list(argv),
        "duration_ms": result["duration_ms"],
        "exit_code": result["exit_code"],
        "stderr_base64": base64.b64encode(stderr).decode("ascii"),  # type: ignore[arg-type]
        "stderr_sha256": _sha256(stderr),  # type: ignore[arg-type]
        "stdout_base64": base64.b64encode(stdout).decode("ascii"),  # type: ignore[arg-type]
        "stdout_sha256": _sha256(stdout),  # type: ignore[arg-type]
    }


def _run_record(
    argv: tuple[str, ...],
    *,
    stdin_bytes: bytes,
    environment: dict[str, str],
    timeout_seconds: int,
    max_stdin_bytes: int,
    max_stdout_bytes: int,
    max_stderr_bytes: int,
    runner: Callable[..., object] | None,
) -> dict[str, object]:
    return _command_record(
        argv,
        _run(
            argv,
            stdin_bytes=stdin_bytes,
            environment=environment,
            timeout_seconds=timeout_seconds,
            max_stdin_bytes=max_stdin_bytes,
            max_stdout_bytes=max_stdout_bytes,
            max_stderr_bytes=max_stderr_bytes,
            runner=runner,
        ),
    )


def _record_stdout(record: dict[str, object]) -> bytes:
    try:
        return base64.b64decode(record["stdout_base64"], validate=True)  # type: ignore[arg-type]
    except (TypeError, ValueError) as exc:
        raise OuterBrokerExecutionError("outer broker command record is invalid") from exc


def _runtime_probe_record(
    *,
    runtime_path: Path,
    name: str,
    environment: dict[str, str],
    runner: Callable[..., object] | None,
    probe: Callable[..., subprocess.CompletedProcess] | None,
) -> dict[str, object]:
    argv = (
        (str(runtime_path), "info", "--format", "json")
        if name == "podman"
        else (str(runtime_path), "info", "--format", "{{json .SecurityOptions}}")
    )
    if probe is None:
        record = _run_record(
            argv,
            stdin_bytes=b"",
            environment=environment,
            timeout_seconds=10,
            max_stdin_bytes=2,
            max_stdout_bytes=_MAX_INSPECT_BYTES,
            max_stderr_bytes=_MAX_COMMAND_STDERR_BYTES,
            runner=runner,
        )
    else:
        started = time.monotonic_ns()
        try:
            raw = probe(
                argv,
                check=False,
                capture_output=True,
                env=environment,
                shell=False,
                text=True,
                timeout=10,
            )
            stdout = raw.stdout.encode("utf-8") if isinstance(raw.stdout, str) else raw.stdout
            stderr = raw.stderr.encode("utf-8") if isinstance(raw.stderr, str) else raw.stderr
            result = {
                "exit_code": raw.returncode,
                "stdout": stdout,
                "stderr": stderr,
                "duration_ms": max(0, (time.monotonic_ns() - started) // 1_000_000),
            }
            record = _command_record(argv, result)
        except Exception as exc:
            raise OuterBrokerExecutionError("outer runtime security probe failed") from exc
    if record["exit_code"] != 0:
        raise OuterBrokerExecutionError("outer runtime security probe failed")
    return record


def _decode_runtime_security(
    name: str,
    record: dict[str, object],
) -> tuple[bool, bool, str]:
    try:
        security = json.loads(_record_stdout(record).decode("utf-8", errors="strict"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise OuterBrokerExecutionError("outer runtime security probe failed") from exc
    if name == "podman":
        try:
            host_security = security["host"]["security"]
            rootless = host_security["rootless"]
            seccomp_enabled = host_security["seccompEnabled"]
            seccomp_profile = host_security["seccompProfilePath"]
        except (KeyError, TypeError) as exc:
            raise OuterBrokerExecutionError("outer runtime security probe failed") from exc
        user_namespace = True
    else:
        if not isinstance(security, list) or not all(isinstance(item, str) for item in security):
            raise OuterBrokerExecutionError("outer runtime security probe failed")
        normalized = {item.casefold() for item in security}
        rootless = any("rootless" in item for item in normalized)
        user_namespace = rootless or any("userns" in item for item in normalized)
        seccomp_enabled = any(
            item.startswith("name=seccomp,") and "profile=builtin" in item for item in normalized
        )
        seccomp_profile = "builtin"
    if (
        type(rootless) is not bool
        or type(user_namespace) is not bool
        or (not rootless and not user_namespace)
        or seccomp_enabled is not True
        or not isinstance(seccomp_profile, str)
        or not seccomp_profile
        or "unconfined" in seccomp_profile.casefold()
    ):
        raise OuterBrokerExecutionError("outer runtime security probe failed")
    return rootless, user_namespace, seccomp_profile


def measure_broker_outer_runtime(runtime_executable: Path, candidate_uid: int) -> bytes:
    """Return the path-free canonical runtime binding measured by the stdlib outer process."""

    if (
        isinstance(candidate_uid, bool)
        or not isinstance(candidate_uid, int)
        or candidate_uid <= 0
        or candidate_uid == os.geteuid()
    ):
        raise OuterBrokerExecutionError("outer broker candidate UID is invalid")
    try:
        runtime_path = Path(os.path.abspath(runtime_executable))
    except (OSError, TypeError, ValueError) as exc:
        raise OuterBrokerExecutionError("outer runtime executable is invalid") from exc
    name = runtime_path.name
    if name not in {"podman", "docker"}:
        raise OuterBrokerExecutionError("outer runtime executable is unsupported")
    environment = _base_environment(name)
    before_digest, before_metadata = _measure_runtime(runtime_path, candidate_uid=candidate_uid)
    record = _runtime_probe_record(
        runtime_path=runtime_path,
        name=name,
        environment=environment,
        runner=None,
        probe=None,
    )
    rootless, user_namespace, seccomp_profile = _decode_runtime_security(name, record)
    after_digest, after_metadata = _measure_runtime(runtime_path, candidate_uid=candidate_uid)
    stable = ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_size", "st_mtime_ns")
    if before_digest != after_digest or any(
        getattr(before_metadata, field) != getattr(after_metadata, field) for field in stable
    ):
        raise OuterBrokerExecutionError("outer runtime executable changed during measurement")
    security_evidence_sha256 = _sha256(
        _canonical(
            {
                "name": name,
                "rootless": rootless,
                "seccomp_profile": seccomp_profile,
                "user_namespace": user_namespace,
            }
        )
        + b"\n"
    )
    return _canonical(
        {
            "environment_sha256": _sha256(_canonical(environment)),
            "executable_sha256": before_digest,
            "name": name,
            "rootless": rootless,
            "seccomp_profile": seccomp_profile,
            "security_evidence_sha256": security_evidence_sha256,
            "user_namespace": user_namespace,
        }
    )


def _probe_runtime(
    *,
    runtime_path: Path,
    runtime: dict[str, Any],
    candidate_uid: int,
    environment: dict[str, str],
    runner: Callable[..., object] | None,
    probe: Callable[..., subprocess.CompletedProcess] | None,
) -> dict[str, object]:
    digest, metadata = _measure_runtime(runtime_path, candidate_uid=candidate_uid)
    if digest != runtime["executable_sha256"]:
        raise OuterBrokerExecutionError("outer runtime digest differs from prepared binding")
    record = _runtime_probe_record(
        runtime_path=runtime_path,
        name=runtime["name"],
        environment=environment,
        runner=runner,
        probe=probe,
    )
    rootless, user_namespace, seccomp_profile = _decode_runtime_security(runtime["name"], record)
    measured_security = _sha256(
        _canonical(
            {
                "name": runtime["name"],
                "rootless": rootless,
                "seccomp_profile": seccomp_profile,
                "user_namespace": user_namespace,
            }
        )
        + b"\n"
    )
    if (
        rootless is not runtime["rootless"]
        or user_namespace is not runtime["user_namespace"]
        or seccomp_profile != runtime["seccomp_profile"]
        or measured_security != runtime["security_evidence_sha256"]
    ):
        raise OuterBrokerExecutionError("outer runtime security differs from prepared binding")
    return {
        "command": record,
        "device": metadata.st_dev,
        "inode": metadata.st_ino,
        "runtime_sha256": digest,
        "security_evidence_sha256": measured_security,
    }


def _parse_one_inspect(raw: bytes) -> dict[str, Any]:
    def pairs(values: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in values:
            if key in result:
                raise OuterBrokerExecutionError("outer broker inspect has duplicate keys")
            result[key] = value
        return result

    try:
        value = json.loads(raw.decode("utf-8", errors="strict"), object_pairs_hook=pairs)
    except OuterBrokerExecutionError:
        raise
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise OuterBrokerExecutionError("outer broker inspect is invalid") from exc
    if not isinstance(value, list) or len(value) != 1 or not isinstance(value[0], dict):
        raise OuterBrokerExecutionError("outer broker inspect is invalid")
    return value[0]


def _dict_field(value: dict[str, Any], *names: str) -> dict[str, Any]:
    for name in names:
        item = value.get(name)
        if isinstance(item, dict):
            return item
    raise OuterBrokerExecutionError("outer broker inspect is invalid")


def _value_field(value: dict[str, Any], *names: str) -> Any:
    for name in names:
        if name in value:
            return value[name]
    raise OuterBrokerExecutionError("outer broker inspect is invalid")


def _network_members(payload: dict[str, Any]) -> set[str]:
    containers = _value_field(payload, "Containers", "containers")
    if not isinstance(containers, dict):
        raise OuterBrokerExecutionError("outer broker network inspect is invalid")
    names: set[str] = set()
    for item in containers.values():
        if not isinstance(item, dict):
            raise OuterBrokerExecutionError("outer broker network inspect is invalid")
        name = item.get("Name", item.get("name"))
        if not isinstance(name, str) or not name or name.lstrip("/") in names:
            raise OuterBrokerExecutionError("outer broker network inspect is invalid")
        names.add(name.lstrip("/"))
    return names


def _validate_network(
    raw: bytes,
    *,
    name: str,
    internal: bool,
    gateway_name: str,
    owner: str,
    session: str,
    kind: str,
) -> bytes:
    payload = _parse_one_inspect(raw)
    labels = _dict_field(payload, "Labels", "labels")
    if (
        _value_field(payload, "Name", "name") != name
        or _value_field(payload, "Internal", "internal") is not internal
        or labels.get("ai-review.owner-sha256") != owner
        or labels.get("ai-review.session-sha256") != session
        or labels.get("ai-review.kind") != kind
        or _network_members(payload) != {gateway_name}
    ):
        raise OuterBrokerExecutionError("outer broker network boundary is invalid")
    return _canonical([payload])


def _validate_gateway(
    raw: bytes,
    *,
    name: str,
    image: str,
    internal_network: str,
    external_network: str,
    owner: str,
    session: str,
) -> bytes:
    payload = _parse_one_inspect(raw)
    config = _dict_field(payload, "Config", "config")
    host_config = _dict_field(payload, "HostConfig", "hostConfig")
    state = _dict_field(payload, "State", "state")
    networks = _dict_field(_dict_field(payload, "NetworkSettings"), "Networks", "networks")
    labels = _dict_field(config, "Labels", "labels")
    env = _value_field(config, "Env", "env")
    aliases = networks.get(internal_network, {}).get("Aliases")
    environment_names = (
        {item.split("=", 1)[0].casefold() for item in env}
        if isinstance(env, list) and all(isinstance(item, str) and "=" in item for item in env)
        else set(_FORBIDDEN_GATEWAY_ENV)
    )
    if (
        _value_field(payload, "Name", "name").lstrip("/") != name
        or _value_field(config, "Image", "image") != image
        or _value_field(config, "Entrypoint", "entrypoint") != [_GATEWAY_ENTRYPOINT]
        or _value_field(config, "User", "user") != f"{_CONTAINER_UID}:{_CONTAINER_GID}"
        or _value_field(payload, "Mounts", "mounts") != []
        or host_config.get("Binds", host_config.get("binds")) not in (None, [])
        or {item.casefold() for item in host_config.get("CapDrop", [])} != {"all"}
        or "no-new-privileges"
        not in {item.casefold() for item in host_config.get("SecurityOpt", [])}
        or host_config.get("ReadonlyRootfs") is not True
        or host_config.get("Privileged") is not False
        or set(networks) != {internal_network, external_network}
        or not isinstance(aliases, list)
        or _GATEWAY_ALIAS not in aliases
        or "AI_REVIEW_EGRESS_GATEWAY=1" not in env
        or environment_names & _FORBIDDEN_GATEWAY_ENV
        or labels.get("ai-review.owner-sha256") != owner
        or labels.get("ai-review.session-sha256") != session
        or labels.get("ai-review.kind") != "gateway"
        or not isinstance(_value_field(state, "Running", "running"), bool)
    ):
        raise OuterBrokerExecutionError("outer broker gateway boundary is invalid")
    return _canonical([payload])


def _validate_owned(
    raw: bytes,
    *,
    resource_type: str,
    name: str,
    kind: str,
    owner: str,
    session: str,
) -> None:
    payload = _parse_one_inspect(raw)
    if resource_type == "container":
        labels = _dict_field(_dict_field(payload, "Config", "config"), "Labels", "labels")
    else:
        labels = _dict_field(payload, "Labels", "labels")
    if (
        _value_field(payload, "Name", "name").lstrip("/") != name
        or labels.get("ai-review.owner-sha256") != owner
        or labels.get("ai-review.session-sha256") != session
        or labels.get("ai-review.kind") != kind
    ):
        raise OuterBrokerExecutionError("outer broker cleanup ownership is invalid")


def _network_create(
    runtime: str, *, name: str, internal: bool, owner: str, session: str, kind: str
) -> tuple[str, ...]:
    return (
        runtime,
        "network",
        "create",
        "--driver=bridge",
        *(("--internal",) if internal else ()),
        f"--label=ai-review.owner-sha256={owner}",
        f"--label=ai-review.session-sha256={session}",
        f"--label=ai-review.kind={kind}",
        name,
    )


def _gateway_run(
    runtime_path: str,
    runtime: dict[str, Any],
    *,
    name: str,
    external_network: str,
    image: str,
    owner: str,
    session: str,
) -> tuple[str, ...]:
    userns: tuple[str, ...] = ()
    if runtime["name"] == "podman" and runtime["rootless"]:
        userns = (f"--userns=keep-id:uid={_CONTAINER_UID},gid={_CONTAINER_GID}",)
    elif runtime["name"] == "podman":
        userns = ("--userns=auto",)
    return (
        runtime_path,
        "run",
        "--detach",
        "--pull=never",
        f"--name={name}",
        f"--network={external_network}",
        "--read-only",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "--ipc=none",
        *userns,
        f"--user={_CONTAINER_UID}:{_CONTAINER_GID}",
        "--workdir=/",
        "--pids-limit=32",
        "--memory=128m",
        "--cpus=0.5",
        "--tmpfs=/tmp:rw,noexec,nosuid,nodev,size=4m,mode=1777",
        "--env=AI_REVIEW_EGRESS_GATEWAY=1",
        f"--label=ai-review.owner-sha256={owner}",
        f"--label=ai-review.session-sha256={session}",
        "--label=ai-review.kind=gateway",
        f"--entrypoint={_GATEWAY_ENTRYPOINT}",
        image,
    )


def _absence(runtime: str, kind: str, name: str) -> tuple[str, ...]:
    noun = "container" if kind == "container" else "network"
    format_value = "{{.Names}}" if kind == "container" else "{{.Name}}"
    arguments = [runtime, noun, "ls"]
    if kind == "container":
        arguments.append("--all")
    arguments.extend(("--filter", f"name=^{name}$", f"--format={format_value}"))
    return tuple(arguments)


def _inspect(runtime: str, kind: str, name: str) -> tuple[str, ...]:
    return (runtime, kind, "inspect", "--", name)


def _remove(runtime: str, kind: str, name: str) -> tuple[str, ...]:
    if kind == "container":
        return (runtime, "container", "rm", "-f", "--", name)
    return (runtime, "network", "rm", "--", name)


def _ledger_identity(path: Path, *, candidate_uid: int) -> tuple[int, int, str]:
    metadata = _assert_protected(path, candidate_uid=candidate_uid, regular=True)
    if stat.S_IMODE(metadata.st_mode) & 0o077:
        raise OuterBrokerExecutionError("outer broker ledger permissions are invalid")
    payload = {
        "ledger_device": metadata.st_dev,
        "ledger_inode": metadata.st_ino,
        "ledger_path": str(Path(os.path.abspath(path))),
        "schema_version": "1.0",
    }
    return metadata.st_dev, metadata.st_ino, _sha256(_LEDGER_IDENTITY_DOMAIN + _canonical(payload))


def _validate_outer_ledger_schema(connection: sqlite3.Connection) -> None:
    columns = [
        (str(row[1]), str(row[2]), int(row[3]), int(row[5]))
        for row in connection.execute("PRAGMA table_info(broker_reservations)")
    ]
    tables = [
        row for row in connection.execute("PRAGMA table_list") if row[1] == "broker_reservations"
    ]
    objects = list(
        connection.execute(
            "SELECT type,name,tbl_name,sql FROM sqlite_schema "
            "WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name"
        )
    )
    if (
        columns
        != [
            ("packet_sha256", "TEXT", 1, 1),
            ("role", "TEXT", 1, 2),
            ("attempt", "INTEGER", 1, 3),
            ("reserved_tokens", "INTEGER", 1, 0),
            ("reserved_cost_microusd", "INTEGER", 1, 0),
            ("reservation_unix_ns", "INTEGER", 1, 0),
        ]
        or len(tables) != 1
        or int(tables[0][5]) != 1
        or objects != [("table", "broker_reservations", "broker_reservations", _LEDGER_SCHEMA_SQL)]
    ):
        raise OuterBrokerExecutionError("outer broker ledger schema is invalid")


def prepare_broker_outer_ledger(ledger_path: Path, *, candidate_uid: int) -> str:
    """Create one protected empty ledger and return its immutable host identity digest.

    This function is the stdlib-only architecture-B initialization boundary.  It intentionally
    refuses an existing pathname instead of adopting caller-created SQLite state.
    """

    if (
        isinstance(candidate_uid, bool)
        or not isinstance(candidate_uid, int)
        or candidate_uid <= 0
        or candidate_uid == os.geteuid()
    ):
        raise OuterBrokerExecutionError("outer broker candidate UID is invalid")
    try:
        absolute = Path(os.path.abspath(ledger_path))
    except (OSError, TypeError, ValueError) as exc:
        raise OuterBrokerExecutionError("outer broker ledger path is invalid") from exc
    if absolute == Path(absolute.anchor) or absolute.name in {"", ".", ".."}:
        raise OuterBrokerExecutionError("outer broker ledger path is invalid")
    parent = absolute.parent
    parent_metadata = _assert_protected(parent, candidate_uid=candidate_uid, regular=False)
    if (
        not stat.S_ISDIR(parent_metadata.st_mode)
        or parent_metadata.st_uid != os.geteuid()
        or stat.S_IMODE(parent_metadata.st_mode) & 0o077
    ):
        raise OuterBrokerExecutionError("outer broker ledger parent is not private")
    descriptor: int | None = None
    connection: sqlite3.Connection | None = None
    created_identity: tuple[int, int] | None = None
    succeeded = False
    try:
        flags = (
            os.O_RDWR
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        try:
            descriptor = os.open(absolute, flags, 0o600)
        except FileExistsError as exc:
            raise OuterBrokerExecutionError("outer broker ledger already exists") from exc
        metadata = os.fstat(descriptor)
        created_identity = (metadata.st_dev, metadata.st_ino)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) != 0o600
        ):
            raise OuterBrokerExecutionError("outer broker ledger creation is invalid")
        os.close(descriptor)
        descriptor = None
        connection = sqlite3.connect(absolute, timeout=5, isolation_level=None)
        connection.execute("PRAGMA busy_timeout = 5000")
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA trusted_schema = OFF")
        connection.execute("PRAGMA journal_mode = DELETE")
        connection.execute("PRAGMA synchronous = FULL")
        connection.execute("BEGIN IMMEDIATE")
        connection.execute(_LEDGER_SCHEMA_SQL)
        connection.execute("COMMIT")
        _validate_outer_ledger_schema(connection)
        if connection.execute("PRAGMA integrity_check").fetchone() != ("ok",):
            raise OuterBrokerExecutionError("outer broker ledger integrity check failed")
        connection.close()
        connection = None
        descriptor = os.open(absolute, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = None
        parent_descriptor = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(parent_descriptor)
        finally:
            os.close(parent_descriptor)
        identity = _ledger_identity(absolute, candidate_uid=candidate_uid)
        if identity[:2] != created_identity:
            raise OuterBrokerExecutionError("outer broker ledger changed during initialization")
        succeeded = True
        return identity[2]
    except OuterBrokerExecutionError:
        raise
    except (OSError, sqlite3.Error, TypeError, ValueError) as exc:
        raise OuterBrokerExecutionError("outer broker ledger initialization failed") from exc
    finally:
        if connection is not None:
            if connection.in_transaction:
                try:
                    connection.execute("ROLLBACK")
                except sqlite3.Error:
                    pass
            connection.close()
        if descriptor is not None:
            os.close(descriptor)
        if not succeeded and created_identity is not None:
            try:
                current = os.lstat(absolute)
                if (current.st_dev, current.st_ino) == created_identity:
                    os.unlink(absolute)
            except OSError:
                pass


def _reserve(*, ledger_path: Path, batch: dict[str, Any], run: dict[str, Any]) -> dict[str, object]:
    device, inode, identity = _ledger_identity(ledger_path, candidate_uid=batch["candidate_uid"])
    if identity != batch["broker_ledger_identity_sha256"]:
        raise OuterBrokerExecutionError("outer broker ledger identity changed")
    connection: sqlite3.Connection | None = None
    try:
        connection = sqlite3.connect(ledger_path, timeout=5, isolation_level=None)
        connection.execute("PRAGMA busy_timeout = 5000")
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA trusted_schema = OFF")
        connection.execute("PRAGMA journal_mode = DELETE")
        connection.execute("PRAGMA synchronous = FULL")
        columns = [
            (str(row[1]), str(row[2]), int(row[3]), int(row[5]))
            for row in connection.execute("PRAGMA table_info(broker_reservations)")
        ]
        if columns != [
            ("packet_sha256", "TEXT", 1, 1),
            ("role", "TEXT", 1, 2),
            ("attempt", "INTEGER", 1, 3),
            ("reserved_tokens", "INTEGER", 1, 0),
            ("reserved_cost_microusd", "INTEGER", 1, 0),
            ("reservation_unix_ns", "INTEGER", 1, 0),
        ]:
            raise OuterBrokerExecutionError("outer broker ledger schema is invalid")
        connection.execute("BEGIN IMMEDIATE")
        attempts = [
            row[0]
            for row in connection.execute(
                "SELECT attempt FROM broker_reservations "
                "WHERE packet_sha256=? AND role=? ORDER BY attempt",
                (run["packet_sha256"], run["role"]),
            )
        ]
        if attempts != list(range(1, len(attempts) + 1)) or run["attempt"] != len(attempts) + 1:
            raise OuterBrokerExecutionError("outer broker attempt reservation rejected")
        totals = connection.execute(
            "SELECT COALESCE(SUM(reserved_tokens),0),"
            "COALESCE(SUM(reserved_cost_microusd),0) FROM broker_reservations "
            "WHERE packet_sha256=?",
            (run["packet_sha256"],),
        ).fetchone()
        if totals is None:
            raise OuterBrokerExecutionError("outer broker ledger totals are invalid")
        cumulative = totals[0] + run["reserved_tokens"]
        cumulative_cost = totals[1] + run["reserved_cost_microusd"]
        if (
            cumulative > batch["broker_packet_reservation_limit"]
            or cumulative_cost > batch["broker_packet_cost_limit_microusd"]
        ):
            raise OuterBrokerExecutionError("outer broker packet reservation rejected")
        reservation_unix_ns = time.time_ns()
        connection.execute(
            "INSERT INTO broker_reservations "
            "(packet_sha256,role,attempt,reserved_tokens,reserved_cost_microusd,reservation_unix_ns) "
            "VALUES (?,?,?,?,?,?)",
            (
                run["packet_sha256"],
                run["role"],
                run["attempt"],
                run["reserved_tokens"],
                run["reserved_cost_microusd"],
                reservation_unix_ns,
            ),
        )
        rows = [
            {
                "attempt": row[2],
                "packet_sha256": row[0],
                "reservation_unix_ns": row[5],
                "reserved_cost_microusd": row[4],
                "reserved_tokens": row[3],
                "role": row[1],
            }
            for row in connection.execute(
                "SELECT packet_sha256,role,attempt,reserved_tokens,reserved_cost_microusd,"
                "reservation_unix_ns FROM broker_reservations "
                "WHERE packet_sha256=? ORDER BY role,attempt",
                (run["packet_sha256"],),
            )
        ]
        measured_unix_ns = time.time_ns()
        connection.execute("COMMIT")
    except OuterBrokerExecutionError:
        if connection is not None and connection.in_transaction:
            connection.execute("ROLLBACK")
        raise
    except (OSError, sqlite3.Error, TypeError, ValueError) as exc:
        if connection is not None and connection.in_transaction:
            connection.execute("ROLLBACK")
        raise OuterBrokerExecutionError("outer broker ledger reservation failed") from exc
    finally:
        if connection is not None:
            connection.close()
    after_device, after_inode, after_identity = _ledger_identity(
        ledger_path, candidate_uid=batch["candidate_uid"]
    )
    if (after_device, after_inode, after_identity) != (device, inode, identity):
        raise OuterBrokerExecutionError("outer broker ledger changed during reservation")
    return {
        "broker_ledger_identity_sha256": identity,
        "cumulative_reserved_cost_microusd": cumulative_cost,
        "cumulative_reserved_tokens": cumulative,
        "ledger_device": device,
        "ledger_inode": inode,
        "measured_unix_ns": measured_unix_ns,
        "records": rows,
        "reservation_unix_ns": reservation_unix_ns,
    }


def _measure_frozen_ledger(*, ledger_path: Path, batch: dict[str, Any]) -> dict[str, object]:
    """Freeze the final protected ledger into the canonical cross-namespace evidence stream."""

    device, inode, identity = _ledger_identity(ledger_path, candidate_uid=batch["candidate_uid"])
    if identity != batch["broker_ledger_identity_sha256"]:
        raise OuterBrokerExecutionError("outer broker ledger identity changed")
    connection: sqlite3.Connection | None = None
    try:
        absolute = Path(os.path.abspath(ledger_path))
        connection = sqlite3.connect(
            absolute.as_uri() + "?mode=ro",
            uri=True,
            timeout=5,
            isolation_level=None,
        )
        connection.execute("PRAGMA busy_timeout = 5000")
        connection.execute("PRAGMA trusted_schema = OFF")
        connection.execute("PRAGMA query_only = ON")
        columns = [
            (str(row[1]), str(row[2]), int(row[3]), int(row[5]))
            for row in connection.execute("PRAGMA table_info(broker_reservations)")
        ]
        if columns != [
            ("packet_sha256", "TEXT", 1, 1),
            ("role", "TEXT", 1, 2),
            ("attempt", "INTEGER", 1, 3),
            ("reserved_tokens", "INTEGER", 1, 0),
            ("reserved_cost_microusd", "INTEGER", 1, 0),
            ("reservation_unix_ns", "INTEGER", 1, 0),
        ]:
            raise OuterBrokerExecutionError("outer broker ledger schema is invalid")
        connection.execute("BEGIN")
        records = [
            {
                "attempt": row[2],
                "packet_sha256": row[0],
                "reservation_unix_ns": row[5],
                "reserved_cost_microusd": row[4],
                "reserved_tokens": row[3],
                "role": row[1],
            }
            for row in connection.execute(
                "SELECT packet_sha256,role,attempt,reserved_tokens,reserved_cost_microusd,"
                "reservation_unix_ns FROM broker_reservations "
                "WHERE packet_sha256=? ORDER BY role,attempt",
                (batch["review_packet_sha256"],),
            )
        ]
        measured_unix_ns = time.time_ns()
        connection.execute("COMMIT")
    except OuterBrokerExecutionError:
        if connection is not None and connection.in_transaction:
            connection.execute("ROLLBACK")
        raise
    except (OSError, sqlite3.Error, TypeError, ValueError) as exc:
        if connection is not None and connection.in_transaction:
            connection.execute("ROLLBACK")
        raise OuterBrokerExecutionError("outer broker final ledger measurement failed") from exc
    finally:
        if connection is not None:
            connection.close()
    after = _ledger_identity(ledger_path, candidate_uid=batch["candidate_uid"])
    if after != (device, inode, identity):
        raise OuterBrokerExecutionError("outer broker ledger changed during measurement")
    attempts: dict[str, list[int]] = {"reviewer": [], "adversary": []}
    cumulative_tokens = 0
    cumulative_cost = 0
    for record in records:
        role = record["role"]
        attempt = record["attempt"]
        tokens = record["reserved_tokens"]
        cost = record["reserved_cost_microusd"]
        timestamp = record["reservation_unix_ns"]
        if (
            role not in attempts
            or isinstance(attempt, bool)
            or not isinstance(attempt, int)
            or not 1 <= attempt <= 2
            or isinstance(tokens, bool)
            or not isinstance(tokens, int)
            or not 1 <= tokens <= 272_000
            or isinstance(cost, bool)
            or not isinstance(cost, int)
            or not 1 <= cost <= 7_940_000
            or isinstance(timestamp, bool)
            or not isinstance(timestamp, int)
            or timestamp <= 0
        ):
            raise OuterBrokerExecutionError("outer broker final ledger record is invalid")
        attempts[role].append(attempt)
        cumulative_tokens += tokens
        cumulative_cost += cost
    if (
        not records
        or any(values != list(range(1, len(values) + 1)) for values in attempts.values())
        or cumulative_tokens > batch["broker_packet_reservation_limit"]
        or cumulative_cost > batch["broker_packet_cost_limit_microusd"]
    ):
        raise OuterBrokerExecutionError("outer broker final ledger records are invalid")
    records_bytes = _canonical(
        {
            "packet_sha256": batch["review_packet_sha256"],
            "records": records,
            "schema_version": "1.0",
        }
    )
    frozen: dict[str, object] = {
        "broker_ledger_identity_sha256": identity,
        "broker_packet_cost_limit_microusd": batch["broker_packet_cost_limit_microusd"],
        "broker_packet_reservation_limit": batch["broker_packet_reservation_limit"],
        "broker_pricing_policy_sha256": batch["broker_pricing_policy_sha256"],
        "cumulative_reserved_cost_microusd": cumulative_cost,
        "cumulative_reserved_tokens": cumulative_tokens,
        "ledger_device": device,
        "ledger_inode": inode,
        "ledger_path": str(Path(os.path.abspath(ledger_path))),
        "measured_unix_ns": measured_unix_ns,
        "packet_sha256": batch["review_packet_sha256"],
        "records": records,
        "records_sha256": _sha256(records_bytes),
        "schema_version": "1.0",
    }
    frozen["final_ledger_sha256"] = _domain_sha256(_FROZEN_LEDGER_DOMAIN, frozen)
    return frozen


def _generic_record(
    argv: tuple[str, ...],
    *,
    environment: dict[str, str],
    runner: Callable[..., object] | None,
) -> dict[str, object]:
    return _run_record(
        argv,
        stdin_bytes=b"",
        environment=environment,
        timeout_seconds=30,
        max_stdin_bytes=2,
        max_stdout_bytes=_MAX_INSPECT_BYTES,
        max_stderr_bytes=_MAX_COMMAND_STDERR_BYTES,
        runner=runner,
    )


def _require_success(record: dict[str, object]) -> None:
    if record["exit_code"] != 0:
        raise OuterBrokerExecutionError("outer broker lifecycle command failed")


def _execute_one(
    *,
    batch: dict[str, Any],
    run: dict[str, Any],
    credential: str,
    ledger_path: Path,
    runtime_path: Path,
    environment: dict[str, str],
    runtime_pre: dict[str, object],
    runner: Callable[..., object] | None,
    stream_runner: Callable[..., object] | None,
    probe: Callable[..., subprocess.CompletedProcess] | None,
    broker_cleanup: Callable[..., object] | None,
) -> dict[str, object]:
    if (
        not isinstance(credential, str)
        or not 1 <= len(credential) <= 512
        or any(ord(character) < 33 or ord(character) > 126 for character in credential)
    ):
        raise OuterBrokerExecutionError("outer broker credential is invalid")
    started_unix_ns = time.time_ns()
    started = time.monotonic_ns()
    runtime = batch["_runtime"]
    runtime_text = str(runtime_path)
    values = _invocation_values(run)
    external_network = _domain_name("ai-review-egress-net-", _EXTERNAL_NETWORK_DOMAIN, values)
    gateway_name = (
        "ai-review-egress-gateway-" + run["broker_internal_network"].rsplit("-", 1)[-1][-16:]
    )
    owner = _sha256(_OWNER_DOMAIN + _canonical(list(values)))
    session = _sha256(_SESSION_DOMAIN + os.urandom(32))
    if (
        _EXTERNAL_NETWORK_RE.fullmatch(external_network) is None
        or _SHA256_RE.fullmatch(session) is None
    ):
        raise OuterBrokerExecutionError("outer broker lifecycle names are invalid")
    provisioning: list[dict[str, object]] = []
    post: list[dict[str, object]] = []
    cleanup: list[dict[str, object]] = []
    absence: list[dict[str, object]] = []
    created_internal = created_external = created_gateway = False
    broker_cleanup_record: dict[str, object] | None = None
    broker_record: dict[str, object] | None = None
    broker_attempted = False
    broker_started_unix_ns = 0
    reservation: dict[str, object] | None = None
    failure: BaseException | None = None
    pre_canonical: tuple[bytes, bytes, bytes] | None = None

    def clean_broker_container() -> dict[str, object]:
        cleanup_argv = (runtime_text, "rm", "-f", "--", run["container_name"])
        if broker_cleanup is None:
            return _generic_record(cleanup_argv, environment=environment, runner=runner)
        cleanup_started = time.monotonic_ns()
        try:
            raw_cleanup = broker_cleanup(runtime, run["container_name"], environment)
            exit_code = getattr(raw_cleanup, "exit_code", 0 if raw_cleanup is True else 1)
            duration = getattr(raw_cleanup, "duration_ms", 0)
            return _command_record(
                cleanup_argv,
                {
                    "exit_code": exit_code,
                    "stdout": b"",
                    "stderr": b"",
                    "duration_ms": max(
                        duration,
                        max(0, (time.monotonic_ns() - cleanup_started) // 1_000_000),
                    ),
                },
            )
        except Exception as exc:
            raise OuterBrokerExecutionError("outer broker container cleanup failed") from exc

    try:
        preflight = (
            _absence(runtime_text, "container", gateway_name),
            _absence(runtime_text, "network", run["broker_internal_network"]),
            _absence(runtime_text, "network", external_network),
        )
        for argv in preflight:
            record = _generic_record(argv, environment=environment, runner=runner)
            provisioning.append(record)
            if record["exit_code"] != 0 or _record_stdout(record):
                raise OuterBrokerExecutionError("outer broker lifecycle name collision")
        create_internal = _network_create(
            runtime_text,
            name=run["broker_internal_network"],
            internal=True,
            owner=owner,
            session=session,
            kind="broker-internal",
        )
        created_internal = True
        record = _generic_record(create_internal, environment=environment, runner=runner)
        provisioning.append(record)
        _require_success(record)
        create_external = _network_create(
            runtime_text,
            name=external_network,
            internal=False,
            owner=owner,
            session=session,
            kind="gateway-external",
        )
        created_external = True
        record = _generic_record(create_external, environment=environment, runner=runner)
        provisioning.append(record)
        _require_success(record)
        gateway_argv = _gateway_run(
            runtime_text,
            runtime,
            name=gateway_name,
            external_network=external_network,
            image=batch["gateway_image"],
            owner=owner,
            session=session,
        )
        created_gateway = True
        record = _generic_record(gateway_argv, environment=environment, runner=runner)
        provisioning.append(record)
        _require_success(record)
        connect_argv = (
            runtime_text,
            "network",
            "connect",
            "--alias",
            _GATEWAY_ALIAS,
            run["broker_internal_network"],
            gateway_name,
        )
        record = _generic_record(connect_argv, environment=environment, runner=runner)
        provisioning.append(record)
        _require_success(record)
        inspect_argvs = (
            _inspect(runtime_text, "network", run["broker_internal_network"]),
            _inspect(runtime_text, "network", external_network),
            _inspect(runtime_text, "container", gateway_name),
        )
        inspect_records = []
        for argv in inspect_argvs:
            record = _generic_record(argv, environment=environment, runner=runner)
            provisioning.append(record)
            _require_success(record)
            inspect_records.append(record)
        pre_canonical = (
            _validate_network(
                _record_stdout(inspect_records[0]),
                name=run["broker_internal_network"],
                internal=True,
                gateway_name=gateway_name,
                owner=owner,
                session=session,
                kind="broker-internal",
            ),
            _validate_network(
                _record_stdout(inspect_records[1]),
                name=external_network,
                internal=False,
                gateway_name=gateway_name,
                owner=owner,
                session=session,
                kind="gateway-external",
            ),
            _validate_gateway(
                _record_stdout(inspect_records[2]),
                name=gateway_name,
                image=batch["gateway_image"],
                internal_network=run["broker_internal_network"],
                external_network=external_network,
                owner=owner,
                session=session,
            ),
        )
        reservation = _reserve(ledger_path=ledger_path, batch=batch, run=run)
        broker_argv = (runtime_text, *run["_descriptor_argv"][1:])
        broker_environment = {**environment, _CREDENTIAL_ENV: credential}
        broker_started_unix_ns = time.time_ns()
        broker_attempted = True
        broker_record = _run_record(
            broker_argv,
            stdin_bytes=run["_stdin"],
            environment=broker_environment,
            timeout_seconds=batch["timeout_seconds"],
            max_stdin_bytes=batch["max_stdin_bytes"],
            max_stdout_bytes=batch["max_stdout_bytes"],
            max_stderr_bytes=batch["max_stderr_bytes"],
            runner=stream_runner,
        )
        broker_cleanup_record = clean_broker_container()
        _require_success(broker_cleanup_record)
        if broker_record["exit_code"] != 0:
            raise OuterBrokerExecutionError("outer broker process failed")
        broker_stdout = _record_stdout(broker_record)
        if credential.encode("ascii") in broker_stdout:
            raise OuterBrokerExecutionError("outer broker output contains credential material")
        for argv in inspect_argvs:
            record = _generic_record(argv, environment=environment, runner=runner)
            post.append(record)
            _require_success(record)
        post_canonical = (
            _validate_network(
                _record_stdout(post[0]),
                name=run["broker_internal_network"],
                internal=True,
                gateway_name=gateway_name,
                owner=owner,
                session=session,
                kind="broker-internal",
            ),
            _validate_network(
                _record_stdout(post[1]),
                name=external_network,
                internal=False,
                gateway_name=gateway_name,
                owner=owner,
                session=session,
                kind="gateway-external",
            ),
            _validate_gateway(
                _record_stdout(post[2]),
                name=gateway_name,
                image=batch["gateway_image"],
                internal_network=run["broker_internal_network"],
                external_network=external_network,
                owner=owner,
                session=session,
            ),
        )
        if post_canonical != pre_canonical:
            raise OuterBrokerExecutionError("outer broker egress boundary changed during execution")
    except BaseException as exc:
        failure = exc
    finally:
        targets = (
            (created_gateway, "container", gateway_name, "gateway"),
            (created_internal, "network", run["broker_internal_network"], "broker-internal"),
            (created_external, "network", external_network, "gateway-external"),
        )
        cleanup_ok = True
        if broker_attempted and broker_cleanup_record is None:
            try:
                broker_cleanup_record = clean_broker_container()
                _require_success(broker_cleanup_record)
            except BaseException:
                cleanup_ok = False
        for created, kind, name, label_kind in targets:
            if not created:
                continue
            try:
                inspected = _generic_record(
                    _inspect(runtime_text, kind, name), environment=environment, runner=runner
                )
                cleanup.append(inspected)
                _require_success(inspected)
                _validate_owned(
                    _record_stdout(inspected),
                    resource_type=kind,
                    name=name,
                    kind=label_kind,
                    owner=owner,
                    session=session,
                )
                removed = _generic_record(
                    _remove(runtime_text, kind, name), environment=environment, runner=runner
                )
                cleanup.append(removed)
                _require_success(removed)
            except BaseException:
                cleanup_ok = False
        for created, kind, name, _label_kind in targets:
            if not created:
                continue
            try:
                record = _generic_record(
                    _absence(runtime_text, kind, name), environment=environment, runner=runner
                )
                absence.append(record)
                if record["exit_code"] != 0 or _record_stdout(record):
                    cleanup_ok = False
            except BaseException:
                cleanup_ok = False
        if not cleanup_ok:
            failure = OuterBrokerExecutionError("outer broker cleanup could not be attested")
    if failure is not None:
        if isinstance(failure, OuterBrokerExecutionError):
            raise failure
        raise OuterBrokerExecutionError("outer broker execution failed") from failure
    if (
        reservation is None
        or broker_record is None
        or broker_cleanup_record is None
        or pre_canonical is None
    ):
        raise OuterBrokerExecutionError("outer broker execution evidence is incomplete")
    runtime_post = _probe_runtime(
        runtime_path=runtime_path,
        runtime=runtime,
        candidate_uid=batch["candidate_uid"],
        environment=environment,
        runner=runner,
        probe=probe,
    )
    if (
        runtime_pre["runtime_sha256"] != runtime_post["runtime_sha256"]
        or runtime_pre["security_evidence_sha256"] != runtime_post["security_evidence_sha256"]
        or (runtime_pre["device"], runtime_pre["inode"])
        != (runtime_post["device"], runtime_post["inode"])
    ):
        raise OuterBrokerExecutionError("outer broker runtime changed during execution")
    result: dict[str, object] = {
        "broker_cleanup_command": broker_cleanup_record,
        "broker_command": broker_record,
        "broker_started_unix_ns": broker_started_unix_ns,
        "cleanup_commands": cleanup,
        "cleanup_succeeded": True,
        "descriptor_sha256": run["descriptor_sha256"],
        "duration_ms": max(0, (time.monotonic_ns() - started) // 1_000_000),
        "environment_sha256": _sha256(_canonical(environment)),
        "gateway_container_name": gateway_name,
        "gateway_external_network": external_network,
        "owner_sha256": owner,
        "post_cleanup_absence_commands": absence,
        "post_execution_inspect_commands": post,
        "provisioning_commands": provisioning,
        "reservation": reservation,
        "role": run["role"],
        "runtime_post": runtime_post,
        "runtime_pre": runtime_pre,
        "schema_version": "1.0",
        "session_sha256": session,
        "started_unix_ns": started_unix_ns,
    }
    result["run_evidence_sha256"] = _domain_sha256(_OUTER_RUN_DOMAIN, result)
    return result


def _outer_payload(evidence: dict[str, Any], *, include_digest: bool) -> dict[str, object]:
    payload = {
        "batch_sha256": evidence["batch_sha256"],
        "duration_ms": evidence["duration_ms"],
        "final_ledger": evidence["final_ledger"],
        "runs": evidence["runs"],
        "schema_version": evidence["schema_version"],
        "started_unix_ns": evidence["started_unix_ns"],
    }
    if include_digest:
        payload["outer_evidence_sha256"] = evidence["outer_evidence_sha256"]
    return payload


def canonical_outer_broker_evidence_bytes(evidence: Mapping[str, object]) -> bytes:
    """Return the only canonical byte encoding accepted by coordinator finalization."""

    if not isinstance(evidence, Mapping):
        raise OuterBrokerExecutionError("outer broker evidence type is invalid")
    payload = dict(evidence)
    expected = {
        "batch_sha256",
        "duration_ms",
        "final_ledger",
        "outer_evidence_sha256",
        "runs",
        "schema_version",
        "started_unix_ns",
    }
    if set(payload) != expected:
        raise OuterBrokerExecutionError("outer broker evidence has missing or unknown fields")
    unsigned = _outer_payload(payload, include_digest=False)
    if payload["schema_version"] != "1.0" or payload["outer_evidence_sha256"] != _domain_sha256(
        _OUTER_BATCH_DOMAIN, unsigned
    ):
        raise OuterBrokerExecutionError("outer broker evidence digest is invalid")
    raw = _canonical(payload)
    if len(raw) > _MAX_OUTER_EVIDENCE_BYTES:
        raise OuterBrokerExecutionError("outer broker evidence exceeds its byte limit")
    return raw


def _execute_prepared_broker_outer(
    prepared_batch: bytes,
    *,
    credentials: Mapping[str, str],
    ledger_path: Path,
    runtime_executable: Path,
    require_two: bool,
    runner: Callable[..., object] | None,
    stream_runner: Callable[..., object] | None,
    probe: Callable[..., subprocess.CompletedProcess] | None,
    broker_cleanup: Callable[..., object] | None,
) -> bytes:
    batch = _parse_prepared_batch(prepared_batch, require_two=require_two)
    if set(credentials) != {run["role"] for run in batch["_runs"]}:
        raise OuterBrokerExecutionError("outer broker credentials do not match the prepared roles")
    runtime_path = Path(os.path.abspath(runtime_executable))
    if runtime_path.name != batch["_runtime"]["name"]:
        raise OuterBrokerExecutionError("outer runtime executable name is not prepared")
    environment = _base_environment(batch["_runtime"]["name"])
    if _sha256(_canonical(environment)) != batch["_runtime"]["environment_sha256"]:
        raise OuterBrokerExecutionError("outer runtime environment differs from prepared binding")
    runtime_pre = _probe_runtime(
        runtime_path=runtime_path,
        runtime=batch["_runtime"],
        candidate_uid=batch["candidate_uid"],
        environment=environment,
        runner=runner,
        probe=probe,
    )
    started_unix_ns = time.time_ns()
    started = time.monotonic_ns()
    runs = []
    for run in batch["_runs"]:
        runs.append(
            _execute_one(
                batch=batch,
                run=run,
                credential=credentials[run["role"]],
                ledger_path=ledger_path,
                runtime_path=runtime_path,
                environment=environment,
                runtime_pre=runtime_pre,
                runner=runner,
                stream_runner=stream_runner,
                probe=probe,
                broker_cleanup=broker_cleanup,
            )
        )
    final_ledger = _measure_frozen_ledger(ledger_path=ledger_path, batch=batch)
    evidence: dict[str, object] = {
        "batch_sha256": batch["batch_sha256"],
        "duration_ms": max(0, (time.monotonic_ns() - started) // 1_000_000),
        "final_ledger": final_ledger,
        "runs": runs,
        "schema_version": "1.0",
        "started_unix_ns": started_unix_ns,
        "outer_evidence_sha256": "0" * 64,
    }
    evidence["outer_evidence_sha256"] = _domain_sha256(
        _OUTER_BATCH_DOMAIN,
        _outer_payload(evidence, include_digest=False),
    )
    return canonical_outer_broker_evidence_bytes(evidence)


def execute_prepared_broker_outer(
    prepared_batch: bytes,
    *,
    credentials: Mapping[str, str],
    ledger_path: Path,
    runtime_executable: Path,
) -> bytes:
    """Execute the exact two-role batch in the root-owned stdlib outer process."""

    return _execute_prepared_broker_outer(
        prepared_batch,
        credentials=credentials,
        ledger_path=ledger_path,
        runtime_executable=runtime_executable,
        require_two=True,
        runner=None,
        stream_runner=None,
        probe=None,
        broker_cleanup=None,
    )
