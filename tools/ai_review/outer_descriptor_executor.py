"""Stdlib-only executor for coordinator-approved offline and broker descriptors.

This module is deliberately importable by the root-owned ``-I -S`` launcher.  It does not
interpret candidate code or import the harness model layer: the pinned coordinator emits one
canonical descriptor, and this executor accepts only the two closed container profiles below.
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
import stat
import subprocess
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any


_DOMAIN = b"amazon-explorer-outer-execution-descriptor-v1\0"
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_IMAGE_RE = re.compile(r"^[^@\s]+@(sha256:[0-9a-f]{64})$")
_CONTAINER_RE = re.compile(r"^ai-review-(?:offline|broker)-[0-9a-f]{24}$")
_BROKER_NETWORK_RE = re.compile(r"^--network=ai-review-broker-[0-9a-f]{24}$")
_OFFLINE_MOUNT_PREFIX = "type=bind,src="
_OFFLINE_MOUNT_SUFFIX = ",dst=/workspace,readonly,bind-propagation=rprivate"
_FORBIDDEN_MOUNT_PARTS = {
    ".aws",
    ".cache",
    ".docker",
    ".git",
    ".gnupg",
    ".kube",
    ".ssh",
    "candidate",
    "credentials",
    "secrets",
}
_FORBIDDEN_MOUNT_TREES = tuple(
    Path(value) for value in ("/boot", "/dev", "/etc", "/proc", "/root", "/run", "/sys")
)
_FORBIDDEN_BROAD_MOUNTS = tuple(
    Path(value) for value in ("/", "/home", "/media", "/mnt", "/opt", "/srv", "/usr", "/var")
)
_MAX_STDIN = 6_000_000
_MAX_OUTPUT = 6_000_000


class OuterDescriptorError(RuntimeError):
    """Raised before or during a fail-closed descriptor execution."""


def _canonical(value: object) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")


def _domain_sha256(payload: dict[str, object]) -> str:
    return hashlib.sha256(_DOMAIN + _canonical(payload)).hexdigest()


def _strict_json(raw: bytes) -> dict[str, Any]:
    def pairs(values: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in values:
            if key in result:
                raise OuterDescriptorError("outer descriptor contains a duplicate key")
            result[key] = value
        return result

    try:
        value = json.loads(raw.decode("utf-8", errors="strict"), object_pairs_hook=pairs)
    except OuterDescriptorError:
        raise
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise OuterDescriptorError("outer descriptor is not strict JSON") from exc
    if not isinstance(value, dict) or raw != _canonical(value):
        raise OuterDescriptorError("outer descriptor is not canonical JSON")
    return value


def _rehash_executable(path: Path, *, candidate_uid: int) -> tuple[str, os.stat_result]:
    try:
        current = Path(path.anchor)
        for part in path.parts[1:]:
            current /= part
            component = os.lstat(current)
            if (
                stat.S_ISLNK(component.st_mode)
                or component.st_uid == candidate_uid
                or (component.st_mode & 0o022 and not component.st_mode & stat.S_ISVTX)
            ):
                raise OuterDescriptorError("outer runtime path is candidate-accessible")
        before = os.lstat(path)
        if (
            not path.is_absolute()
            or not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_mode & 0o022
            or not before.st_mode & 0o111
        ):
            raise OuterDescriptorError("outer runtime executable is not protected")
        digest = hashlib.sha256()
        total = 0
        with path.open("rb") as stream:
            while chunk := stream.read(1024 * 1024):
                total += len(chunk)
                if total > 128 * 1024 * 1024:
                    raise OuterDescriptorError("outer runtime executable exceeds its byte limit")
                digest.update(chunk)
        after = os.lstat(path)
    except OSError as exc:
        raise OuterDescriptorError("outer runtime executable could not be measured") from exc
    stable = ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_size", "st_mtime_ns")
    if any(getattr(before, name) != getattr(after, name) for name in stable):
        raise OuterDescriptorError("outer runtime executable changed during measurement")
    return digest.hexdigest(), after


def _candidate_may_write(metadata: os.stat_result, candidate_uid: int) -> bool:
    mode = stat.S_IMODE(metadata.st_mode)
    if metadata.st_uid == candidate_uid and mode & stat.S_IWUSR:
        return True
    return bool(mode & (stat.S_IWGRP | stat.S_IWOTH))


def _candidate_may_replace(
    *, parent: os.stat_result, child: os.stat_result, candidate_uid: int
) -> bool:
    if not _candidate_may_write(parent, candidate_uid):
        return False
    if not stat.S_IMODE(parent.st_mode) & stat.S_ISVTX:
        return True
    return candidate_uid in {parent.st_uid, child.st_uid}


def _validate_offline_mount_source(value: str, *, candidate_uid: int) -> str:
    if not value.startswith(_OFFLINE_MOUNT_PREFIX) or not value.endswith(_OFFLINE_MOUNT_SUFFIX):
        raise OuterDescriptorError("offline mount source is not canonical")
    source = value[len(_OFFLINE_MOUNT_PREFIX) : -len(_OFFLINE_MOUNT_SUFFIX)]
    path = Path(source)
    lowered = source.casefold()
    if (
        not source
        or not path.is_absolute()
        or str(path) != source
        or os.path.normpath(source) != source
        or any(character in source for character in (",", "\n", "\r", "\x00"))
        or "docker.sock" in lowered
        or "podman.sock" in lowered
        or any(part.casefold() in _FORBIDDEN_MOUNT_PARTS for part in path.parts)
        or path in _FORBIDDEN_BROAD_MOUNTS
        or any(path == root or path.is_relative_to(root) for root in _FORBIDDEN_MOUNT_TREES)
    ):
        raise OuterDescriptorError("offline mount source is forbidden")

    private_parent_found = False
    try:
        parent_metadata = os.lstat(path.anchor)
        current = Path(path.anchor)
        for part in path.parts[1:]:
            current /= part
            child_metadata = os.lstat(current)
            if (
                stat.S_ISLNK(child_metadata.st_mode)
                or child_metadata.st_uid == candidate_uid
                or _candidate_may_replace(
                    parent=parent_metadata,
                    child=child_metadata,
                    candidate_uid=candidate_uid,
                )
            ):
                raise OuterDescriptorError("offline mount source is candidate-accessible")
            if current != path and (
                stat.S_ISDIR(child_metadata.st_mode)
                and child_metadata.st_uid == os.geteuid()
                and stat.S_IMODE(child_metadata.st_mode) == 0o700
            ):
                private_parent_found = True
            parent_metadata = child_metadata
    except FileNotFoundError as exc:
        raise OuterDescriptorError("offline mount source does not exist") from exc
    except OSError as exc:
        raise OuterDescriptorError("offline mount source could not be inspected") from exc
    if (
        not stat.S_ISDIR(parent_metadata.st_mode)
        or parent_metadata.st_uid == candidate_uid
        or stat.S_IMODE(parent_metadata.st_mode) != 0o555
        or not private_parent_found
    ):
        raise OuterDescriptorError("offline mount source is not a protected read-only directory")
    return value


@dataclass(frozen=True)
class OuterExecutionDescriptor:
    schema_version: str
    kind: str
    request_sha256: str
    candidate_uid: int
    runtime_path: Path
    runtime_sha256: str
    image: str
    approved_image_digest: str
    container_name: str
    argv: tuple[str, ...]
    environment: dict[str, str]
    stdin: bytes
    stdin_sha256: str
    timeout_seconds: int
    max_output_bytes: int
    allowed_exit_codes: tuple[int, ...]
    cleanup_argv: tuple[str, ...]
    descriptor_sha256: str

    @classmethod
    def parse(cls, raw: bytes) -> OuterExecutionDescriptor:
        payload = _strict_json(raw)
        fields = {
            "schema_version",
            "kind",
            "request_sha256",
            "candidate_uid",
            "runtime_path",
            "runtime_sha256",
            "image",
            "approved_image_digest",
            "container_name",
            "argv",
            "environment",
            "stdin_base64",
            "stdin_sha256",
            "timeout_seconds",
            "max_output_bytes",
            "allowed_exit_codes",
            "cleanup_argv",
            "descriptor_sha256",
        }
        if set(payload) != fields:
            raise OuterDescriptorError("outer descriptor has missing or unknown fields")
        unsigned = {key: value for key, value in payload.items() if key != "descriptor_sha256"}
        if not isinstance(payload["descriptor_sha256"], str) or not secrets_compare(
            payload["descriptor_sha256"], _domain_sha256(unsigned)
        ):
            raise OuterDescriptorError("outer descriptor canonical digest is invalid")
        try:
            stdin = base64.b64decode(payload["stdin_base64"], validate=True)
            descriptor = cls(
                schema_version=payload["schema_version"],
                kind=payload["kind"],
                request_sha256=payload["request_sha256"],
                candidate_uid=payload["candidate_uid"],
                runtime_path=Path(payload["runtime_path"]),
                runtime_sha256=payload["runtime_sha256"],
                image=payload["image"],
                approved_image_digest=payload["approved_image_digest"],
                container_name=payload["container_name"],
                argv=tuple(payload["argv"]),
                environment=dict(payload["environment"]),
                stdin=stdin,
                stdin_sha256=payload["stdin_sha256"],
                timeout_seconds=payload["timeout_seconds"],
                max_output_bytes=payload["max_output_bytes"],
                allowed_exit_codes=tuple(payload["allowed_exit_codes"]),
                cleanup_argv=tuple(payload["cleanup_argv"]),
                descriptor_sha256=payload["descriptor_sha256"],
            )
        except (TypeError, ValueError, UnicodeError) as exc:
            raise OuterDescriptorError("outer descriptor field type is invalid") from exc
        descriptor.validate()
        return descriptor

    @classmethod
    def create(
        cls,
        *,
        kind: str,
        request_sha256: str,
        candidate_uid: int,
        runtime_path: Path,
        runtime_sha256: str,
        image: str,
        approved_image_digest: str,
        container_name: str,
        argv: tuple[str, ...],
        stdin: bytes,
        allowed_exit_codes: tuple[int, ...] = (0,),
        timeout_seconds: int = 300,
        max_output_bytes: int = 2_000_000,
    ) -> bytes:
        payload: dict[str, object] = {
            "schema_version": "1.0",
            "kind": kind,
            "request_sha256": request_sha256,
            "candidate_uid": candidate_uid,
            "runtime_path": str(runtime_path),
            "runtime_sha256": runtime_sha256,
            "image": image,
            "approved_image_digest": approved_image_digest,
            "container_name": container_name,
            "argv": list(argv),
            "environment": {"LC_ALL": "C", "PATH": os.defpath},
            "stdin_base64": base64.b64encode(stdin).decode("ascii"),
            "stdin_sha256": hashlib.sha256(stdin).hexdigest(),
            "timeout_seconds": timeout_seconds,
            "max_output_bytes": max_output_bytes,
            "allowed_exit_codes": list(allowed_exit_codes),
            "cleanup_argv": [str(runtime_path), "rm", "-f", "--", container_name],
        }
        return _canonical({**payload, "descriptor_sha256": _domain_sha256(payload)})

    def validate(self) -> None:
        if self.schema_version != "1.0" or self.kind not in {"offline", "broker"}:
            raise OuterDescriptorError("outer descriptor kind or version is invalid")
        if any(
            _SHA256_RE.fullmatch(value) is None
            for value in (
                self.request_sha256,
                self.runtime_sha256,
                self.stdin_sha256,
                self.descriptor_sha256,
            )
        ):
            raise OuterDescriptorError("outer descriptor contains an invalid SHA-256")
        if (
            isinstance(self.candidate_uid, bool)
            or not 1 <= self.candidate_uid <= 2**32 - 2
            or self.candidate_uid == os.geteuid()
        ):
            raise OuterDescriptorError("outer descriptor candidate UID is invalid")
        measured, _metadata = _rehash_executable(
            self.runtime_path,
            candidate_uid=self.candidate_uid,
        )
        if not secrets_compare(measured, self.runtime_sha256):
            raise OuterDescriptorError("outer runtime differs from the coordinator descriptor")
        image_match = _IMAGE_RE.fullmatch(self.image)
        if image_match is None or image_match.group(1) != self.approved_image_digest:
            raise OuterDescriptorError("outer descriptor image is not pinned")
        if _CONTAINER_RE.fullmatch(self.container_name) is None:
            raise OuterDescriptorError("outer descriptor container name is invalid")
        if (
            not self.stdin
            or len(self.stdin) > _MAX_STDIN
            or not secrets_compare(hashlib.sha256(self.stdin).hexdigest(), self.stdin_sha256)
        ):
            raise OuterDescriptorError("outer descriptor stdin binding is invalid")
        if (
            isinstance(self.timeout_seconds, bool)
            or not 1 <= self.timeout_seconds <= 900
            or isinstance(self.max_output_bytes, bool)
            or not 1_024 <= self.max_output_bytes <= _MAX_OUTPUT
            or not self.allowed_exit_codes
            or len(set(self.allowed_exit_codes)) != len(self.allowed_exit_codes)
            or any(
                isinstance(code, bool) or not 0 <= code <= 255 for code in self.allowed_exit_codes
            )
        ):
            raise OuterDescriptorError("outer descriptor execution limits are invalid")
        if self.environment != {"LC_ALL": "C", "PATH": os.defpath}:
            raise OuterDescriptorError("outer descriptor environment is not canonical")
        if self.cleanup_argv != (
            str(self.runtime_path),
            "rm",
            "-f",
            "--",
            self.container_name,
        ):
            raise OuterDescriptorError("outer descriptor cleanup command is invalid")
        self._validate_argv()

    def _validate_argv(self) -> None:
        if (
            not 20 <= len(self.argv) <= 256
            or self.argv[:2] != (str(self.runtime_path), "run")
            or any(
                not isinstance(value, str) or not value or "\x00" in value for value in self.argv
            )
            or any(
                "docker.sock" in value.casefold() or "podman.sock" in value.casefold()
                for value in self.argv
            )
            or any(value in {"--privileged", "--network=host"} for value in self.argv)
            or self.argv.count(self.image) != 1
        ):
            raise OuterDescriptorError("outer descriptor argv is not an approved container command")
        common = (
            str(self.runtime_path),
            "run",
            "--rm",
            "--pull=never",
            f"--name={self.container_name}",
            "--read-only",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            "--ipc=none",
            "--userns=keep-id:uid=65532,gid=65532",
            "--user=65532:65532",
            "--pids-limit=128",
            "--memory=1g",
            "--cpus=1",
            "--tmpfs=/tmp:rw,noexec,nosuid,nodev,size=32m,mode=1777",
            "--env=PYTHONDONTWRITEBYTECODE=1",
            "--env=PYTHONNOUSERSITE=1",
        )
        mounts = [
            self.argv[index + 1] for index, value in enumerate(self.argv[:-1]) if value == "--mount"
        ]
        if self.kind == "offline":
            if "--network=none" not in self.argv or len(mounts) != 1:
                raise OuterDescriptorError("offline descriptor mount or network policy is invalid")
            mount = _validate_offline_mount_source(
                mounts[0],
                candidate_uid=self.candidate_uid,
            )
            expected = (*common, "--network=none", "--mount", mount, self.image, "worker")
        else:
            networks = tuple(value for value in self.argv if _BROKER_NETWORK_RE.fullmatch(value))
            if mounts or len(networks) != 1:
                raise OuterDescriptorError("broker descriptor may receive only packet stdin")
            if any(value == "/candidate" or value.startswith("/candidate/") for value in self.argv):
                raise OuterDescriptorError("broker descriptor contains a candidate path")
            expected = (*common, networks[0], self.image, "worker")
        if self.argv != expected:
            raise OuterDescriptorError(
                "outer descriptor argv is not the canonical container profile"
            )


def secrets_compare(left: str, right: str) -> bool:
    return hmac.compare_digest(left, right)


def _kill_group(process: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except (OSError, ProcessLookupError):
        process.kill()


def _bounded_run(
    descriptor: OuterExecutionDescriptor,
    *,
    credential: str | None,
) -> tuple[int, bytes, bytes, int]:
    environment = dict(descriptor.environment)
    if descriptor.kind == "broker":
        if not isinstance(credential, str) or not credential or "\x00" in credential:
            raise OuterDescriptorError("broker execution requires an out-of-band credential")
        environment["OPENAI_API_KEY"] = credential
    elif credential is not None:
        raise OuterDescriptorError("offline execution must not receive a broker credential")
    started = time.monotonic_ns()
    try:
        process = subprocess.Popen(
            descriptor.argv,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=environment,
            shell=False,
            start_new_session=True,
        )
    except OSError as exc:
        raise OuterDescriptorError("outer container runtime could not start") from exc
    if process.stdin is None or process.stdout is None or process.stderr is None:
        _kill_group(process)
        raise OuterDescriptorError("outer runtime pipes were not created")
    write_error: list[BaseException] = []

    def write_stdin() -> None:
        try:
            process.stdin.write(descriptor.stdin)
            process.stdin.close()
        except (BrokenPipeError, OSError) as exc:
            write_error.append(exc)

    writer = threading.Thread(target=write_stdin, daemon=True)
    writer.start()
    selector = selectors.DefaultSelector()
    streams = {process.stdout: bytearray(), process.stderr: bytearray()}
    try:
        for stream in streams:
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ)
        deadline = time.monotonic() + descriptor.timeout_seconds
        total = 0
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                _kill_group(process)
                raise OuterDescriptorError("outer descriptor execution timed out")
            for key, _mask in selector.select(min(remaining, 0.25)):
                stream = key.fileobj
                try:
                    chunk = os.read(stream.fileno(), 64 * 1024)
                except BlockingIOError:
                    continue
                if not chunk:
                    selector.unregister(stream)
                    continue
                total += len(chunk)
                if total > descriptor.max_output_bytes:
                    _kill_group(process)
                    raise OuterDescriptorError("outer descriptor output exceeded its byte limit")
                streams[stream].extend(chunk)
        exit_code = process.wait(timeout=max(0.1, deadline - time.monotonic()))
        writer.join(timeout=1)
        if writer.is_alive() or write_error:
            raise OuterDescriptorError("outer descriptor stdin could not be delivered")
        return (
            exit_code,
            bytes(streams[process.stdout]),
            bytes(streams[process.stderr]),
            max(0, (time.monotonic_ns() - started) // 1_000_000),
        )
    finally:
        selector.close()
        for stream in streams:
            stream.close()
        if process.poll() is None:
            _kill_group(process)
            process.wait(timeout=5)


def execute_outer_descriptor(raw: bytes, *, credential: str | None = None) -> bytes:
    """Execute one exact descriptor, always clean up, and return canonical bounded evidence."""

    descriptor = OuterExecutionDescriptor.parse(raw)
    pre_sha256, pre_metadata = _rehash_executable(
        descriptor.runtime_path,
        candidate_uid=descriptor.candidate_uid,
    )
    cleanup_succeeded = False
    try:
        exit_code, stdout, stderr, duration_ms = _bounded_run(
            descriptor,
            credential=credential,
        )
    finally:
        try:
            cleanup = subprocess.run(
                descriptor.cleanup_argv,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                env=descriptor.environment,
                check=False,
                shell=False,
                timeout=30,
            )
            cleanup_succeeded = cleanup.returncode == 0
        except (OSError, subprocess.TimeoutExpired):
            cleanup_succeeded = False
    post_sha256, post_metadata = _rehash_executable(
        descriptor.runtime_path,
        candidate_uid=descriptor.candidate_uid,
    )
    if (
        not cleanup_succeeded
        or exit_code not in descriptor.allowed_exit_codes
        or not secrets_compare(pre_sha256, post_sha256)
        or (pre_metadata.st_dev, pre_metadata.st_ino)
        != (
            post_metadata.st_dev,
            post_metadata.st_ino,
        )
    ):
        raise OuterDescriptorError("outer descriptor execution or cleanup failed closed")
    evidence = {
        "schema_version": "1.0",
        "kind": descriptor.kind,
        "request_sha256": descriptor.request_sha256,
        "descriptor_sha256": descriptor.descriptor_sha256,
        "runtime_sha256": post_sha256,
        "exit_code": exit_code,
        "stdout_base64": base64.b64encode(stdout).decode("ascii"),
        "stdout_sha256": hashlib.sha256(stdout).hexdigest(),
        "stderr_base64": base64.b64encode(stderr).decode("ascii"),
        "stderr_sha256": hashlib.sha256(stderr).hexdigest(),
        "duration_ms": duration_ms,
        "cleanup_succeeded": True,
    }
    return _canonical(evidence)
