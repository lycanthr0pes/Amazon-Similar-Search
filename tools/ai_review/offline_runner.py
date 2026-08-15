"""Fail-closed OS-isolated execution with bounded, digest-bound evidence."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import selectors
import shutil
import signal
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable
from typing import Sequence

from tools.ai_review.preflight import PreflightError
from tools.ai_review.preflight import assert_candidate_cannot_mutate
from tools.ai_review.preflight import read_protected_file
from tools.ai_review.snapshot import SnapshotEvidence
from tools.ai_review.snapshot import verify_readonly_snapshot


IMAGE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/:+-]*@(sha256:[0-9a-f]{64})$")
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
GIT_SHA_RE = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
CONTAINER_NAME_RE = re.compile(r"^ai-review-[0-9a-f]{24}$")
CONTROL_DIRECTORY_RE = re.compile(r"^\.run-[a-z0-9_]{8}$")
ACCEPTANCE_ID_RE = re.compile(r"^[A-Z][A-Z0-9_-]{0,63}$")
SUPPORTED_BACKENDS = ("podman", "docker")
CONTAINER_UID = 65_534
CONTAINER_GID = 65_534
_FAILURE_FINGERPRINT_DOMAIN = b"amazon-explorer-offline-failure-v1\0"
_EXECUTION_RESPONSE_DOMAIN = b"amazon-explorer-offline-response-v1\0"


class OfflineRunnerError(RuntimeError):
    """Raised when isolation inputs or execution violate the runner contract."""


class ContainerUnavailableError(OfflineRunnerError):
    """Raised instead of falling back to unsandboxed host execution."""


@dataclass(frozen=True)
class ContainerBackend:
    name: str
    executable: Path
    rootless: bool
    user_namespace: bool
    seccomp_enabled: bool
    seccomp_profile: str
    sha256: str = ""
    security_evidence_sha256: str = ""


@dataclass(frozen=True)
class RunRequest:
    phase: str
    acceptance_test_id: str
    session_id: str
    source_commit_sha: str
    source_commit_tree_sha: str
    source_snapshot_sha256: str
    task_sha256: str
    candidate_sha256: str
    candidate_snapshot_sha256: str
    execution_snapshot_sha256: str
    test_patch_sha256: str | None
    test_manifest_sha256: str | None
    command: tuple[str, ...]
    runner_image_digest: str

    def canonical_bytes(self) -> bytes:
        return _canonical_json(
            {
                "acceptance_test_id": self.acceptance_test_id,
                "candidate_sha256": self.candidate_sha256,
                "candidate_snapshot_sha256": self.candidate_snapshot_sha256,
                "command": list(self.command),
                "execution_snapshot_sha256": self.execution_snapshot_sha256,
                "phase": self.phase,
                "runner_image_digest": self.runner_image_digest,
                "session_id": self.session_id,
                "source_commit_sha": self.source_commit_sha,
                "source_commit_tree_sha": self.source_commit_tree_sha,
                "source_snapshot_sha256": self.source_snapshot_sha256,
                "task_sha256": self.task_sha256,
                "test_patch_sha256": self.test_patch_sha256,
                "test_manifest_sha256": self.test_manifest_sha256,
            }
        )

    def sha256(self) -> str:
        return hashlib.sha256(self.canonical_bytes()).hexdigest()


@dataclass(frozen=True)
class OfflineRunEvidence:
    request: RunRequest
    request_sha256: str
    runtime_name: str
    runtime_sha256: str
    runtime_security_sha256: str
    runtime_rootless: bool
    runtime_user_namespace: bool
    runtime_seccomp_profile: str
    runner_image_digest: str
    snapshot_sha256: str
    argv: tuple[str, ...]
    argv_sha256: str
    container_id: str
    exit_code: int
    stdout: bytes
    stderr: bytes
    stdout_sha256: str
    stderr_sha256: str
    log: bytes
    log_sha256: str
    log_truncated: bool
    stdout_bytes: int
    stderr_bytes: int
    started_unix_ns: int
    duration_ms: int
    cleanup_succeeded: bool
    failure_fingerprint_sha256: str
    response_sha256: str


@dataclass(frozen=True)
class _BoundedProcessResult:
    exit_code: int
    stdout: bytes
    stderr: bytes
    stdout_sha256: str
    stderr_sha256: str
    duration_ms: int


def _canonical_json(payload: object) -> bytes:
    return (
        json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")


def _stream_binding(stdout: bytes, stderr: bytes) -> dict[str, int | str]:
    if not isinstance(stdout, bytes) or not isinstance(stderr, bytes):
        raise OfflineRunnerError("offline stdout and stderr must be raw bytes")
    return {
        "stderr_bytes": len(stderr),
        "stderr_sha256": hashlib.sha256(stderr).hexdigest(),
        "stdout_bytes": len(stdout),
        "stdout_sha256": hashlib.sha256(stdout).hexdigest(),
    }


def offline_log_sha256(stdout: bytes, stderr: bytes) -> str:
    """Digest the exact raw streams without trusting caller-supplied stream hashes."""

    return hashlib.sha256(_canonical_json(_stream_binding(stdout, stderr))).hexdigest()


def failure_fingerprint_sha256(*, exit_code: int, stdout: bytes, stderr: bytes) -> str:
    """Build the TaskSpec RED fingerprint from the measured failure, not a report field."""

    if isinstance(exit_code, bool) or not isinstance(exit_code, int):
        raise OfflineRunnerError("offline exit code must be a strict integer")
    payload = {"exit_code": exit_code, **_stream_binding(stdout, stderr)}
    return hashlib.sha256(_FAILURE_FINGERPRINT_DOMAIN + _canonical_json(payload)).hexdigest()


def execution_response_sha256(
    *,
    exit_code: int,
    stdout: bytes,
    stderr: bytes,
    container_id: str,
    cleanup_succeeded: bool,
    log_truncated: bool,
) -> str:
    """Digest the complete execution response independently from signed claims."""

    if isinstance(exit_code, bool) or not isinstance(exit_code, int):
        raise OfflineRunnerError("offline exit code must be a strict integer")
    if not re.fullmatch(r"[0-9a-f]{12,64}", container_id):
        raise OfflineRunnerError("container ID is invalid")
    if type(cleanup_succeeded) is not bool or type(log_truncated) is not bool:
        raise OfflineRunnerError("offline cleanup and truncation evidence must be booleans")
    payload = {
        "cleanup_succeeded": cleanup_succeeded,
        "container_id": container_id,
        "exit_code": exit_code,
        "log_truncated": log_truncated,
        **_stream_binding(stdout, stderr),
    }
    return hashlib.sha256(_EXECUTION_RESPONSE_DOMAIN + _canonical_json(payload)).hexdigest()


def _system_which(name: str) -> str | None:
    return shutil.which(name, path=os.defpath)


def _base_host_environment(name: str) -> dict[str, str]:
    environment = {"PATH": os.defpath, "LC_ALL": "C"}
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        runtime_directory = Path(f"/run/user/{os.geteuid()}")
        if runtime_directory.is_dir() and not runtime_directory.is_symlink():
            environment["XDG_RUNTIME_DIR"] = str(runtime_directory)
            docker_socket = runtime_directory / "docker.sock"
            if name == "docker" and docker_socket.exists() and not docker_socket.is_symlink():
                environment["DOCKER_HOST"] = f"unix://{docker_socket}"
    return environment


def _validate_backend(backend: ContainerBackend, *, candidate_uid: int) -> ContainerBackend:
    if backend.name not in SUPPORTED_BACKENDS:
        raise OfflineRunnerError("container backend must be Podman or Docker")
    if not isinstance(backend.rootless, bool) or not isinstance(backend.user_namespace, bool):
        raise OfflineRunnerError("container backend isolation mode is invalid")
    if not backend.rootless and not backend.user_namespace:
        raise OfflineRunnerError("rootful container backend requires a user namespace")
    if (
        backend.seccomp_enabled is not True
        or not backend.seccomp_profile
        or "unconfined" in backend.seccomp_profile.casefold()
    ):
        raise OfflineRunnerError("container backend requires an active seccomp profile")
    try:
        resolved = backend.executable.resolve(strict=True)
        evidence, _raw = read_protected_file(
            resolved,
            candidate_uid=candidate_uid,
            label=f"{backend.name} executable",
        )
    except (OSError, PreflightError) as exc:
        raise OfflineRunnerError(str(exc)) from exc
    if not evidence.mode & 0o111:
        raise OfflineRunnerError("container backend executable is not executable")
    if backend.sha256 and backend.sha256 != evidence.sha256:
        raise OfflineRunnerError("container backend executable changed after detection")
    security_sha256 = _security_evidence_sha256(
        backend.name,
        backend.rootless,
        backend.user_namespace,
        backend.seccomp_profile,
    )
    if backend.security_evidence_sha256 and backend.security_evidence_sha256 != security_sha256:
        raise OfflineRunnerError("container backend security evidence changed after detection")
    return ContainerBackend(
        name=backend.name,
        executable=evidence.path,
        rootless=backend.rootless,
        user_namespace=backend.user_namespace,
        seccomp_enabled=True,
        seccomp_profile=backend.seccomp_profile,
        sha256=evidence.sha256,
        security_evidence_sha256=security_sha256,
    )


def _security_evidence_sha256(
    name: str, rootless: bool, user_namespace: bool, seccomp_profile: str
) -> str:
    return hashlib.sha256(
        _canonical_json(
            {
                "name": name,
                "rootless": rootless,
                "seccomp_profile": seccomp_profile,
                "user_namespace": user_namespace,
            }
        )
    ).hexdigest()


def _probe_backend(
    *,
    name: str,
    executable: Path,
    probe: Callable[..., subprocess.CompletedProcess] | None,
) -> tuple[bool, bool, str]:
    if name == "podman":
        argv = (str(executable), "info", "--format", "json")
    else:
        argv = (str(executable), "info", "--format", "{{json .SecurityOptions}}")
    try:
        if probe is None:
            bounded = _run_bounded(
                argv,
                environment=_base_host_environment(name),
                timeout_seconds=10,
                max_output_bytes=64_000,
            )
            returncode = bounded.exit_code
            stdout = bounded.stdout.decode("utf-8")
        else:
            result = probe(
                argv,
                check=False,
                capture_output=True,
                env=_base_host_environment(name),
                shell=False,
                text=True,
                timeout=10,
            )
            returncode = result.returncode
            stdout = result.stdout
        if returncode != 0 or not isinstance(stdout, str) or len(stdout.encode("utf-8")) > 64_000:
            raise OfflineRunnerError("container backend info probe failed")
        payload = json.loads(stdout)
    except (
        OSError,
        UnicodeDecodeError,
        subprocess.TimeoutExpired,
        json.JSONDecodeError,
        TypeError,
    ) as exc:
        raise OfflineRunnerError("container backend info probe failed") from exc
    if name == "podman":
        try:
            security = payload["host"]["security"]
            rootless = security["rootless"]
            seccomp_enabled = security["seccompEnabled"]
            seccomp_profile = security["seccompProfilePath"]
        except (KeyError, TypeError) as exc:
            raise OfflineRunnerError("Podman did not report rootless and seccomp state") from exc
        if (
            not isinstance(rootless, bool)
            or seccomp_enabled is not True
            or not isinstance(seccomp_profile, str)
            or not seccomp_profile
            or "unconfined" in seccomp_profile.casefold()
        ):
            raise OfflineRunnerError("Podman did not attest an active seccomp profile")
        return rootless, True, seccomp_profile
    if not isinstance(payload, list) or not all(isinstance(item, str) for item in payload):
        raise OfflineRunnerError("Docker did not report its security options")
    normalized = {item.casefold() for item in payload}
    rootless = any("rootless" in item for item in normalized)
    user_namespace = rootless or any("userns" in item for item in normalized)
    seccomp_options = {item for item in normalized if item.startswith("name=seccomp,")}
    if not any("profile=builtin" in item for item in seccomp_options):
        raise OfflineRunnerError("Docker did not attest its builtin seccomp profile")
    return rootless, user_namespace, "builtin"


def detect_container_backend(
    *,
    candidate_uid: int | None = None,
    which: Callable[[str], str | None] = _system_which,
    probe: Callable[..., subprocess.CompletedProcess] | None = None,
) -> ContainerBackend:
    """Probe a supported runtime and reject absent or insufficient isolation."""

    failures: list[str] = []
    for name in SUPPORTED_BACKENDS:
        path = which(name)
        if path is None:
            continue
        if candidate_uid is None:
            raise OfflineRunnerError("candidate UID is required to trust a container backend")
        try:
            resolved = Path(path).resolve(strict=True)
            rootless, user_namespace, seccomp_profile = _probe_backend(
                name=name, executable=resolved, probe=probe
            )
            return _validate_backend(
                ContainerBackend(
                    name=name,
                    executable=resolved,
                    rootless=rootless,
                    user_namespace=user_namespace,
                    seccomp_enabled=True,
                    seccomp_profile=seccomp_profile,
                ),
                candidate_uid=candidate_uid,
            )
        except (OSError, OfflineRunnerError) as exc:
            failures.append(f"{name}: {exc}")
    detail = "; ".join(failures)
    suffix = f" ({detail})" if detail else ""
    raise ContainerUnavailableError(
        "Podman or Docker with user-namespace isolation is required; refusing host execution"
        + suffix
    )


def _validate_image(image: str, approved_image_digest: str) -> None:
    match = IMAGE_RE.fullmatch(image)
    if match is None:
        raise OfflineRunnerError("runner image must be pinned by a sha256 digest")
    if DIGEST_RE.fullmatch(approved_image_digest) is None:
        raise OfflineRunnerError("approved runner image digest is invalid")
    if match.group(1) != approved_image_digest:
        raise OfflineRunnerError("runner image digest does not match the runtime manifest")


def _validate_command(command: Sequence[str]) -> tuple[str, ...]:
    values = tuple(command)
    if not values or len(values) > 256:
        raise OfflineRunnerError("offline command must contain between 1 and 256 arguments")
    if any(not isinstance(value, str) or not value or "\x00" in value for value in values):
        raise OfflineRunnerError("offline command arguments must be non-empty strings without NUL")
    return values


def _user_namespace_argv(backend: ContainerBackend) -> tuple[str, ...]:
    if backend.name == "podman" and backend.rootless:
        return (f"--userns=keep-id:uid={CONTAINER_UID},gid={CONTAINER_GID}",)
    if backend.name == "podman":
        return ("--userns=auto",)
    # A rootful Docker daemon was accepted only when ``docker info`` attested userns-remap.
    # Omitting --userns preserves that daemon default; ``--userns=host`` would disable it.
    return ()


def _compose_offline_container_argv(
    *,
    backend: ContainerBackend,
    snapshot_tree: Path,
    image: str,
    command: tuple[str, ...],
    container_name: str | None = None,
    cidfile: Path | None = None,
) -> tuple[str, ...]:
    control_arguments: tuple[str, ...] = ()
    if container_name is not None and cidfile is not None:
        control_arguments = (f"--name={container_name}", f"--cidfile={cidfile}")
    snapshot_path = str(snapshot_tree)
    mount = f"type=bind,src={snapshot_path},dst=/workspace,readonly,bind-propagation=rprivate"
    return (
        str(backend.executable),
        "run",
        "--pull=never",
        *control_arguments,
        "--network=none",
        "--read-only",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "--ipc=none",
        *_user_namespace_argv(backend),
        f"--user={CONTAINER_UID}:{CONTAINER_GID}",
        "--workdir=/workspace",
        "--pids-limit=256",
        "--memory=2g",
        "--cpus=2",
        "--tmpfs=/tmp:rw,noexec,nosuid,nodev,size=64m,mode=1777",
        "--tmpfs=/run:rw,noexec,nosuid,nodev,size=16m,mode=0755",
        "--env=PYTHONDONTWRITEBYTECODE=1",
        "--env=PYTHONNOUSERSITE=1",
        "--mount",
        mount,
        image,
        *command,
    )


def build_offline_container_argv(
    *,
    backend: ContainerBackend,
    snapshot: SnapshotEvidence,
    image: str,
    approved_image_digest: str,
    command: Sequence[str],
    candidate_uid: int,
    container_name: str | None = None,
    cidfile: Path | None = None,
) -> tuple[str, ...]:
    """Build one read-only mount, no-network, non-root exec-form container argv."""

    trusted_backend = _validate_backend(backend, candidate_uid=candidate_uid)
    verified = verify_readonly_snapshot(snapshot.root, candidate_uid=candidate_uid)
    if verified.snapshot_sha256 != snapshot.snapshot_sha256:
        raise OfflineRunnerError("snapshot evidence changed before container execution")
    _validate_image(image, approved_image_digest)
    container_command = _validate_command(command)
    if (container_name is None) != (cidfile is None):
        raise OfflineRunnerError("container name and cidfile must be supplied together")
    if container_name is not None and cidfile is not None:
        if CONTAINER_NAME_RE.fullmatch(container_name) is None:
            raise OfflineRunnerError("container name is invalid")
        try:
            parent = assert_candidate_cannot_mutate(cidfile.parent, candidate_uid=candidate_uid)
        except PreflightError as exc:
            raise OfflineRunnerError(str(exc)) from exc
        if cidfile.exists() or cidfile.is_symlink() or parent != cidfile.parent:
            raise OfflineRunnerError("cidfile must be a new file in the trusted control directory")
    snapshot_path = str(verified.tree)
    if any(character in snapshot_path for character in (",", "\n", "\r", "\x00")):
        raise OfflineRunnerError("snapshot path cannot be represented safely as a bind mount")
    return _compose_offline_container_argv(
        backend=trusted_backend,
        snapshot_tree=verified.tree,
        image=image,
        command=container_command,
        container_name=container_name,
        cidfile=cidfile,
    )


def _kill_process_group(process: subprocess.Popen) -> None:
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except (OSError, ProcessLookupError):
        try:
            process.kill()
        except OSError:
            pass


def _run_bounded(
    argv: tuple[str, ...],
    *,
    environment: dict[str, str],
    timeout_seconds: int,
    max_output_bytes: int,
) -> _BoundedProcessResult:
    started = time.monotonic_ns()
    try:
        process = subprocess.Popen(
            argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=environment,
            shell=False,
            start_new_session=True,
        )
    except OSError as exc:
        raise OfflineRunnerError("failed to start isolated container runtime") from exc
    selector = selectors.DefaultSelector()
    if process.stdout is None or process.stderr is None:
        _kill_process_group(process)
        raise OfflineRunnerError("container runtime pipes were not created")
    streams = {
        process.stdout: (bytearray(), hashlib.sha256()),
        process.stderr: (bytearray(), hashlib.sha256()),
    }
    try:
        for stream in streams:
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ)
        deadline = time.monotonic() + timeout_seconds
        total = 0
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                _kill_process_group(process)
                raise OfflineRunnerError("isolated candidate execution timed out")
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
                if total > max_output_bytes:
                    _kill_process_group(process)
                    raise OfflineRunnerError("isolated candidate output exceeded the byte limit")
                buffer, digest = streams[stream]
                buffer.extend(chunk)
                digest.update(chunk)
        exit_code = process.wait(timeout=max(0.1, deadline - time.monotonic()))
        stdout_buffer, stdout_digest = streams[process.stdout]
        stderr_buffer, stderr_digest = streams[process.stderr]
        return _BoundedProcessResult(
            exit_code=exit_code,
            stdout=bytes(stdout_buffer),
            stderr=bytes(stderr_buffer),
            stdout_sha256=stdout_digest.hexdigest(),
            stderr_sha256=stderr_digest.hexdigest(),
            duration_ms=max(0, (time.monotonic_ns() - started) // 1_000_000),
        )
    finally:
        selector.close()
        for stream in streams:
            stream.close()
        if process.poll() is None:
            _kill_process_group(process)
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                pass


def _cleanup_container(
    backend: ContainerBackend,
    container_name: str,
    environment: dict[str, str],
) -> bool:
    try:
        result = subprocess.run(
            [str(backend.executable), "rm", "-f", "--", container_name],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=environment,
            shell=False,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return result.returncode == 0


def _read_container_id(cidfile: Path, *, candidate_uid: int) -> str:
    try:
        evidence, raw = read_protected_file(
            cidfile,
            candidate_uid=candidate_uid,
            label="container ID file",
            max_bytes=128,
        )
    except PreflightError as exc:
        raise OfflineRunnerError(str(exc)) from exc
    try:
        container_id = raw.decode("ascii").strip()
    except UnicodeDecodeError as exc:
        raise OfflineRunnerError("container ID is invalid") from exc
    if not re.fullmatch(r"[0-9a-f]{12,64}", container_id) or evidence.size > 128:
        raise OfflineRunnerError("container ID is invalid")
    return container_id


def execute_offline(
    *,
    snapshot_root: Path,
    image: str,
    approved_image_digest: str,
    command: Sequence[str],
    phase: str,
    acceptance_test_id: str,
    session_id: str,
    task_sha256: str,
    candidate_sha256: str,
    source_snapshot_sha256: str,
    test_patch_sha256: str | None,
    test_manifest_sha256: str | None = None,
    candidate_snapshot_sha256: str | None = None,
    candidate_uid: int,
    timeout_seconds: int = 900,
    max_log_bytes: int = 1_000_000,
    which: Callable[[str], str | None] = _system_which,
    probe: Callable[..., subprocess.CompletedProcess] | None = None,
    stream_runner: Callable[..., _BoundedProcessResult] = _run_bounded,
    cleanup: Callable[[ContainerBackend, str, dict[str, str]], bool] = _cleanup_container,
) -> OfflineRunEvidence:
    """Run a digest-bound request and always remove its explicitly named container."""

    if isinstance(timeout_seconds, bool) or not 1 <= timeout_seconds <= 3600:
        raise OfflineRunnerError("offline runner timeout must be between 1 and 3600 seconds")
    if isinstance(max_log_bytes, bool) or not 1_024 <= max_log_bytes <= 10_000_000:
        raise OfflineRunnerError("offline runner log limit must be between 1024 and 10000000 bytes")
    if phase not in {"gate", "red", "green"}:
        raise OfflineRunnerError("offline runner phase must be gate, red, or green")
    if ACCEPTANCE_ID_RE.fullmatch(acceptance_test_id) is None:
        raise OfflineRunnerError("offline runner acceptance test id is invalid")
    if CONTAINER_NAME_RE.fullmatch(session_id) is None:
        raise OfflineRunnerError("offline runner session id must be preallocated")
    if SHA256_RE.fullmatch(task_sha256) is None:
        raise OfflineRunnerError("task SHA-256 must be lowercase hexadecimal")
    if SHA256_RE.fullmatch(candidate_sha256) is None:
        raise OfflineRunnerError("candidate digest must be lowercase hexadecimal")
    if SHA256_RE.fullmatch(source_snapshot_sha256) is None:
        raise OfflineRunnerError("source snapshot SHA-256 must be lowercase hexadecimal")
    tdd_digests = (test_patch_sha256, test_manifest_sha256)
    if phase == "gate":
        if tdd_digests != (None, None):
            raise OfflineRunnerError("gate runs must not claim TDD patch or manifest evidence")
    elif any(value is None or SHA256_RE.fullmatch(value) is None for value in tdd_digests):
        raise OfflineRunnerError("TDD runs require test patch and manifest SHA-256 values")

    backend = detect_container_backend(candidate_uid=candidate_uid, which=which, probe=probe)
    snapshot = verify_readonly_snapshot(snapshot_root, candidate_uid=candidate_uid)
    if candidate_snapshot_sha256 is None:
        if phase == "red":
            raise OfflineRunnerError("RED runs require the verified candidate snapshot digest")
        bound_candidate_snapshot_sha256 = snapshot.snapshot_sha256
    else:
        if SHA256_RE.fullmatch(candidate_snapshot_sha256) is None:
            raise OfflineRunnerError("candidate snapshot SHA-256 must be lowercase hexadecimal")
        bound_candidate_snapshot_sha256 = candidate_snapshot_sha256
    if phase in {"gate", "green"} and bound_candidate_snapshot_sha256 != snapshot.snapshot_sha256:
        raise OfflineRunnerError(f"{phase.upper()} must execute the candidate snapshot itself")
    if phase in {"gate", "green"} and source_snapshot_sha256 != snapshot.snapshot_sha256:
        raise OfflineRunnerError(f"{phase.upper()} source must be the candidate snapshot")
    if phase == "red" and source_snapshot_sha256 == bound_candidate_snapshot_sha256:
        raise OfflineRunnerError("RED source and candidate snapshots must be distinct")
    if phase == "red" and snapshot.snapshot_sha256 in {
        source_snapshot_sha256,
        bound_candidate_snapshot_sha256,
    }:
        raise OfflineRunnerError("RED execution must use the measured overlay snapshot")
    container_command = _validate_command(command)
    request = RunRequest(
        phase=phase,
        acceptance_test_id=acceptance_test_id,
        session_id=session_id,
        source_commit_sha=snapshot.commit_sha,
        source_commit_tree_sha=snapshot.commit_tree_sha,
        source_snapshot_sha256=source_snapshot_sha256,
        task_sha256=task_sha256,
        candidate_sha256=candidate_sha256,
        candidate_snapshot_sha256=bound_candidate_snapshot_sha256,
        execution_snapshot_sha256=snapshot.snapshot_sha256,
        test_patch_sha256=test_patch_sha256,
        test_manifest_sha256=test_manifest_sha256,
        command=container_command,
        runner_image_digest=approved_image_digest,
    )
    control_root = Path(tempfile.mkdtemp(prefix=".run-", dir=snapshot.root.parent))
    control_root.chmod(0o700)
    container_name = session_id
    cidfile = control_root / "container.cid"
    try:
        argv = build_offline_container_argv(
            backend=backend,
            snapshot=snapshot,
            image=image,
            approved_image_digest=approved_image_digest,
            command=container_command,
            candidate_uid=candidate_uid,
            container_name=container_name,
            cidfile=cidfile,
        )
    except BaseException:
        try:
            control_root.rmdir()
        except OSError:
            pass
        raise
    host_environment = _base_host_environment(backend.name)
    started_unix_ns = time.time_ns()
    cleanup_succeeded = False
    execution_error: BaseException | None = None
    result: _BoundedProcessResult | None = None
    container_id: str | None = None
    try:
        result = stream_runner(
            argv,
            environment=host_environment,
            timeout_seconds=timeout_seconds,
            max_output_bytes=max_log_bytes,
        )
        container_id = _read_container_id(cidfile, candidate_uid=candidate_uid)
    except BaseException as exc:
        execution_error = exc
    finally:
        cleanup_succeeded = cleanup(backend, container_name, host_environment)
        try:
            cidfile.unlink(missing_ok=True)
            control_root.rmdir()
        except OSError:
            cleanup_succeeded = False
    if not cleanup_succeeded:
        raise OfflineRunnerError("container cleanup could not be attested") from execution_error
    if execution_error is not None:
        raise execution_error
    if result is None or container_id is None:
        raise OfflineRunnerError("isolated execution returned without complete evidence")
    post_rootless, post_user_namespace, post_seccomp_profile = _probe_backend(
        name=backend.name,
        executable=backend.executable,
        probe=probe,
    )
    post_security_sha256 = _security_evidence_sha256(
        backend.name,
        post_rootless,
        post_user_namespace,
        post_seccomp_profile,
    )
    if post_security_sha256 != backend.security_evidence_sha256:
        raise OfflineRunnerError("container backend security state changed during execution")

    if result.stdout_sha256 != hashlib.sha256(result.stdout).hexdigest() or (
        result.stderr_sha256 != hashlib.sha256(result.stderr).hexdigest()
    ):
        raise OfflineRunnerError("stream runner returned inconsistent output digests")
    presentation = b"[stdout]\n" + result.stdout + b"\n[stderr]\n" + result.stderr
    log_sha256 = offline_log_sha256(result.stdout, result.stderr)
    failure_sha256 = failure_fingerprint_sha256(
        exit_code=result.exit_code,
        stdout=result.stdout,
        stderr=result.stderr,
    )
    response_sha256 = execution_response_sha256(
        exit_code=result.exit_code,
        stdout=result.stdout,
        stderr=result.stderr,
        container_id=container_id,
        cleanup_succeeded=True,
        log_truncated=False,
    )
    return OfflineRunEvidence(
        request=request,
        request_sha256=request.sha256(),
        runtime_name=backend.name,
        runtime_sha256=backend.sha256,
        runtime_security_sha256=backend.security_evidence_sha256,
        runtime_rootless=backend.rootless,
        runtime_user_namespace=backend.user_namespace,
        runtime_seccomp_profile=backend.seccomp_profile,
        runner_image_digest=approved_image_digest,
        snapshot_sha256=snapshot.snapshot_sha256,
        argv=argv,
        argv_sha256=hashlib.sha256(_canonical_json(list(argv))).hexdigest(),
        container_id=container_id,
        exit_code=result.exit_code,
        stdout=result.stdout,
        stderr=result.stderr,
        stdout_sha256=result.stdout_sha256,
        stderr_sha256=result.stderr_sha256,
        log=presentation,
        log_sha256=log_sha256,
        log_truncated=False,
        stdout_bytes=len(result.stdout),
        stderr_bytes=len(result.stderr),
        started_unix_ns=started_unix_ns,
        duration_ms=result.duration_ms,
        cleanup_succeeded=True,
        failure_fingerprint_sha256=failure_sha256,
        response_sha256=response_sha256,
    )


def _validate_run_request(request: RunRequest) -> None:
    if request.phase not in {"gate", "red", "green"}:
        raise OfflineRunnerError("offline request phase is invalid")
    if ACCEPTANCE_ID_RE.fullmatch(request.acceptance_test_id) is None:
        raise OfflineRunnerError("offline request acceptance test id is invalid")
    if CONTAINER_NAME_RE.fullmatch(request.session_id) is None:
        raise OfflineRunnerError("offline request session id is invalid")
    if (
        GIT_SHA_RE.fullmatch(request.source_commit_sha) is None
        or GIT_SHA_RE.fullmatch(request.source_commit_tree_sha) is None
    ):
        raise OfflineRunnerError("offline request source commit binding is invalid")
    digest_values = (
        request.source_snapshot_sha256,
        request.task_sha256,
        request.candidate_sha256,
        request.candidate_snapshot_sha256,
        request.execution_snapshot_sha256,
    )
    if any(SHA256_RE.fullmatch(value) is None for value in digest_values):
        raise OfflineRunnerError("offline request contains an invalid SHA-256")
    _validate_command(request.command)
    if DIGEST_RE.fullmatch(request.runner_image_digest) is None:
        raise OfflineRunnerError("offline request runner image digest is invalid")
    tdd_values = (request.test_patch_sha256, request.test_manifest_sha256)
    if request.phase == "gate":
        if tdd_values != (None, None):
            raise OfflineRunnerError("gate request must not claim TDD evidence")
    elif any(value is None or SHA256_RE.fullmatch(value) is None for value in tdd_values):
        raise OfflineRunnerError("TDD request requires patch and manifest SHA-256")
    if request.phase in {"gate", "green"} and not (
        request.source_snapshot_sha256
        == request.candidate_snapshot_sha256
        == request.execution_snapshot_sha256
    ):
        raise OfflineRunnerError(
            f"{request.phase.upper()} request must execute its candidate snapshot"
        )
    if request.phase == "red" and (
        request.source_snapshot_sha256 == request.candidate_snapshot_sha256
        or request.execution_snapshot_sha256
        in {request.source_snapshot_sha256, request.candidate_snapshot_sha256}
    ):
        raise OfflineRunnerError("RED request must bind distinct base, candidate, and overlay")


def _control_values_from_argv(
    argv: tuple[str, ...],
    *,
    session_id: str,
    expected_control_parent: Path | None,
) -> Path:
    name_values = [value.removeprefix("--name=") for value in argv if value.startswith("--name=")]
    cid_values = [
        value.removeprefix("--cidfile=") for value in argv if value.startswith("--cidfile=")
    ]
    if name_values != [session_id] or len(cid_values) != 1:
        raise OfflineRunnerError("offline argv control name or cidfile is invalid")
    cidfile = Path(cid_values[0])
    if not cidfile.is_absolute() or cidfile.name != "container.cid":
        raise OfflineRunnerError("offline argv cidfile path is invalid")
    if CONTROL_DIRECTORY_RE.fullmatch(cidfile.parent.name) is None:
        raise OfflineRunnerError("offline argv control directory name is invalid")
    if expected_control_parent is not None and cidfile.parent.parent != expected_control_parent:
        raise OfflineRunnerError("offline argv cidfile is outside the snapshot control root")
    if cidfile.exists() or cidfile.is_symlink() or cidfile.parent.exists():
        raise OfflineRunnerError("offline argv control path survived attested cleanup")
    return cidfile


def _snapshot_mount_source_from_argv(argv: tuple[str, ...]) -> Path:
    """Extract only the host-side source from an otherwise canonical mount argument.

    A coordinator re-validates evidence inside a different mount namespace than the
    root-owned outer executor.  Consequently the host source path cannot equal the
    coordinator-visible snapshot path.  The source is the sole path component that
    may differ; the destination, read-only/rprivate flags, and every other argument
    remain subject to exact comparison below.
    """

    mount_indexes = [index for index, value in enumerate(argv) if value == "--mount"]
    if len(mount_indexes) != 1 or mount_indexes[0] + 1 >= len(argv):
        raise OfflineRunnerError("offline argv must contain exactly one snapshot mount")
    value = argv[mount_indexes[0] + 1]
    prefix = "type=bind,src="
    suffix = ",dst=/workspace,readonly,bind-propagation=rprivate"
    if not value.startswith(prefix) or not value.endswith(suffix):
        raise OfflineRunnerError("offline snapshot mount is not canonical")
    source = value[len(prefix) : -len(suffix)]
    if (
        not source
        or any(character in source for character in (",", "\n", "\r", "\x00"))
        or not Path(source).is_absolute()
    ):
        raise OfflineRunnerError("offline snapshot mount source is invalid")
    return Path(source)


def validate_offline_run_evidence(
    evidence: OfflineRunEvidence,
    *,
    execution_snapshot: SnapshotEvidence,
    image: str,
    approved_image_digest: str,
    candidate_uid: int,
    expected_mount_source: Path | None = None,
) -> OfflineRunEvidence:
    """Remeasure one completed run instead of trusting its digest-only dataclass fields."""

    if not isinstance(evidence, OfflineRunEvidence) or not isinstance(evidence.request, RunRequest):
        raise OfflineRunnerError("offline run evidence type is invalid")
    _validate_run_request(evidence.request)
    verified_snapshot = verify_readonly_snapshot(
        execution_snapshot.root,
        candidate_uid=candidate_uid,
    )
    if verified_snapshot != execution_snapshot:
        raise OfflineRunnerError("offline execution snapshot evidence changed")
    request = evidence.request
    request_checks = (
        (evidence.request_sha256, request.sha256()),
        (request.execution_snapshot_sha256, verified_snapshot.snapshot_sha256),
        (request.source_commit_sha, verified_snapshot.commit_sha),
        (request.source_commit_tree_sha, verified_snapshot.commit_tree_sha),
        (request.runner_image_digest, approved_image_digest),
        (evidence.runner_image_digest, approved_image_digest),
        (evidence.snapshot_sha256, verified_snapshot.snapshot_sha256),
    )
    if any(actual != expected for actual, expected in request_checks):
        raise OfflineRunnerError("offline request or snapshot binding does not match raw evidence")
    _validate_image(image, approved_image_digest)

    if not isinstance(evidence.argv, tuple) or not evidence.argv:
        raise OfflineRunnerError("offline argv evidence is invalid")
    if any(not isinstance(value, str) or not value or "\x00" in value for value in evidence.argv):
        raise OfflineRunnerError("offline argv contains an invalid argument")
    if evidence.runtime_name not in SUPPORTED_BACKENDS:
        raise OfflineRunnerError("offline runtime name is invalid")
    if (
        type(evidence.runtime_rootless) is not bool
        or type(evidence.runtime_user_namespace) is not bool
    ):
        raise OfflineRunnerError("offline runtime isolation flags are invalid")
    measured_mount_source = _snapshot_mount_source_from_argv(evidence.argv)
    if expected_mount_source is not None:
        try:
            trusted_mount_source = Path(expected_mount_source).resolve(strict=True)
        except OSError as exc:
            raise OfflineRunnerError("offline snapshot mount source is unavailable") from exc
        if measured_mount_source != trusted_mount_source:
            raise OfflineRunnerError("offline snapshot mount source changed outside the plan")
    same_mount_namespace = measured_mount_source == verified_snapshot.tree
    reported_backend = ContainerBackend(
        name=evidence.runtime_name,
        executable=Path(evidence.argv[0]),
        rootless=evidence.runtime_rootless,
        user_namespace=evidence.runtime_user_namespace,
        seccomp_enabled=True,
        seccomp_profile=evidence.runtime_seccomp_profile,
        sha256=evidence.runtime_sha256,
        security_evidence_sha256=evidence.runtime_security_sha256,
    )
    if same_mount_namespace or expected_mount_source is not None:
        backend = _validate_backend(reported_backend, candidate_uid=candidate_uid)
    else:
        # The pinned coordinator cannot see the outer host's runtime inode.  The
        # root-owned outer executor already rehashes it before/after execution.
        # Recompute every path-independent backend claim here; do not silently
        # substitute a coordinator-container executable.
        if (
            not reported_backend.executable.is_absolute()
            or SHA256_RE.fullmatch(reported_backend.sha256) is None
        ):
            raise OfflineRunnerError("offline outer runtime binding is invalid")
        expected_security = _security_evidence_sha256(
            reported_backend.name,
            reported_backend.rootless,
            reported_backend.user_namespace,
            reported_backend.seccomp_profile,
        )
        if not hmac.compare_digest(expected_security, reported_backend.security_evidence_sha256):
            raise OfflineRunnerError("offline outer runtime security evidence is invalid")
        if (
            not reported_backend.rootless
            and not reported_backend.user_namespace
            or not reported_backend.seccomp_profile
            or "unconfined" in reported_backend.seccomp_profile.casefold()
        ):
            raise OfflineRunnerError("offline outer runtime isolation evidence is invalid")
        backend = reported_backend
    cidfile = _control_values_from_argv(
        evidence.argv,
        session_id=request.session_id,
        expected_control_parent=(verified_snapshot.root.parent if same_mount_namespace else None),
    )
    expected_argv = _compose_offline_container_argv(
        backend=backend,
        # Only this source differs between the outer host and the pinned coordinator
        # mount namespace.  The outer executor supplies ``expected_mount_source`` and
        # remeasures that tree before and after execution; coordinator-side callers
        # independently remeasure ``execution_snapshot`` and compare the remaining
        # argv byte-for-byte.
        snapshot_tree=measured_mount_source,
        image=image,
        command=request.command,
        container_name=request.session_id,
        cidfile=cidfile,
    )
    if evidence.argv != expected_argv:
        raise OfflineRunnerError("offline argv does not match the canonical isolated runner")
    if evidence.argv_sha256 != hashlib.sha256(_canonical_json(list(expected_argv))).hexdigest():
        raise OfflineRunnerError("offline argv SHA-256 does not match its exact arguments")

    if isinstance(evidence.exit_code, bool) or not isinstance(evidence.exit_code, int):
        raise OfflineRunnerError("offline exit code must be a strict integer")
    if (
        not isinstance(evidence.stdout, bytes)
        or not isinstance(evidence.stderr, bytes)
        or len(evidence.stdout) + len(evidence.stderr) > 10_000_000
    ):
        raise OfflineRunnerError("offline raw streams are invalid or oversized")
    stream = _stream_binding(evidence.stdout, evidence.stderr)
    if (
        evidence.stdout_bytes != stream["stdout_bytes"]
        or evidence.stderr_bytes != stream["stderr_bytes"]
        or evidence.stdout_sha256 != stream["stdout_sha256"]
        or evidence.stderr_sha256 != stream["stderr_sha256"]
        or evidence.log_sha256 != offline_log_sha256(evidence.stdout, evidence.stderr)
    ):
        raise OfflineRunnerError("offline raw streams do not match their digest evidence")
    presentation = b"[stdout]\n" + evidence.stdout + b"\n[stderr]\n" + evidence.stderr
    if evidence.log != presentation or evidence.log_truncated is not False:
        raise OfflineRunnerError("offline bounded log is not the exact measured presentation")
    if evidence.cleanup_succeeded is not True:
        raise OfflineRunnerError("offline container cleanup was not attested")
    if not re.fullmatch(r"[0-9a-f]{12,64}", evidence.container_id):
        raise OfflineRunnerError("offline container ID is invalid")
    if (
        isinstance(evidence.started_unix_ns, bool)
        or not isinstance(evidence.started_unix_ns, int)
        or evidence.started_unix_ns <= 0
        or isinstance(evidence.duration_ms, bool)
        or not isinstance(evidence.duration_ms, int)
        or not 0 <= evidence.duration_ms <= 3_600_000
    ):
        raise OfflineRunnerError("offline execution timing evidence is invalid")
    if evidence.failure_fingerprint_sha256 != failure_fingerprint_sha256(
        exit_code=evidence.exit_code,
        stdout=evidence.stdout,
        stderr=evidence.stderr,
    ):
        raise OfflineRunnerError("offline failure fingerprint does not match raw streams")
    if evidence.response_sha256 != execution_response_sha256(
        exit_code=evidence.exit_code,
        stdout=evidence.stdout,
        stderr=evidence.stderr,
        container_id=evidence.container_id,
        cleanup_succeeded=evidence.cleanup_succeeded,
        log_truncated=evidence.log_truncated,
    ):
        raise OfflineRunnerError("offline execution response does not match raw evidence")
    return evidence
