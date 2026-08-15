"""Launch the pinned coordinator image without exposing a host dependency environment."""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import stat
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Callable
from typing import Sequence

from tools.ai_review.offline_runner import ContainerBackend
from tools.ai_review.offline_runner import _BoundedProcessResult
from tools.ai_review.offline_runner import _run_bounded
from tools.ai_review.offline_runner import detect_container_backend
from tools.ai_review.nonce_ledger import NonceLedgerContractError
from tools.ai_review.nonce_ledger import validate_existing_nonce_ledger
from tools.ai_review.preflight import PreflightError
from tools.ai_review.preflight import RuntimePreflightEvidence
from tools.ai_review.preflight import assert_candidate_cannot_mutate
from tools.ai_review.preflight import assert_candidate_cannot_mutate_tree
from tools.ai_review.preflight import read_protected_file
from tools.ai_review.preflight import read_verified_fd_asset
from tools.ai_review.sensitive_paths import sensitive_path_reason


COORDINATOR_UID = 65_532
COORDINATOR_GID = 65_532
IMAGE_RE = re.compile(r"^[^@\s]+@(sha256:[0-9a-f]{64})$")
CONTAINER_NAME_RE = re.compile(r"^ai-review-coordinator-[0-9a-f]{24}$")
CONTAINER_ASSET_PATHS = {
    "manifest": "/runtime/runtime-manifest.json",
    "harness": "/runtime/harness.pyz",
    "task": "/runtime/task.json",
    "dependency_lock": "/runtime/uv.lock",
    "schema_bundle": "/runtime/schemas.json",
    "coordinator_public_key": "/runtime/coordinator-public-key.pem",
    "broker_egress_policy": "/runtime/broker-egress-policy.json",
    "openai_pricing_policy": "/runtime/openai-pricing-policy.json",
}
CONTAINER_VALUE_TOKENS = {
    "@runtime-manifest-sha256": "manifest_sha256",
    "@coordinator-image-digest": "coordinator_image_digest",
    "@offline-runner-image-digest": "offline_runner_image_digest",
    "@broker-image-digest": "broker_image_digest",
    "@broker-gateway-image-digest": "broker_gateway_image_digest",
    "@broker-allowlist-policy-sha256": "broker_egress_policy.sha256",
    "@broker-pricing-policy-sha256": "openai_pricing_policy.sha256",
    "@broker-packet-reservation-limit": "broker_packet_reservation_limit",
    "@broker-packet-cost-limit-microusd": "broker_packet_cost_limit_microusd",
    "@task-sha256": "task.sha256",
    "@harness-sha256": "harness.sha256",
    "@schema-bundle-sha256": "schema_bundle.sha256",
    "@coordinator-public-key-sha256": "coordinator_public_key.sha256",
}
CONTAINER_PATH_TOKENS = {
    "@runtime-manifest-container": CONTAINER_ASSET_PATHS["manifest"],
    "@harness-container": CONTAINER_ASSET_PATHS["harness"],
    "@task-container": CONTAINER_ASSET_PATHS["task"],
    "@dependency-lock-container": CONTAINER_ASSET_PATHS["dependency_lock"],
    "@schema-bundle-container": CONTAINER_ASSET_PATHS["schema_bundle"],
    "@coordinator-public-key-container": CONTAINER_ASSET_PATHS["coordinator_public_key"],
    "@broker-egress-policy-container": CONTAINER_ASSET_PATHS["broker_egress_policy"],
    "@openai-pricing-policy-container": CONTAINER_ASSET_PATHS["openai_pricing_policy"],
    "@artifact-root-container": "/artifacts",
    "@candidate-repo-container": "/candidate",
}


class CoordinatorLauncherError(RuntimeError):
    """Raised instead of falling back to a mutable host Python environment."""


@dataclass(frozen=True)
class CoordinatorInvocation:
    argv: tuple[str, ...]
    environment: dict[str, str]
    container_name: str
    image_digest: str
    manifest_sha256: str
    argv_sha256: str


@dataclass(frozen=True)
class CoordinatorExecutionEvidence:
    invocation: CoordinatorInvocation
    runtime_sha256: str
    runtime_security_sha256: str
    stdout: bytes
    stdout_sha256: str
    stderr_sha256: str
    exit_code: int
    duration_ms: int
    cleanup_succeeded: bool
    staged_assets_sha256: str
    artifact_input_sha256: str


@dataclass(frozen=True)
class FrozenCoordinatorAssets:
    root: Path
    paths: dict[str, Path]
    bundle_sha256: str


@dataclass(frozen=True)
class FrozenArtifactInput:
    root: Path
    manifest_sha256: str


def _validate_image(image: str, approved_digest: str) -> None:
    match = IMAGE_RE.fullmatch(image)
    if match is None or match.group(1) != approved_digest:
        raise CoordinatorLauncherError("coordinator image is not pinned to the runtime manifest")


def _validate_backend(backend: ContainerBackend, *, candidate_uid: int) -> ContainerBackend:
    if backend.name != "podman" or not backend.rootless or not backend.user_namespace:
        raise CoordinatorLauncherError(
            "coordinator production runtime requires rootless Podman with user namespaces"
        )
    if (
        backend.seccomp_enabled is not True
        or not backend.seccomp_profile
        or "unconfined" in backend.seccomp_profile.casefold()
    ):
        raise CoordinatorLauncherError("coordinator runtime requires active seccomp")
    try:
        executable, _raw = read_protected_file(
            backend.executable,
            candidate_uid=candidate_uid,
            label="coordinator container runtime",
        )
    except PreflightError as exc:
        raise CoordinatorLauncherError(str(exc)) from exc
    if executable.sha256 != backend.sha256 or not executable.mode & 0o111:
        raise CoordinatorLauncherError("coordinator container runtime changed after probing")
    return backend


def _safe_mount(source: Path, destination: str, *, readonly: bool = True) -> str:
    raw = str(source)
    if any(character in raw for character in (",", "\n", "\r", "\x00")):
        raise CoordinatorLauncherError("coordinator mount path is not safely representable")
    access = ",readonly" if readonly else ""
    return f"type=bind,src={raw},dst={destination}{access},bind-propagation=rprivate"


def _runtime_asset_paths(evidence: RuntimePreflightEvidence) -> dict[str, Path]:
    return {
        "manifest": evidence.manifest_path,
        "harness": evidence.harness.path,
        "task": evidence.task.path,
        "dependency_lock": evidence.dependency_lock.path,
        "schema_bundle": evidence.schema_bundle.path,
        "coordinator_public_key": evidence.coordinator_public_key.path,
        "broker_egress_policy": evidence.broker_egress_policy.path,
        "openai_pricing_policy": evidence.openai_pricing_policy.path,
    }


def freeze_coordinator_assets(
    evidence: RuntimePreflightEvidence,
    destination: Path,
) -> FrozenCoordinatorAssets:
    """Copy held preflight FDs into one immutable, container-mountable input tree."""

    parent = destination.parent
    try:
        protected_parent = assert_candidate_cannot_mutate(
            parent,
            candidate_uid=evidence.candidate_uid,
        )
    except PreflightError as exc:
        raise CoordinatorLauncherError(str(exc)) from exc
    if destination.exists() or destination.is_symlink() or protected_parent != parent:
        raise CoordinatorLauncherError("coordinator staging destination must be new")
    destination.mkdir(mode=0o700)
    paths: dict[str, Path] = {}
    manifest_items: list[tuple[str, str]] = []
    expected = {
        "manifest": evidence.manifest_sha256,
        "harness": evidence.harness.sha256,
        "task": evidence.task.sha256,
        "dependency_lock": evidence.dependency_lock.sha256,
        "schema_bundle": evidence.schema_bundle.sha256,
        "coordinator_public_key": evidence.coordinator_public_key.sha256,
        "broker_egress_policy": evidence.broker_egress_policy.sha256,
        "openai_pricing_policy": evidence.openai_pricing_policy.sha256,
    }
    try:
        directory_fd = os.open(
            destination,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        try:
            for name in sorted(expected):
                _source, raw = read_verified_fd_asset(
                    evidence.fd_path(name),
                    expected_sha256=expected[name],
                    label=f"coordinator staged {name}",
                )
                filename = Path(CONTAINER_ASSET_PATHS[name]).name
                flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
                descriptor = os.open(filename, flags, 0o400, dir_fd=directory_fd)
                try:
                    view = memoryview(raw)
                    while view:
                        written = os.write(descriptor, view)
                        if written <= 0:
                            raise CoordinatorLauncherError("coordinator staging write failed")
                        view = view[written:]
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
                path = destination / filename
                path.chmod(0o444)
                paths[name] = path
                manifest_items.append((name, expected[name]))
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
        destination.chmod(0o555)
        bundle = hashlib.sha256()
        bundle.update(b"amazon-explorer-coordinator-staged-assets-v1\0")
        for name, digest in manifest_items:
            for value in (name, digest):
                encoded = value.encode("ascii")
                bundle.update(len(encoded).to_bytes(4, "big"))
                bundle.update(encoded)
        return FrozenCoordinatorAssets(
            root=destination,
            paths=paths,
            bundle_sha256=bundle.hexdigest(),
        )
    except BaseException:
        shutil.rmtree(destination, ignore_errors=True)
        raise


def _protected_artifact_path(relative: Path, *, allow_agents: bool = False) -> bool:
    parts = tuple(part.casefold() for part in relative.parts)
    if sensitive_path_reason(relative) is not None:
        return True
    instruction = any(part in {"agents.md", "agents.override.md"} for part in parts)
    if not instruction:
        return False
    snapshot_instruction = (
        allow_agents
        and len(parts) >= 4
        and parts[0] in {"snapshots", "red-snapshots"}
        and re.fullmatch(r"[0-9a-f]{64}", parts[1]) is not None
        and parts[2] == "tree"
    )
    return not snapshot_instruction


def _freeze_artifact_input(
    source_root: Path,
    destination: Path,
    *,
    candidate_uid: int,
    allow_agents: bool = False,
    max_entries: int = 10_000,
    max_total_bytes: int = 128 * 1024 * 1024,
) -> FrozenArtifactInput:
    """Copy bounded structured evidence into a read-only, secret-free input tree."""

    try:
        source = assert_candidate_cannot_mutate_tree(
            source_root,
            candidate_uid=candidate_uid,
        ).root
        parent = assert_candidate_cannot_mutate(
            destination.parent,
            candidate_uid=candidate_uid,
        )
    except PreflightError as exc:
        raise CoordinatorLauncherError(str(exc)) from exc
    if destination.exists() or destination.is_symlink() or parent != destination.parent:
        raise CoordinatorLauncherError("artifact staging destination must be new")
    destination.mkdir(mode=0o700)
    entries: list[tuple[str, str, int]] = []
    total_bytes = 0
    try:
        for directory, directories, filenames in os.walk(source, followlinks=False):
            relative_directory = Path(directory).relative_to(source)
            target_directory = destination / relative_directory
            target_directory.mkdir(mode=0o700, parents=True, exist_ok=True)
            directories.sort()
            filenames.sort()
            for name in filenames:
                relative = relative_directory / name
                if _protected_artifact_path(relative, allow_agents=allow_agents):
                    raise CoordinatorLauncherError("artifact input contains a protected path")
                try:
                    evidence, raw = read_protected_file(
                        Path(directory) / name,
                        candidate_uid=candidate_uid,
                        label=f"artifact input {relative.as_posix()}",
                        max_bytes=16 * 1024 * 1024,
                    )
                except PreflightError as exc:
                    raise CoordinatorLauncherError(str(exc)) from exc
                total_bytes += evidence.size
                if len(entries) >= max_entries or total_bytes > max_total_bytes:
                    raise CoordinatorLauncherError("artifact input exceeds its bounded manifest")
                target = destination / relative
                directory_fd = os.open(
                    target.parent,
                    os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
                )
                try:
                    descriptor = os.open(
                        target.name,
                        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                        0o400,
                        dir_fd=directory_fd,
                    )
                    try:
                        view = memoryview(raw)
                        while view:
                            written = os.write(descriptor, view)
                            if written <= 0:
                                raise CoordinatorLauncherError("artifact staging write failed")
                            view = view[written:]
                        os.fsync(descriptor)
                    finally:
                        os.close(descriptor)
                finally:
                    os.close(directory_fd)
                target.chmod(0o444)
                entries.append((relative.as_posix(), evidence.sha256, evidence.size))
        for path in sorted(
            (item for item in destination.rglob("*") if item.is_dir()),
            key=lambda item: len(item.parts),
            reverse=True,
        ):
            path.chmod(0o555)
        destination.chmod(0o555)
        digest = hashlib.sha256()
        digest.update(b"amazon-explorer-coordinator-artifact-input-v1\0")
        for path, content_sha256, size in sorted(entries):
            for value in (path, content_sha256, str(size)):
                encoded = value.encode("utf-8")
                digest.update(len(encoded).to_bytes(4, "big"))
                digest.update(encoded)
        return FrozenArtifactInput(root=destination, manifest_sha256=digest.hexdigest())
    except BaseException:
        shutil.rmtree(destination, ignore_errors=True)
        raise


def freeze_artifact_input(
    source_root: Path,
    destination: Path,
    *,
    candidate_uid: int,
) -> FrozenArtifactInput:
    """Freeze secret-free structured evidence; repository instructions stay forbidden."""

    return _freeze_artifact_input(
        source_root,
        destination,
        candidate_uid=candidate_uid,
    )


def freeze_snapshot_artifact_input(
    source_root: Path,
    destination: Path,
    *,
    candidate_uid: int,
) -> FrozenArtifactInput:
    """Freeze verified code snapshots on their dedicated non-instruction boundary."""

    return _freeze_artifact_input(
        source_root,
        destination,
        candidate_uid=candidate_uid,
        allow_agents=True,
        max_entries=200_000,
        max_total_bytes=512 * 1024 * 1024,
    )


def _expand_command(evidence: RuntimePreflightEvidence, command: Sequence[str]) -> tuple[str, ...]:
    values = tuple(command)
    if not values or len(values) > 256:
        raise CoordinatorLauncherError("coordinator command is empty or too long")

    def bound_value(attribute: str) -> str:
        value: object = evidence
        for part in attribute.split("."):
            value = getattr(value, part)
        if isinstance(value, bool) or not isinstance(value, (str, int)):
            raise CoordinatorLauncherError("coordinator token has an invalid trusted type")
        return str(value)

    expanded = tuple(
        CONTAINER_PATH_TOKENS[value]
        if value in CONTAINER_PATH_TOKENS
        else bound_value(CONTAINER_VALUE_TOKENS[value])
        if value in CONTAINER_VALUE_TOKENS
        else value
        for value in values
    )
    host_paths = [str(path) for path in _runtime_asset_paths(evidence).values()]
    if any(
        not isinstance(value, str)
        or not value
        or "\x00" in value
        or "\n" in value
        or "\r" in value
        or any(host_path in value for host_path in host_paths)
        for value in expanded
    ):
        raise CoordinatorLauncherError("coordinator command contains an unsafe host value")
    return expanded


def _user_namespace_arguments(backend: ContainerBackend) -> tuple[str, ...]:
    if backend.name != "podman" or not backend.rootless:
        raise CoordinatorLauncherError("coordinator keep-id mapping requires rootless Podman")
    return (f"--userns=keep-id:uid={COORDINATOR_UID},gid={COORDINATOR_GID}",)


def _assert_keep_id_owner(path: Path, *, label: str) -> None:
    metadata = os.lstat(path)
    if (metadata.st_uid, metadata.st_gid) != (os.geteuid(), os.getegid()):
        raise CoordinatorLauncherError(
            f"{label} owner is not mapped to the coordinator keep-id user"
        )


def _validated_nonce_ledger_root(path: Path, *, candidate_uid: int) -> Path:
    try:
        root = assert_candidate_cannot_mutate_tree(
            path,
            candidate_uid=candidate_uid,
        ).root
    except PreflightError as exc:
        raise CoordinatorLauncherError(str(exc)) from exc
    metadata = os.lstat(root)
    if (
        stat.S_IMODE(metadata.st_mode) != 0o700
        or metadata.st_uid != os.geteuid()
        or metadata.st_gid != os.getegid()
    ):
        raise CoordinatorLauncherError(
            "attestation nonce ledger root must be private and keep-id owned"
        )
    entries = tuple(root.iterdir())
    if len(entries) > 1 or (entries and entries[0].name != "nonces.sqlite3"):
        raise CoordinatorLauncherError("attestation nonce ledger root contains an unknown file")
    if entries:
        ledger = entries[0]
        ledger_metadata = os.lstat(ledger)
        if (
            not stat.S_ISREG(ledger_metadata.st_mode)
            or ledger_metadata.st_nlink != 1
            or stat.S_IMODE(ledger_metadata.st_mode) != 0o600
            or ledger_metadata.st_uid != os.geteuid()
            or ledger_metadata.st_gid != os.getegid()
        ):
            raise CoordinatorLauncherError("attestation nonce ledger file is unsafe")
        try:
            validate_existing_nonce_ledger(
                ledger,
                expected_uid=os.geteuid(),
                expected_gid=os.getegid(),
            )
        except NonceLedgerContractError:
            raise CoordinatorLauncherError(
                "attestation nonce ledger database violates its trusted contract"
            ) from None
    return root


def build_coordinator_invocation(
    *,
    evidence: RuntimePreflightEvidence,
    backend: ContainerBackend,
    image: str,
    artifact_root: Path,
    candidate_repo: Path | None,
    candidate_uid: int,
    command: Sequence[str],
    container_name: str,
    mount_candidate: bool = True,
    phase_output_root: Path | None = None,
    signing_key: Path | None = None,
    nonce_ledger_root: Path | None = None,
    snapshot_artifact_root: Path | None = None,
    frozen_assets: FrozenCoordinatorAssets | None = None,
    frozen_artifacts: FrozenArtifactInput | None = None,
    frozen_snapshot_artifacts: FrozenArtifactInput | None = None,
) -> CoordinatorInvocation:
    """Build a no-network, read-only coordinator container with no runtime socket mount."""

    trusted_backend = _validate_backend(backend, candidate_uid=candidate_uid)
    _validate_image(image, evidence.coordinator_image_digest)
    if CONTAINER_NAME_RE.fullmatch(container_name) is None:
        raise CoordinatorLauncherError("coordinator container name is invalid")
    if type(mount_candidate) is not bool:
        raise CoordinatorLauncherError("coordinator candidate mount policy is invalid")
    try:
        artifacts = assert_candidate_cannot_mutate(artifact_root, candidate_uid=candidate_uid)
        candidate = (
            assert_candidate_cannot_mutate_tree(
                candidate_repo,
                candidate_uid=candidate_uid,
            ).root
            if mount_candidate and candidate_repo is not None
            else None
        )
    except PreflightError as exc:
        raise CoordinatorLauncherError(str(exc)) from exc
    if mount_candidate and candidate is None:
        raise CoordinatorLauncherError("candidate mount requires a protected candidate tree")
    if not mount_candidate and candidate_repo is not None:
        raise CoordinatorLauncherError("candidate path is forbidden for this coordinator phase")
    if not artifacts.is_dir() or stat.S_IMODE(artifacts.stat().st_mode) & 0o077:
        raise CoordinatorLauncherError("coordinator artifact root must be a private directory")
    expanded_command = _expand_command(evidence, command)
    if not mount_candidate and any(
        value == "/candidate" or value.startswith("/candidate/") for value in expanded_command
    ):
        raise CoordinatorLauncherError("candidate path token is forbidden for this phase")
    snapshots: Path | None = None
    if snapshot_artifact_root is not None:
        try:
            snapshots = assert_candidate_cannot_mutate_tree(
                snapshot_artifact_root,
                candidate_uid=candidate_uid,
            ).root
        except PreflightError as exc:
            raise CoordinatorLauncherError(str(exc)) from exc
        if (
            snapshots == artifacts
            or snapshots.is_relative_to(artifacts)
            or artifacts.is_relative_to(snapshots)
        ):
            raise CoordinatorLauncherError("snapshot and general artifact roots must be separate")
        _assert_keep_id_owner(snapshots, label="coordinator snapshot artifacts")
    command_uses_snapshots = any(
        value == "/snapshots" or value.startswith("/snapshots/") for value in expanded_command
    )
    if command_uses_snapshots != (snapshots is not None):
        raise CoordinatorLauncherError("coordinator snapshot mount does not match its command")
    output_root: Path | None = None
    if phase_output_root is not None:
        try:
            output_root = assert_candidate_cannot_mutate(
                phase_output_root,
                candidate_uid=candidate_uid,
            )
        except PreflightError as exc:
            raise CoordinatorLauncherError(str(exc)) from exc
        if (
            not output_root.is_dir()
            or stat.S_IMODE(output_root.stat().st_mode) != 0o700
            or any(output_root.iterdir())
        ):
            raise CoordinatorLauncherError("coordinator phase output must be new and empty")
        _assert_keep_id_owner(output_root, label="coordinator phase output")
    sign_prepare = (
        expanded_command[0] == "sign"
        and expanded_command.count("--workflow-operation") == 1
        and expanded_command.index("--workflow-operation") + 1 < len(expanded_command)
        and expanded_command[expanded_command.index("--workflow-operation") + 1] == "prepare"
    )
    key_path: Path | None = None
    if signing_key is not None:
        if not sign_prepare:
            raise CoordinatorLauncherError(
                "private signing key is allowed only during sign workflow prepare"
            )
        try:
            key_evidence, _raw_key = read_protected_file(
                signing_key,
                candidate_uid=candidate_uid,
                label="coordinator private signing key",
                max_bytes=64 * 1024,
            )
        except PreflightError as exc:
            raise CoordinatorLauncherError(str(exc)) from exc
        if key_evidence.mode & 0o077 or key_evidence.mode & 0o222:
            raise CoordinatorLauncherError("private signing key must be private and read-only")
        key_path = key_evidence.path
        _assert_keep_id_owner(key_path, label="coordinator private signing key")
    elif sign_prepare:
        raise CoordinatorLauncherError(
            "sign workflow prepare requires the protected private signing key"
        )
    judge_prepare = (
        expanded_command[0] == "attested-judge"
        and expanded_command.count("--workflow-operation") == 1
        and expanded_command.index("--workflow-operation") + 1 < len(expanded_command)
        and expanded_command[expanded_command.index("--workflow-operation") + 1] == "prepare"
    )
    nonce_root = (
        _validated_nonce_ledger_root(nonce_ledger_root, candidate_uid=candidate_uid)
        if nonce_ledger_root is not None
        else None
    )
    if (nonce_root is not None) != judge_prepare:
        raise CoordinatorLauncherError(
            "attestation nonce ledger is allowed only for attested-judge prepare"
        )
    command_uses_nonce_ledger = any(
        value == "/nonce-ledger" or value.startswith("/nonce-ledger/") for value in expanded_command
    )
    if command_uses_nonce_ledger != judge_prepare:
        raise CoordinatorLauncherError(
            "attestation nonce ledger mount does not match the coordinator command"
        )
    asset_paths = _runtime_asset_paths(evidence) if frozen_assets is None else frozen_assets.paths
    if set(asset_paths) != set(CONTAINER_ASSET_PATHS):
        raise CoordinatorLauncherError("coordinator staged asset set is incomplete")
    mounts: list[str] = []
    for name, source in asset_paths.items():
        mounts.extend(("--mount", _safe_mount(source, CONTAINER_ASSET_PATHS[name])))
    mounted_artifacts = artifacts if frozen_artifacts is None else frozen_artifacts.root
    mounts.extend(("--mount", _safe_mount(mounted_artifacts, "/artifacts")))
    if snapshots is not None:
        mounted_snapshots = (
            snapshots if frozen_snapshot_artifacts is None else frozen_snapshot_artifacts.root
        )
        mounts.extend(("--mount", _safe_mount(mounted_snapshots, "/snapshots")))
    if candidate is not None:
        mounts.extend(("--mount", _safe_mount(candidate, "/candidate")))
    if output_root is not None:
        mounts.extend(("--mount", _safe_mount(output_root, "/output", readonly=False)))
    if key_path is not None:
        mounts.extend(
            (
                "--mount",
                _safe_mount(key_path, "/signing/coordinator-private-key.pem"),
            )
        )
    if nonce_root is not None:
        mounts.extend(("--mount", _safe_mount(nonce_root, "/nonce-ledger", readonly=False)))
    argv = (
        str(trusted_backend.executable),
        "run",
        "--rm",
        "--pull=never",
        f"--name={container_name}",
        "--network=none",
        "--read-only",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "--ipc=none",
        *_user_namespace_arguments(trusted_backend),
        f"--user={COORDINATOR_UID}:{COORDINATOR_GID}",
        "--workdir=/",
        "--pids-limit=128",
        "--memory=1g",
        "--cpus=1",
        "--tmpfs=/tmp:rw,noexec,nosuid,nodev,size=32m,mode=1777",
        "--env=PYTHONDONTWRITEBYTECODE=1",
        "--env=PYTHONNOUSERSITE=1",
        *mounts,
        image,
        *expanded_command,
    )
    environment = {"PATH": os.defpath, "LC_ALL": "C"}
    argv_sha256 = hashlib.sha256("\0".join(argv).encode("utf-8")).hexdigest()
    return CoordinatorInvocation(
        argv=argv,
        environment=environment,
        container_name=container_name,
        image_digest=evidence.coordinator_image_digest,
        manifest_sha256=evidence.manifest_sha256,
        argv_sha256=argv_sha256,
    )


def _preflight_paths_unchanged(evidence: RuntimePreflightEvidence) -> None:
    for name, expected in {
        "manifest": (evidence.manifest_path, evidence.manifest_sha256),
        **{
            asset_name: (getattr(evidence, asset_name).path, getattr(evidence, asset_name).sha256)
            for asset_name in (
                "harness",
                "task",
                "dependency_lock",
                "schema_bundle",
                "coordinator_public_key",
                "broker_egress_policy",
                "openai_pricing_policy",
            )
        },
    }.items():
        path, digest = expected
        try:
            measured, _raw = read_protected_file(
                path,
                candidate_uid=evidence.candidate_uid,
                label=f"coordinator {name}",
                expected_sha256=digest,
            )
        except PreflightError as exc:
            raise CoordinatorLauncherError(str(exc)) from exc
        original = None if name == "manifest" else getattr(evidence, name)
        if original is not None and (measured.device, measured.inode) != (
            original.device,
            original.inode,
        ):
            raise CoordinatorLauncherError("coordinator runtime asset path changed after preflight")


def _cleanup(backend: ContainerBackend, name: str, environment: dict[str, str]) -> bool:
    try:
        result = subprocess.run(
            [str(backend.executable), "rm", "-f", "--", name],
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


def execute_coordinator(
    *,
    evidence: RuntimePreflightEvidence,
    image: str,
    artifact_root: Path,
    candidate_repo: Path | None,
    command: Sequence[str],
    container_name: str,
    timeout_seconds: int = 300,
    max_output_bytes: int = 2_000_000,
    mount_candidate: bool = True,
    phase_output_root: Path | None = None,
    signing_key: Path | None = None,
    nonce_ledger_root: Path | None = None,
    snapshot_artifact_root: Path | None = None,
    detector: Callable[..., ContainerBackend] = detect_container_backend,
    runner: Callable[..., _BoundedProcessResult] = _run_bounded,
    cleanup: Callable[[ContainerBackend, str, dict[str, str]], bool] = _cleanup,
) -> CoordinatorExecutionEvidence:
    """Execute once; missing isolation never falls back to host Python."""

    if os.geteuid() == 0:
        raise CoordinatorLauncherError("coordinator production runtime must not run as root")
    if isinstance(timeout_seconds, bool) or not 1 <= timeout_seconds <= 900:
        raise CoordinatorLauncherError("coordinator timeout is invalid")
    if isinstance(max_output_bytes, bool) or not 1024 <= max_output_bytes <= 10_000_000:
        raise CoordinatorLauncherError("coordinator output limit is invalid")
    backend = detector(candidate_uid=evidence.candidate_uid)
    staging_parent = artifact_root.parent
    staging = Path(tempfile.mkdtemp(prefix=".coordinator-stage-parent-", dir=staging_parent))
    staging.chmod(0o700)
    frozen: FrozenCoordinatorAssets | None = None
    frozen_artifacts: FrozenArtifactInput | None = None
    frozen_snapshot_artifacts: FrozenArtifactInput | None = None
    try:
        frozen = freeze_coordinator_assets(evidence, staging / "input")
        frozen_artifacts = freeze_artifact_input(
            artifact_root,
            staging / "artifacts",
            candidate_uid=evidence.candidate_uid,
        )
        if snapshot_artifact_root is not None:
            frozen_snapshot_artifacts = freeze_snapshot_artifact_input(
                snapshot_artifact_root,
                staging / "snapshots",
                candidate_uid=evidence.candidate_uid,
            )
        invocation = build_coordinator_invocation(
            evidence=evidence,
            backend=backend,
            image=image,
            artifact_root=artifact_root,
            candidate_repo=candidate_repo,
            candidate_uid=evidence.candidate_uid,
            command=command,
            container_name=container_name,
            mount_candidate=mount_candidate,
            phase_output_root=phase_output_root,
            signing_key=signing_key,
            nonce_ledger_root=nonce_ledger_root,
            snapshot_artifact_root=snapshot_artifact_root,
            frozen_assets=frozen,
            frozen_artifacts=frozen_artifacts,
            frozen_snapshot_artifacts=frozen_snapshot_artifacts,
        )
        _preflight_paths_unchanged(evidence)
        cleanup_succeeded = False
        try:
            result = runner(
                invocation.argv,
                environment=invocation.environment,
                timeout_seconds=timeout_seconds,
                max_output_bytes=max_output_bytes,
            )
        finally:
            cleanup_succeeded = cleanup(backend, container_name, invocation.environment)
    finally:
        shutil.rmtree(staging, ignore_errors=True)
    _preflight_paths_unchanged(evidence)
    if nonce_ledger_root is not None:
        _validated_nonce_ledger_root(nonce_ledger_root, candidate_uid=evidence.candidate_uid)
    current_backend = detector(candidate_uid=evidence.candidate_uid)
    if current_backend != backend:
        raise CoordinatorLauncherError("coordinator runtime changed during execution")
    if not cleanup_succeeded:
        raise CoordinatorLauncherError("coordinator container cleanup could not be verified")
    if result.exit_code != 0:
        raise CoordinatorLauncherError("coordinator container returned a non-zero status")
    if result.stderr:
        raise CoordinatorLauncherError("coordinator container emitted unexpected stderr")
    return CoordinatorExecutionEvidence(
        invocation=invocation,
        runtime_sha256=backend.sha256,
        runtime_security_sha256=backend.security_evidence_sha256,
        stdout=result.stdout,
        stdout_sha256=result.stdout_sha256,
        stderr_sha256=result.stderr_sha256,
        exit_code=result.exit_code,
        duration_ms=result.duration_ms,
        cleanup_succeeded=True,
        staged_assets_sha256=frozen.bundle_sha256,
        artifact_input_sha256=frozen_artifacts.manifest_sha256,
    )
