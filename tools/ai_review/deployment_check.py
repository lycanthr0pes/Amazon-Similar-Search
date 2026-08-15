"""Credential-free, network-denied validation of an installed production release.

This module is imported by the root-owned external launcher from the already
hashed harness zipapp.  It is deliberately stdlib-only: deployment validation
must run before any candidate code, site dependency, broker credential, cost
ledger, or external-network lifecycle can become reachable.
"""

from __future__ import annotations

import hashlib
import json
import os
import pwd
import re
import secrets
import shutil
import stat
import subprocess
from collections.abc import Callable
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any


EMPTY_ARTIFACT_SET_SHA256 = "37517e5f3dc66819f61f5a7bb8ace1921282415f10551d2defa5c3eb0985b570"
_SHA_RE = re.compile(r"^[0-9a-f]{64}$")
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_IMAGE_RE = re.compile(
    r"^(?P<registry>[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?(?::[1-9][0-9]{0,4})?)/"
    r"(?P<repository>[a-z0-9]+(?:(?:[._-])[a-z0-9]+)*"
    r"(?:/[a-z0-9]+(?:(?:[._-])[a-z0-9]+)*)*)@"
    r"(?P<digest>sha256:[0-9a-f]{64})$"
)
_CONTAINER_RE = re.compile(r"^ai-review-deploy-[a-z0-9-]+-[0-9a-f]{16}$")
_EVIDENCE_DOMAIN = b"amazon-explorer-deployment-check-v1\0"
_BACKEND_EVIDENCE_DOMAIN = b"amazon-explorer-deployment-backend-v1\0"
_MAX_INSPECT_BYTES = 256_000
_MAX_COMMAND_BYTES = 64_000
_SMOKE_TIMEOUT_SECONDS = 60

_BASE_ENVIRONMENT = {
    "GPG_KEY": "7169605F62C751356D054A26A821E680E5FA6305",
    "PYTHON_SHA256": "5462f9099dfd30e238def83c71d91897d8caa5ff6ebc7a50f14d4802cdaaa79a",
    "PYTHON_VERSION": "3.13.7",
}

_FORBIDDEN_ENVIRONMENT_NAMES = {
    "all_proxy",
    "aws_ca_bundle",
    "curl_ca_bundle",
    "dyld_insert_libraries",
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
    "pythoninspect",
    "pythonpath",
    "pythonstartup",
    "requests_ca_bundle",
    "ssl_cert_dir",
    "ssl_cert_file",
    "sslkeylogfile",
}

_ACL_XATTRS = {"system.posix_acl_access", "system.posix_acl_default"}
_PATH_EVIDENCE_DOMAIN = b"amazon-explorer-deployment-path-v1\0"
_ENVIRONMENT_EVIDENCE_DOMAIN = b"amazon-explorer-deployment-environment-v1\0"
_STORAGE_TABLE_KEYS = {
    "storage": {
        "driver",
        "graphroot",
        "imagestore",
        "priority",
        "rootless_storage_path",
        "runroot",
        "transient_store",
    },
    "storage.options": {
        "additionalimagestores",
        "auto-userns-max-size",
        "auto-userns-min-size",
        "disable-volatile",
        "ignore_chown_errors",
        "remap-gids",
        "remap-group",
        "remap-uids",
        "remap-user",
        "root-auto-userns-user",
    },
    "storage.options.overlay": {
        "force_mask",
        "ignore_chown_errors",
        "inodes",
        "mount_program",
        "mountopt",
        "size",
        "use_composefs",
    },
    "storage.options.pull_options": {
        "enable_partial_images",
        "ostree_repos",
        "use_hard_links",
    },
    "storage.options.thinpool": {
        "autoextend_percent",
        "autoextend_threshold",
        "basesize",
        "blocksize",
        "directlvm_device",
        "directlvm_device_force",
        "fs",
        "log_level",
        "min_free_space",
        "mkfsarg",
        "mountopt",
        "use_deferred_deletion",
        "use_deferred_removal",
        "xfs_nospace_max_retries",
    },
}


class DeploymentCheckError(RuntimeError):
    """Raised before a non-live deployment check can overstate its evidence."""


@dataclass(frozen=True)
class LauncherEnvironmentEvidence:
    """Canonical launcher-owned HOME/XDG boundary used by every Podman command."""

    environment: tuple[tuple[str, str], ...]
    evidence_sha256: str


@dataclass(frozen=True)
class DeploymentBackend:
    """Podman backend plus measured launcher storage/runtime path identities."""

    name: str
    executable: Path
    rootless: bool
    user_namespace: bool
    seccomp_enabled: bool
    seccomp_profile: str
    sha256: str
    security_evidence_sha256: str
    deployment_environment_sha256: str
    config_path_sha256: str
    graph_root_path_sha256: str
    run_root_path_sha256: str
    seccomp_path_sha256: str
    podman_info_sha256: str
    environment: tuple[tuple[str, str], ...]


@dataclass(frozen=True)
class _ImageContract:
    role: str
    user: str
    entrypoint: tuple[str, ...] | None
    cmd: tuple[str, ...] | None
    environment: tuple[tuple[str, str], ...]
    smoke_tail: tuple[str, ...]
    smoke_exit_code: int

    @property
    def uid(self) -> int:
        return int(self.user.split(":", 1)[0])


def _path_components(path: Path) -> tuple[Path, ...]:
    absolute = Path(os.path.abspath(path))
    if not absolute.is_absolute() or any(character in str(absolute) for character in "\x00\r\n"):
        raise DeploymentCheckError("deployment protected path is invalid")
    current = Path(absolute.anchor)
    components = [current]
    for part in absolute.parts[1:]:
        current /= part
        components.append(current)
    return tuple(components)


def _without_acl(path: Path) -> os.stat_result:
    try:
        metadata = os.lstat(path)
        if stat.S_ISLNK(metadata.st_mode):
            raise DeploymentCheckError("deployment protected path contains a symlink")
        extended = set(os.listxattr(path, follow_symlinks=False))
    except DeploymentCheckError:
        raise
    except OSError as exc:
        raise DeploymentCheckError("deployment protected path could not be inspected") from exc
    if extended & _ACL_XATTRS:
        raise DeploymentCheckError("deployment protected path has a POSIX ACL")
    return metadata


def _identity_payload(path: Path, metadata: os.stat_result, *, kind: str) -> dict[str, object]:
    return {
        "ctime_ns": metadata.st_ctime_ns,
        "device": metadata.st_dev,
        "gid": metadata.st_gid,
        "inode": metadata.st_ino,
        "kind": kind,
        "mode": stat.S_IMODE(metadata.st_mode),
        "path": str(path),
        "uid": metadata.st_uid,
    }


def _measure_private_directory(
    path: Path,
    *,
    owner_uid: int,
    candidate_uid: int,
    volatile_leaf_ctime: bool = False,
) -> dict[str, object]:
    absolute = Path(os.path.abspath(path))
    metadata: os.stat_result | None = None
    components: list[dict[str, object]] = []
    for component in _path_components(absolute):
        metadata = _without_acl(component)
        mode = stat.S_IMODE(metadata.st_mode)
        if not stat.S_ISDIR(metadata.st_mode):
            raise DeploymentCheckError("deployment private path ancestry is not a directory")
        if metadata.st_uid == candidate_uid or metadata.st_uid not in {0, owner_uid}:
            raise DeploymentCheckError("deployment private path has an untrusted owner")
        if mode & 0o022:
            raise DeploymentCheckError("deployment private path has a writable ancestor")
        identity = _identity_payload(component, metadata, kind="directory")
        if volatile_leaf_ctime and component == absolute:
            # Podman creates and removes runtime entries directly below graphRoot
            # during an otherwise read-only smoke.  That necessarily changes the
            # directory ctime; all trust-relevant identity fields remain bound.
            del identity["ctime_ns"]
            identity["volatile_metadata"] = ["ctime_ns"]
        components.append(identity)
    if metadata is None or not stat.S_ISDIR(metadata.st_mode):
        raise DeploymentCheckError("deployment private path is not a directory")
    if metadata.st_uid != owner_uid:
        raise DeploymentCheckError("deployment private path is not launcher-owned")
    if stat.S_IMODE(metadata.st_mode) & 0o077:
        raise DeploymentCheckError("deployment private path is not candidate-inaccessible")
    return {"components": components}


def _measure_launcher_file(
    path: Path,
    *,
    owner_uid: int,
    candidate_uid: int,
    maximum: int = 1024 * 1024,
) -> tuple[dict[str, object], bytes]:
    absolute = Path(os.path.abspath(path))
    metadata: os.stat_result | None = None
    components = _path_components(absolute)
    identities: list[dict[str, object]] = []
    for index, component in enumerate(components):
        metadata = _without_acl(component)
        mode = stat.S_IMODE(metadata.st_mode)
        expected_file = index == len(components) - 1
        if expected_file is not stat.S_ISREG(metadata.st_mode):
            raise DeploymentCheckError("deployment config path type is invalid")
        if metadata.st_uid == candidate_uid or metadata.st_uid not in {0, owner_uid}:
            raise DeploymentCheckError("deployment config path has an untrusted owner")
        if mode & 0o022:
            raise DeploymentCheckError("deployment config path has a writable ancestor")
        identities.append(
            _identity_payload(
                component,
                metadata,
                kind="file" if expected_file else "directory",
            )
        )
    if (
        metadata is None
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != owner_uid
        or metadata.st_nlink != 1
        or not 1 <= metadata.st_size <= maximum
    ):
        raise DeploymentCheckError("deployment config is not a bounded launcher-owned file")
    try:
        before = os.lstat(absolute)
        raw = absolute.read_bytes()
        after = os.lstat(absolute)
    except OSError as exc:
        raise DeploymentCheckError("deployment config could not be read") from exc
    stable = ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_size", "st_ctime_ns")
    if len(raw) != before.st_size or any(
        getattr(before, field) != getattr(after, field) for field in stable
    ):
        raise DeploymentCheckError("deployment config changed during measurement")
    identities[-1] = _identity_payload(absolute, after, kind="file")
    identities[-1]["content_sha256"] = hashlib.sha256(raw).hexdigest()
    return {"components": identities}, raw


def _measure_root_protected_file(
    path: Path, *, maximum: int = 4 * 1024 * 1024
) -> dict[str, object]:
    absolute = Path(os.path.abspath(path))
    metadata: os.stat_result | None = None
    path_components = _path_components(absolute)
    identities: list[dict[str, object]] = []
    for index, component in enumerate(path_components):
        metadata = _without_acl(component)
        mode = stat.S_IMODE(metadata.st_mode)
        expected_file = index == len(path_components) - 1
        if expected_file is not stat.S_ISREG(metadata.st_mode):
            raise DeploymentCheckError("deployment seccomp path type is invalid")
        if metadata.st_uid != 0 or mode & 0o022:
            raise DeploymentCheckError("deployment seccomp path is not root-protected")
        identities.append(
            _identity_payload(
                component,
                metadata,
                kind="file" if expected_file else "directory",
            )
        )
    if (
        metadata is None
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or not 1 <= metadata.st_size <= maximum
    ):
        raise DeploymentCheckError("deployment seccomp path is not a bounded regular file")
    try:
        before = os.lstat(absolute)
        raw = absolute.read_bytes()
        after = os.lstat(absolute)
    except OSError as exc:
        raise DeploymentCheckError("deployment seccomp path could not be read") from exc
    stable = ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_size", "st_ctime_ns")
    if len(raw) != before.st_size or any(
        getattr(before, field) != getattr(after, field) for field in stable
    ):
        raise DeploymentCheckError("deployment seccomp path changed during measurement")
    identities[-1] = _identity_payload(absolute, after, kind="file")
    identities[-1]["content_sha256"] = hashlib.sha256(raw).hexdigest()
    return {"components": identities}


def _path_evidence_sha256(value: dict[str, object]) -> str:
    return hashlib.sha256(_PATH_EVIDENCE_DOMAIN + _canonical(value)).hexdigest()


def validate_launcher_environment(
    *,
    launcher_uid: int,
    candidate_uid: int,
    environ: Mapping[str, str] = os.environ,
    passwd_lookup: Callable[[int], object] = pwd.getpwuid,
    runtime_base: Path = Path("/run/user"),
) -> LauncherEnvironmentEvidence:
    """Ignore inherited HOME/XDG settings and attest one canonical private boundary."""

    del environ  # Inherited values are intentionally never trusted or propagated.
    if (
        isinstance(launcher_uid, bool)
        or not isinstance(launcher_uid, int)
        or launcher_uid <= 0
        or isinstance(candidate_uid, bool)
        or not isinstance(candidate_uid, int)
        or candidate_uid <= 0
        or launcher_uid == candidate_uid
    ):
        raise DeploymentCheckError("deployment launcher and candidate UIDs are invalid")
    try:
        account = passwd_lookup(launcher_uid)
        account_uid = account.pw_uid
        raw_home = account.pw_dir
    except Exception as exc:
        raise DeploymentCheckError("deployment launcher passwd entry is unavailable") from exc
    if account_uid != launcher_uid or not isinstance(raw_home, str):
        raise DeploymentCheckError("deployment launcher passwd entry is invalid")
    home = Path(raw_home)
    if not home.is_absolute() or Path(os.path.abspath(home)) != home:
        raise DeploymentCheckError("deployment launcher passwd HOME is not canonical")
    config = home / ".config"
    data = home / ".local" / "share"
    runtime = Path(os.path.abspath(runtime_base)) / str(launcher_uid)
    measured = {
        "home": _measure_private_directory(
            home,
            owner_uid=launcher_uid,
            candidate_uid=candidate_uid,
        ),
        "xdg_config_home": _measure_private_directory(
            config,
            owner_uid=launcher_uid,
            candidate_uid=candidate_uid,
        ),
        "xdg_data_home": _measure_private_directory(
            data,
            owner_uid=launcher_uid,
            candidate_uid=candidate_uid,
        ),
        "xdg_runtime_dir": _measure_private_directory(
            runtime,
            owner_uid=launcher_uid,
            candidate_uid=candidate_uid,
        ),
    }
    environment = tuple(
        sorted(
            {
                "CONTAINERS_STORAGE_CONF": str(config / "containers" / "storage.conf"),
                "HOME": str(home),
                "LC_ALL": "C",
                "PATH": os.defpath,
                "XDG_CONFIG_HOME": str(config),
                "XDG_DATA_HOME": str(data),
                "XDG_RUNTIME_DIR": str(runtime),
            }.items()
        )
    )
    evidence = {"environment": environment, "paths": measured}
    return LauncherEnvironmentEvidence(
        environment=environment,
        evidence_sha256=hashlib.sha256(
            _ENVIRONMENT_EVIDENCE_DOMAIN + _canonical(evidence)
        ).hexdigest(),
    )


_IMAGE_CONTRACTS = {
    "coordinator": _ImageContract(
        role="coordinator",
        user="65532:65532",
        entrypoint=(
            "/opt/ai-review-runtime/.venv/bin/python",
            "-I",
            "/opt/ai-review-app/tools/ai_review/coordinator_main.py",
        ),
        cmd=None,
        environment=(
            ("HOME", "/nonexistent"),
            (
                "PATH",
                "/opt/ai-review-runtime/.venv/bin:/usr/local/bin:/usr/bin:/bin",
            ),
            ("PYTHONDONTWRITEBYTECODE", "1"),
            ("PYTHONHASHSEED", "0"),
            ("PYTHONNOUSERSITE", "1"),
            ("VIRTUAL_ENV", "/opt/ai-review-runtime/.venv"),
        ),
        smoke_tail=("--help",),
        smoke_exit_code=0,
    ),
    "offline-runner": _ImageContract(
        role="offline-runner",
        user="65534:65534",
        entrypoint=None,
        cmd=("python", "--version"),
        environment=(
            ("HOME", "/nonexistent"),
            (
                "PATH",
                "/opt/ai-review-runtime/.venv/bin:/usr/local/bin:/usr/bin:/bin",
            ),
            ("PYTHONDONTWRITEBYTECODE", "1"),
            ("PYTHONPYCACHEPREFIX", "/tmp/pycache"),
            ("PYTEST_ADDOPTS", "-p no:cacheprovider"),
            ("RUFF_CACHE_DIR", "/tmp/ruff-cache"),
            ("UV_CACHE_DIR", "/tmp/uv-cache"),
            ("UV_FROZEN", "1"),
            ("UV_NO_CACHE", "1"),
            ("UV_OFFLINE", "1"),
            ("UV_PROJECT_ENVIRONMENT", "/opt/ai-review-runtime/.venv"),
        ),
        smoke_tail=(),
        smoke_exit_code=0,
    ),
    "broker": _ImageContract(
        role="broker",
        user="65532:65532",
        entrypoint=("/opt/ai-review/bin/responses-broker",),
        cmd=None,
        environment=(
            ("HOME", "/nonexistent"),
            ("PATH", "/usr/local/bin:/usr/bin:/bin"),
            ("PYTHONDONTWRITEBYTECODE", "1"),
            ("PYTHONHASHSEED", "0"),
            ("PYTHONNOUSERSITE", "1"),
        ),
        smoke_tail=(),
        smoke_exit_code=2,
    ),
    "broker-gateway": _ImageContract(
        role="broker-gateway",
        user="65531:65531",
        entrypoint=("/opt/ai-review/bin/egress-gateway",),
        cmd=None,
        environment=(
            ("AI_REVIEW_EGRESS_GATEWAY", "1"),
            ("HOME", "/nonexistent"),
            ("PATH", "/usr/local/bin:/usr/bin:/bin"),
            ("PYTHONDONTWRITEBYTECODE", "1"),
            ("PYTHONHASHSEED", "0"),
            ("PYTHONNOUSERSITE", "1"),
        ),
        smoke_tail=("smoke",),
        smoke_exit_code=2,
    ),
}


def _canonical(value: object) -> bytes:
    try:
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
    except (TypeError, ValueError, UnicodeError) as exc:
        raise DeploymentCheckError("deployment evidence is not canonical JSON") from exc


def _domain_sha256(value: object) -> str:
    return hashlib.sha256(_EVIDENCE_DOMAIN + _canonical(value)).hexdigest()


def canonical_backend_evidence_sha256(backend: object) -> str:
    """Bind the live runtime executable and every asserted isolation property."""

    name = getattr(backend, "name", None)
    rootless = getattr(backend, "rootless", None)
    user_namespace = getattr(backend, "user_namespace", None)
    seccomp_enabled = getattr(backend, "seccomp_enabled", None)
    seccomp_profile = getattr(backend, "seccomp_profile", None)
    executable_sha256 = _sha(
        getattr(backend, "sha256", None),
        label="deployment runtime digest",
    )
    security_evidence_sha256 = _sha(
        getattr(backend, "security_evidence_sha256", None),
        label="deployment runtime security digest",
    )
    deployment_environment_sha256 = _sha(
        getattr(backend, "deployment_environment_sha256", None),
        label="deployment environment digest",
    )
    config_path_sha256 = _sha(
        getattr(backend, "config_path_sha256", None),
        label="deployment Podman config digest",
    )
    graph_root_path_sha256 = _sha(
        getattr(backend, "graph_root_path_sha256", None),
        label="deployment graph root digest",
    )
    run_root_path_sha256 = _sha(
        getattr(backend, "run_root_path_sha256", None),
        label="deployment run root digest",
    )
    seccomp_path_sha256 = _sha(
        getattr(backend, "seccomp_path_sha256", None),
        label="deployment seccomp path digest",
    )
    podman_info_sha256 = _sha(
        getattr(backend, "podman_info_sha256", None),
        label="deployment Podman info digest",
    )
    environment = getattr(backend, "environment", None)
    try:
        environment_map = dict(environment) if isinstance(environment, tuple) else {}
    except (TypeError, ValueError):
        environment_map = {}
    if (
        not isinstance(environment, tuple)
        or len(environment_map) != len(environment)
        or tuple(sorted(environment_map.items())) != environment
        or set(environment_map)
        != {
            "CONTAINERS_STORAGE_CONF",
            "HOME",
            "LC_ALL",
            "PATH",
            "XDG_CONFIG_HOME",
            "XDG_DATA_HOME",
            "XDG_RUNTIME_DIR",
        }
        or environment_map["LC_ALL"] != "C"
        or environment_map["PATH"] != os.defpath
        or any(
            not isinstance(value, str)
            or not value
            or any(character in value for character in "\x00\r\n")
            for value in environment_map.values()
        )
        or any(
            not Path(environment_map[name]).is_absolute()
            for name in (
                "CONTAINERS_STORAGE_CONF",
                "HOME",
                "XDG_CONFIG_HOME",
                "XDG_DATA_HOME",
                "XDG_RUNTIME_DIR",
            )
        )
    ):
        raise DeploymentCheckError("deployment runtime environment is invalid")
    _explicit_storage_config_path(environment_map)
    if (
        name != "podman"
        or rootless is not True
        or user_namespace is not True
        or seccomp_enabled is not True
        or not isinstance(seccomp_profile, str)
        or not seccomp_profile
        or "unconfined" in seccomp_profile.casefold()
        or any(character in seccomp_profile for character in "\x00\r\n")
    ):
        raise DeploymentCheckError("deployment runtime is not rootless Podman with seccomp")
    evidence = {
        "executable_sha256": executable_sha256,
        "deployment_environment_sha256": deployment_environment_sha256,
        "environment": list(environment),
        "config_path_sha256": config_path_sha256,
        "graph_root_path_sha256": graph_root_path_sha256,
        "name": name,
        "podman_info_sha256": podman_info_sha256,
        "rootless": rootless,
        "run_root_path_sha256": run_root_path_sha256,
        "seccomp_enabled": seccomp_enabled,
        "seccomp_path_sha256": seccomp_path_sha256,
        "seccomp_profile": seccomp_profile,
        "security_evidence_sha256": security_evidence_sha256,
        "user_namespace": user_namespace,
    }
    return hashlib.sha256(_BACKEND_EVIDENCE_DOMAIN + _canonical(evidence)).hexdigest()


def _strict_json(raw: bytes, *, label: str, maximum: int) -> Any:
    if not isinstance(raw, bytes) or not raw or len(raw) > maximum:
        raise DeploymentCheckError(f"{label} is empty or oversized")

    def pairs(values: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in values:
            if key in result:
                raise DeploymentCheckError(f"{label} contains a duplicate field")
            result[key] = value
        return result

    def reject_constant(_value: str) -> None:
        raise DeploymentCheckError(f"{label} contains a non-JSON number")

    try:
        return json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=pairs,
            parse_constant=reject_constant,
        )
    except DeploymentCheckError:
        raise
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise DeploymentCheckError(f"{label} is invalid JSON") from exc


def _sha(value: object, *, label: str) -> str:
    if not isinstance(value, str) or _SHA_RE.fullmatch(value) is None:
        raise DeploymentCheckError(f"{label} is not a lowercase SHA-256")
    return value


def _image_digest(value: object) -> str:
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= 512
        or any(token in value for token in ("://", "..", "//", "\\", "\x00", "\r", "\n"))
    ):
        raise DeploymentCheckError("deployment image is not a canonical registry reference")
    match = _IMAGE_RE.fullmatch(value)
    if match is None:
        raise DeploymentCheckError("deployment image is not a canonical registry reference")
    registry = match.group("registry")
    if ":" in registry and int(registry.rsplit(":", 1)[1]) > 65_535:
        raise DeploymentCheckError("deployment image is not a canonical registry reference")
    return match.group("digest")


def _validate_result_shape(value: object, *, validate_digest: bool) -> dict[str, Any]:
    fields = {
        "backend_evidence_sha256",
        "credentials_read",
        "deployment_evidence_sha256",
        "external_api_called",
        "external_network_created",
        "images",
        "manifest_sha256",
        "production_e2e_complete",
        "schema_version",
        "status",
    }
    if not isinstance(value, dict) or set(value) != fields:
        raise DeploymentCheckError("deployment evidence has missing or unknown fields")
    if (
        value["schema_version"] != "1.0"
        or value["status"] != "nonlive_ready"
        or value["credentials_read"] is not False
        or value["external_api_called"] is not False
        or value["external_network_created"] is not False
        or value["production_e2e_complete"] is not False
    ):
        raise DeploymentCheckError("deployment evidence overstates the non-live result")
    _sha(value["manifest_sha256"], label="deployment manifest digest")
    _sha(value["backend_evidence_sha256"], label="deployment backend evidence digest")
    evidence_sha256 = _sha(
        value["deployment_evidence_sha256"],
        label="deployment evidence digest",
    )
    images = value["images"]
    if not isinstance(images, list):
        raise DeploymentCheckError("deployment image evidence is invalid")
    roles: list[str] = []
    image_fields = {
        "digest",
        "inspect_sha256",
        "metadata_sha256",
        "role",
        "smoke_argv_sha256",
        "smoke_exit_code",
        "smoke_stderr_sha256",
        "smoke_stdout_sha256",
    }
    for item in images:
        if not isinstance(item, dict) or set(item) != image_fields:
            raise DeploymentCheckError("deployment image evidence is invalid")
        role = item["role"]
        if role not in _IMAGE_CONTRACTS:
            raise DeploymentCheckError("deployment image role is invalid")
        roles.append(role)
        if not isinstance(item["digest"], str) or _DIGEST_RE.fullmatch(item["digest"]) is None:
            raise DeploymentCheckError("deployment image digest is invalid")
        if item["smoke_exit_code"] != _IMAGE_CONTRACTS[role].smoke_exit_code:
            raise DeploymentCheckError("deployment image smoke exit code is invalid")
        for name in (
            "inspect_sha256",
            "metadata_sha256",
            "smoke_argv_sha256",
            "smoke_stderr_sha256",
            "smoke_stdout_sha256",
        ):
            _sha(item[name], label=f"deployment image {name}")
    if roles != sorted(_IMAGE_CONTRACTS) or len(roles) != len(set(roles)):
        raise DeploymentCheckError("deployment image evidence set is incomplete")
    if validate_digest:
        unsigned = {key: item for key, item in value.items() if key != "deployment_evidence_sha256"}
        if evidence_sha256 != _domain_sha256(unsigned):
            raise DeploymentCheckError("deployment evidence digest is invalid")
    return value


def canonical_deployment_check_bytes(
    value: object,
    *,
    validate_digest: bool = True,
) -> bytes:
    """Return the only canonical encoding accepted for non-live readiness evidence."""

    return _canonical(_validate_result_shape(value, validate_digest=validate_digest))


def validate_deployment_check_bytes(
    raw: bytes,
    *,
    expected_manifest_sha256: str,
    expected_backend_evidence_sha256: str,
    expected_image_digests: dict[str, str],
) -> dict[str, Any]:
    value = _strict_json(raw, label="deployment evidence", maximum=128_000)
    parsed = _validate_result_shape(value, validate_digest=True)
    if _canonical(parsed) != raw:
        raise DeploymentCheckError("deployment evidence is not canonical JSON")
    if (
        parsed["manifest_sha256"] != expected_manifest_sha256
        or parsed["backend_evidence_sha256"] != expected_backend_evidence_sha256
        or {item["role"]: item["digest"] for item in parsed["images"]} != expected_image_digests
    ):
        raise DeploymentCheckError("deployment evidence differs from its trusted inputs")
    return parsed


def _command(
    runner: Callable[..., object],
    argv: tuple[str, ...],
    *,
    environment: dict[str, str],
    maximum: int,
    timeout_seconds: int = _SMOKE_TIMEOUT_SECONDS,
) -> tuple[int, bytes, bytes, int]:
    if (
        not argv
        or not Path(argv[0]).is_absolute()
        or any(
            not isinstance(item, str) or not item or any(c in item for c in "\x00\r\n")
            for item in argv
        )
        or any("docker.sock" in item or "podman.sock" in item for item in argv)
    ):
        raise DeploymentCheckError("deployment runtime command is invalid")
    try:
        measured = runner(
            argv,
            environment=environment,
            timeout_seconds=timeout_seconds,
            max_output_bytes=maximum,
        )
        exit_code = measured.exit_code
        stdout = measured.stdout
        stderr = measured.stderr
        duration_ms = measured.duration_ms
    except Exception as exc:
        raise DeploymentCheckError("deployment runtime command failed") from exc
    if (
        isinstance(exit_code, bool)
        or not isinstance(exit_code, int)
        or not isinstance(stdout, bytes)
        or not isinstance(stderr, bytes)
        or len(stdout) + len(stderr) > maximum
        or isinstance(duration_ms, bool)
        or not isinstance(duration_ms, int)
        or not 0 <= duration_ms <= timeout_seconds * 1_000
        or getattr(measured, "stdout_sha256", "") != hashlib.sha256(stdout).hexdigest()
        or getattr(measured, "stderr_sha256", "") != hashlib.sha256(stderr).hexdigest()
    ):
        raise DeploymentCheckError("deployment runtime result is invalid")
    return exit_code, stdout, stderr, duration_ms


def _canonical_absolute_path(value: object, *, label: str) -> Path:
    if (
        not isinstance(value, str)
        or not value
        or any(character in value for character in "\x00\r\n")
    ):
        raise DeploymentCheckError(f"{label} is invalid")
    path = Path(value)
    if not path.is_absolute() or Path(os.path.abspath(path)) != path:
        raise DeploymentCheckError(f"{label} is not canonical")
    return path


def _explicit_storage_config_path(environment: Mapping[str, str]) -> Path:
    """Return the one launcher-selected containers/storage.conf path."""

    try:
        config_home = _canonical_absolute_path(
            environment["XDG_CONFIG_HOME"],
            label="deployment XDG_CONFIG_HOME",
        )
        config = _canonical_absolute_path(
            environment["CONTAINERS_STORAGE_CONF"],
            label="deployment CONTAINERS_STORAGE_CONF",
        )
    except KeyError as exc:
        raise DeploymentCheckError("deployment CONTAINERS_STORAGE_CONF is required") from exc
    expected = config_home / "containers" / "storage.conf"
    if config != expected:
        raise DeploymentCheckError(
            "deployment CONTAINERS_STORAGE_CONF is not the canonical launcher config"
        )
    return config


def _storage_line_without_comment(line: str) -> str:
    quote: str | None = None
    escaped = False
    output: list[str] = []
    for character in line:
        if character in "\x00\r":
            raise DeploymentCheckError("deployment storage config has a control character")
        if quote == '"' and escaped:
            escaped = False
            output.append(character)
            continue
        if quote == '"' and character == "\\":
            escaped = True
            output.append(character)
            continue
        if quote is not None:
            output.append(character)
            if character == quote:
                quote = None
            continue
        if character in {'"', "'"}:
            quote = character
            output.append(character)
        elif character == "#":
            break
        else:
            output.append(character)
    if quote is not None or escaped:
        raise DeploymentCheckError("deployment storage config has an unterminated string")
    return "".join(output).strip()


def _storage_scalar(value: str) -> object:
    if not value or "'''" in value or '"""' in value:
        raise DeploymentCheckError("deployment storage config value is unsupported")
    if value in {"true", "false"}:
        return value == "true"
    if re.fullmatch(r"[+-]?(?:0|[1-9][0-9]*)", value) is not None:
        return int(value)
    if value == "[]":
        return ()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
        inner = value[1:-1]
        if value[0] == '"' and "\\" in inner:
            raise DeploymentCheckError("deployment storage config escapes are unsupported")
        if value[0] in inner or any(character in inner for character in "\x00\r\n"):
            raise DeploymentCheckError("deployment storage config string is unsupported")
        return inner
    raise DeploymentCheckError("deployment storage config value is unsupported")


def _graph_option_text(value: object, *, legacy: bool = False) -> str:
    if not isinstance(value, str):
        raise DeploymentCheckError("deployment Podman graph options value is invalid")
    try:
        encoded = value.encode("utf-8", errors="strict")
    except UnicodeError as exc:
        raise DeploymentCheckError("deployment Podman graph options value is invalid") from exc
    maximum = 4_096 if legacy else 16_384
    allowed_controls = set() if legacy else {"\n", "\t"}
    if (
        not 1 <= len(encoded) <= maximum
        or any(ord(character) < 32 and character not in allowed_controls for character in value)
        or "\x7f" in value
    ):
        raise DeploymentCheckError("deployment Podman graph options value is invalid")
    if "imagestore" in value.casefold():
        raise DeploymentCheckError("deployment Podman external image store is forbidden")
    return value


def _graph_option_key(value: object, *, nested: bool) -> str:
    pattern = r"^[A-Za-z][A-Za-z0-9_.-]{0,63}$" if nested else r"^[a-z0-9][a-z0-9_.-]{0,127}$"
    if not isinstance(value, str) or re.fullmatch(pattern, value) is None:
        raise DeploymentCheckError("deployment Podman graph options key is invalid")
    if "imagestore" in value.casefold():
        raise DeploymentCheckError("deployment Podman external image store is forbidden")
    return value


def _validated_graph_options(value: object) -> list[str] | dict[str, object]:
    """Validate and stabilize legacy and Podman 6 graph option representations."""

    if isinstance(value, list):
        if len(value) > 128:
            raise DeploymentCheckError("deployment Podman graph options are oversized")
        options = [_graph_option_text(item, legacy=True) for item in value]
        if len(set(options)) != len(options):
            raise DeploymentCheckError("deployment Podman graph options are duplicated")
        return sorted(options)
    if not isinstance(value, dict) or len(value) > 128:
        raise DeploymentCheckError("deployment Podman graph options shape is invalid")
    normalized: dict[str, object] = {}
    keys = [_graph_option_key(raw_key, nested=False) for raw_key in value]
    for key in sorted(keys):
        raw_option = value[key]
        if isinstance(raw_option, str):
            normalized[key] = _graph_option_text(raw_option)
            continue
        if not isinstance(raw_option, dict) or not 1 <= len(raw_option) <= 32:
            raise DeploymentCheckError("deployment Podman graph options value is invalid")
        metadata: dict[str, str] = {}
        metadata_keys = [
            _graph_option_key(raw_metadata_key, nested=True) for raw_metadata_key in raw_option
        ]
        for metadata_key in sorted(metadata_keys):
            metadata[metadata_key] = _graph_option_text(raw_option[metadata_key])
        normalized[key] = metadata
    return normalized


def _reported_mount_program(
    graph_options: list[str] | dict[str, object],
) -> Path | None:
    values: list[str] = []
    if isinstance(graph_options, list):
        prefix = "overlay.mount_program="
        values = [item[len(prefix) :] for item in graph_options if item.startswith(prefix)]
    else:
        option = graph_options.get("overlay.mount_program")
        if isinstance(option, str):
            values = [option]
        elif isinstance(option, dict):
            executable = option.get("Executable")
            if not isinstance(executable, str):
                raise DeploymentCheckError(
                    "deployment Podman graph options mount_program is invalid"
                )
            values = [executable]
    if not values:
        return None
    if len(values) != 1:
        raise DeploymentCheckError("deployment Podman graph options mount_program is duplicated")
    return _canonical_absolute_path(
        values[0],
        label="deployment Podman graph options mount_program",
    )


def validate_storage_config(
    raw: bytes,
    *,
    graph_driver_name: str,
    graph_root: Path,
    run_root: Path,
    transient_store: bool,
) -> Path | None:
    """Validate a bounded Python-3.10-compatible subset of containers/storage.conf.

    Podman has already parsed the file.  This parser intentionally accepts only
    reviewed bare tables, bare keys, and single-line scalar values so quoted,
    dotted, escaped, multiline, and inline-table forms cannot hide image stores.
    """

    if not isinstance(raw, bytes) or not 1 <= len(raw) <= 1024 * 1024:
        raise DeploymentCheckError("deployment storage config is empty or oversized")
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeError as exc:
        raise DeploymentCheckError("deployment storage config is not UTF-8") from exc
    table: str | None = None
    assignments: dict[tuple[str, str], object] = {}
    table_re = re.compile(r"^\[([a-z0-9_-]+(?:\.[a-z0-9_-]+)*)\]$")
    assignment_re = re.compile(r"^([a-z][a-z0-9_-]*)\s*=\s*(.+)$")
    for raw_line in text.splitlines():
        line = _storage_line_without_comment(raw_line)
        if not line:
            continue
        table_match = table_re.fullmatch(line)
        if table_match is not None:
            table = table_match.group(1)
            if table not in _STORAGE_TABLE_KEYS:
                raise DeploymentCheckError("deployment storage config table is unsupported")
            continue
        assignment_match = assignment_re.fullmatch(line)
        if assignment_match is None or table is None:
            raise DeploymentCheckError("deployment storage config syntax is unsupported")
        key = assignment_match.group(1)
        if key not in _STORAGE_TABLE_KEYS[table]:
            raise DeploymentCheckError("deployment storage config key is unsupported")
        identity = (table, key)
        if identity in assignments:
            raise DeploymentCheckError("deployment storage config key is duplicated")
        assignments[identity] = _storage_scalar(assignment_match.group(2).strip())

    for identity in (
        ("storage", "imagestore"),
        ("storage.options", "additionalimagestores"),
    ):
        if identity in assignments and assignments[identity] not in {"", ()}:
            raise DeploymentCheckError("deployment Podman external image store is forbidden")
    expected = {
        ("storage", "driver"): graph_driver_name,
        ("storage", "graphroot"): str(graph_root),
        ("storage", "runroot"): str(run_root),
        ("storage", "transient_store"): transient_store,
    }
    if any(
        identity in assignments and assignments[identity] != value
        for identity, value in expected.items()
    ):
        raise DeploymentCheckError("deployment storage config differs from Podman info")
    mount_program = assignments.get(("storage.options.overlay", "mount_program"))
    if mount_program is None:
        return None
    return _canonical_absolute_path(
        mount_program,
        label="deployment storage config mount_program",
    )


def detect_deployment_backend(
    *,
    coordinator_module: object,
    candidate_uid: int,
    launcher_uid: int,
    host: LauncherEnvironmentEvidence,
    runner: Callable[..., object],
) -> DeploymentBackend:
    """Probe Podman with the attested HOME/XDG environment and bind its paths."""

    if not isinstance(host, LauncherEnvironmentEvidence):
        raise DeploymentCheckError("deployment launcher environment evidence is invalid")
    environment = dict(host.environment)
    config = _explicit_storage_config_path(environment)
    podman_raw = shutil.which("podman", path=os.defpath)
    if podman_raw is None:
        raise DeploymentCheckError("deployment readiness requires rootless Podman")
    try:
        podman = Path(podman_raw).resolve(strict=True)
    except OSError as exc:
        raise DeploymentCheckError("deployment Podman executable is unavailable") from exc
    info_raw: bytes | None = None

    def which(name: str) -> str | None:
        return str(podman) if name == "podman" else None

    def probe(argv: tuple[str, ...], **_ignored: object) -> subprocess.CompletedProcess[str]:
        nonlocal info_raw
        if argv != (str(podman), "info", "--format", "json") or info_raw is not None:
            raise DeploymentCheckError("deployment Podman probe command is invalid")
        exit_code, stdout, stderr, _duration = _command(
            runner,
            argv,
            environment=environment,
            maximum=_MAX_INSPECT_BYTES,
            timeout_seconds=10,
        )
        info_raw = stdout
        try:
            text_stdout = stdout.decode("utf-8", errors="strict")
            text_stderr = stderr.decode("utf-8", errors="strict")
        except UnicodeError as exc:
            raise DeploymentCheckError("deployment Podman info is not UTF-8") from exc
        return subprocess.CompletedProcess(argv, exit_code, text_stdout, text_stderr)

    try:
        detected = coordinator_module.detect_container_backend(
            candidate_uid=candidate_uid,
            which=which,
            probe=probe,
        )
        detected = coordinator_module._validate_backend(
            detected,
            candidate_uid=candidate_uid,
        )
    except DeploymentCheckError:
        raise
    except Exception as exc:
        raise DeploymentCheckError("deployment Podman backend probe failed") from exc
    if info_raw is None or getattr(detected, "name", None) != "podman":
        raise DeploymentCheckError("deployment readiness requires rootless Podman")
    value = _strict_json(info_raw, label="deployment Podman info", maximum=_MAX_INSPECT_BYTES)
    try:
        store = value["store"]
        security = value["host"]["security"]
        rootless = security["rootless"]
        seccomp_enabled = security["seccompEnabled"]
        graph_driver_name = store["graphDriverName"]
        graph_options = store["graphOptions"]
        transient_store = store["transientStore"]
        reported_config_raw = store.get("configFile")
        reported_config = (
            None
            if reported_config_raw is None
            else _canonical_absolute_path(
                reported_config_raw,
                label="deployment Podman configFile",
            )
        )
        graph_root = _canonical_absolute_path(
            store["graphRoot"],
            label="deployment Podman graphRoot",
        )
        run_root = _canonical_absolute_path(
            store["runRoot"],
            label="deployment Podman runRoot",
        )
        seccomp = _canonical_absolute_path(
            security["seccompProfilePath"],
            label="deployment Podman seccomp profile",
        )
    except (KeyError, TypeError) as exc:
        raise DeploymentCheckError("deployment Podman info lacks protected paths") from exc
    if (
        rootless is not True
        or seccomp_enabled is not True
        or not isinstance(graph_driver_name, str)
        or not graph_driver_name
        or any(character in graph_driver_name for character in "\x00\r\n")
        or type(transient_store) is not bool
    ):
        raise DeploymentCheckError("deployment Podman info security subset is invalid")
    graph_options = _validated_graph_options(graph_options)
    if reported_config is not None and reported_config != config:
        raise DeploymentCheckError(
            "deployment Podman configFile disagrees with CONTAINERS_STORAGE_CONF"
        )
    config_home = Path(environment["XDG_CONFIG_HOME"])
    data_home = Path(environment["XDG_DATA_HOME"])
    runtime = Path(environment["XDG_RUNTIME_DIR"])
    if (
        config == config_home
        or not config.is_relative_to(config_home)
        or graph_root == data_home
        or not graph_root.is_relative_to(data_home)
        or run_root == runtime
        or not run_root.is_relative_to(runtime)
    ):
        raise DeploymentCheckError("deployment Podman storage paths escape canonical XDG roots")
    if seccomp != Path(getattr(detected, "seccomp_profile", "")):
        raise DeploymentCheckError("deployment Podman seccomp paths disagree")
    config_evidence, config_raw = _measure_launcher_file(
        config,
        owner_uid=launcher_uid,
        candidate_uid=candidate_uid,
    )
    configured_mount_program = validate_storage_config(
        config_raw,
        graph_driver_name=graph_driver_name,
        graph_root=graph_root,
        run_root=run_root,
        transient_store=transient_store,
    )
    reported_mount_program = _reported_mount_program(graph_options)
    if configured_mount_program is not None and reported_mount_program != configured_mount_program:
        raise DeploymentCheckError("deployment Podman mount_program disagrees with storage config")
    graph_evidence = _measure_private_directory(
        graph_root,
        owner_uid=launcher_uid,
        candidate_uid=candidate_uid,
        volatile_leaf_ctime=True,
    )
    run_evidence = _measure_private_directory(
        run_root,
        owner_uid=launcher_uid,
        candidate_uid=candidate_uid,
    )
    seccomp_evidence = _measure_root_protected_file(seccomp)
    security_subset = {
        "host": {
            "security": {
                "rootless": rootless,
                "seccompEnabled": seccomp_enabled,
                "seccompProfilePath": str(seccomp),
            }
        },
        "store": {
            "configFile": str(config),
            "graphDriverName": graph_driver_name,
            "graphOptions": graph_options,
            "graphRoot": str(graph_root),
            "runRoot": str(run_root),
            "transientStore": transient_store,
        },
    }
    return DeploymentBackend(
        name=detected.name,
        executable=detected.executable,
        rootless=detected.rootless,
        user_namespace=detected.user_namespace,
        seccomp_enabled=detected.seccomp_enabled,
        seccomp_profile=detected.seccomp_profile,
        sha256=detected.sha256,
        security_evidence_sha256=detected.security_evidence_sha256,
        deployment_environment_sha256=host.evidence_sha256,
        config_path_sha256=_path_evidence_sha256(config_evidence),
        graph_root_path_sha256=_path_evidence_sha256(graph_evidence),
        run_root_path_sha256=_path_evidence_sha256(run_evidence),
        seccomp_path_sha256=_path_evidence_sha256(seccomp_evidence),
        podman_info_sha256=hashlib.sha256(_canonical(security_subset)).hexdigest(),
        environment=host.environment,
    )


def _environment_map(value: object, *, contract: _ImageContract) -> dict[str, str]:
    if not isinstance(value, list):
        raise DeploymentCheckError("deployment image inspection is invalid")
    environment: dict[str, str] = {}
    for item in value:
        if (
            not isinstance(item, str)
            or "=" not in item
            or any(character in item for character in "\x00\r\n")
        ):
            raise DeploymentCheckError("deployment image inspection is invalid")
        name, setting = item.split("=", 1)
        if not name or name in environment:
            raise DeploymentCheckError("deployment image inspection is invalid")
        environment[name] = setting
    if {name.casefold() for name in environment} & _FORBIDDEN_ENVIRONMENT_NAMES:
        raise DeploymentCheckError("deployment image inspection is invalid")
    expected = dict(contract.environment)
    if set(environment) != set(expected) | set(_BASE_ENVIRONMENT):
        raise DeploymentCheckError("deployment image inspection is invalid")
    exact_environment = {**_BASE_ENVIRONMENT, **expected}
    if environment != exact_environment:
        raise DeploymentCheckError("deployment image inspection is invalid")
    return environment


def _command_sequence(value: object) -> tuple[str, ...] | None:
    if value is None:
        return None
    if not isinstance(value, list) or any(
        not isinstance(item, str) or not item or any(character in item for character in "\x00\r\n")
        for item in value
    ):
        raise DeploymentCheckError("deployment image inspection is invalid")
    return tuple(value)


def _inspect_image(
    role: str,
    image: str,
    expected_digest: str,
    raw: bytes,
) -> tuple[str, str]:
    contract = _IMAGE_CONTRACTS[role]
    value = _strict_json(raw, label="deployment image inspection", maximum=_MAX_INSPECT_BYTES)
    if not isinstance(value, list) or len(value) != 1 or not isinstance(value[0], dict):
        raise DeploymentCheckError("deployment image inspection is invalid")
    inspected = value[0]
    config = inspected.get("Config")
    repo_digests = inspected.get("RepoDigests")
    if (
        inspected.get("Digest") != expected_digest
        or not isinstance(repo_digests, list)
        or image not in repo_digests
        or not isinstance(config, dict)
        or config.get("User") != contract.user
    ):
        raise DeploymentCheckError("deployment image inspection is invalid")
    normalized_entrypoint = _command_sequence(config.get("Entrypoint"))
    normalized_cmd = _command_sequence(config.get("Cmd"))
    if normalized_entrypoint != contract.entrypoint or normalized_cmd != contract.cmd:
        raise DeploymentCheckError("deployment image inspection is invalid")
    environment = _environment_map(config.get("Env"), contract=contract)
    normalized = {
        "cmd": list(normalized_cmd) if normalized_cmd is not None else None,
        "digest": expected_digest,
        "entrypoint": list(normalized_entrypoint) if normalized_entrypoint is not None else None,
        "environment": sorted(environment.items()),
        "role": role,
        "user": contract.user,
    }
    return hashlib.sha256(raw).hexdigest(), hashlib.sha256(_canonical(normalized)).hexdigest()


def _smoke_argv(
    *,
    runtime: Path,
    role: str,
    image: str,
    container_name: str,
) -> tuple[str, ...]:
    contract = _IMAGE_CONTRACTS[role]
    uid = contract.uid
    return (
        str(runtime),
        "run",
        "--rm",
        "--pull=never",
        f"--name={container_name}",
        "--network=none",
        "--read-only",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "--ipc=none",
        f"--userns=keep-id:uid={uid},gid={uid}",
        f"--user={contract.user}",
        "--workdir=/",
        "--pids-limit=16",
        "--memory=128m",
        "--cpus=0.5",
        "--tmpfs=/tmp:rw,noexec,nosuid,nodev,size=4m,mode=1777",
        image,
        *contract.smoke_tail,
    )


def _assert_absent(
    runner: Callable[..., object],
    *,
    runtime: Path,
    name: str,
    environment: dict[str, str],
) -> None:
    exit_code, stdout, stderr, _duration = _command(
        runner,
        (str(runtime), "container", "exists", name),
        environment=environment,
        maximum=_MAX_COMMAND_BYTES,
        timeout_seconds=30,
    )
    if exit_code != 1 or stdout or stderr:
        raise DeploymentCheckError("deployment smoke container cleanup is not proven")


def _cleanup_if_present(
    runner: Callable[..., object],
    *,
    runtime: Path,
    name: str,
    environment: dict[str, str],
) -> None:
    exit_code, stdout, stderr, _duration = _command(
        runner,
        (str(runtime), "container", "exists", name),
        environment=environment,
        maximum=_MAX_COMMAND_BYTES,
        timeout_seconds=30,
    )
    if stdout or stderr or exit_code not in {0, 1}:
        raise DeploymentCheckError("deployment smoke container state is invalid")
    if exit_code == 0:
        removed, _stdout, _stderr, _duration = _command(
            runner,
            (str(runtime), "rm", "-f", "--", name),
            environment=environment,
            maximum=_MAX_COMMAND_BYTES,
            timeout_seconds=30,
        )
        if removed != 0:
            raise DeploymentCheckError("deployment smoke container cleanup failed")
    _assert_absent(runner, runtime=runtime, name=name, environment=environment)


def _smoke_image(
    runner: Callable[..., object],
    *,
    runtime: Path,
    role: str,
    image: str,
    environment: dict[str, str],
    token_hex: Callable[[int], str],
) -> tuple[str, int, str, str]:
    token = token_hex(8)
    container_name = f"ai-review-deploy-{role}-{token}"
    if _CONTAINER_RE.fullmatch(container_name) is None:
        raise DeploymentCheckError("deployment smoke container name is invalid")
    _assert_absent(runner, runtime=runtime, name=container_name, environment=environment)
    argv = _smoke_argv(
        runtime=runtime,
        role=role,
        image=image,
        container_name=container_name,
    )
    failure: Exception | None = None
    result: tuple[int, bytes, bytes, int] | None = None
    try:
        result = _command(
            runner,
            argv,
            environment=environment,
            maximum=_MAX_COMMAND_BYTES,
        )
    except Exception as exc:
        failure = exc
    try:
        _cleanup_if_present(
            runner,
            runtime=runtime,
            name=container_name,
            environment=environment,
        )
    except Exception as exc:
        failure = DeploymentCheckError("deployment smoke cleanup failed")
        failure.__cause__ = exc
    if failure is not None:
        if isinstance(failure, DeploymentCheckError):
            raise failure
        raise DeploymentCheckError("deployment smoke failed") from failure
    if result is None:
        raise DeploymentCheckError("deployment smoke result is missing")
    exit_code, stdout, stderr, _duration = result
    contract = _IMAGE_CONTRACTS[role]
    if exit_code != contract.smoke_exit_code:
        raise DeploymentCheckError("deployment smoke result is invalid")
    if role == "coordinator":
        try:
            stdout.decode("utf-8", errors="strict")
        except UnicodeError as exc:
            raise DeploymentCheckError("deployment smoke result is invalid") from exc
        valid_output = (
            not stderr
            and stdout.startswith(b"usage: ")
            and b"snapshot" in stdout
            and b"attested-judge" in stdout
        )
    elif role == "offline-runner":
        valid_output = not stderr and stdout == b"Python 3.13.7\n"
    elif role == "broker":
        valid_output = (
            not stdout
            and stderr == b"ai-review-broker: request is empty or exceeds the byte limit\n"
        )
    else:
        valid_output = (
            not stdout and stderr == b"egress gateway error: egress gateway accepts no arguments\n"
        )
    if not valid_output:
        raise DeploymentCheckError("deployment smoke result is invalid")
    return (
        hashlib.sha256("\0".join(argv).encode("utf-8")).hexdigest(),
        exit_code,
        hashlib.sha256(stdout).hexdigest(),
        hashlib.sha256(stderr).hexdigest(),
    )


def run_deployment_check(
    *,
    manifest_sha256: str,
    backend: object,
    images: dict[str, str],
    approved_digests: dict[str, str],
    runner: Callable[..., object],
    token_hex: Callable[[int], str] = secrets.token_hex,
) -> bytes:
    """Inspect and smoke four local images with a fixed 60-second per-smoke limit.

    The external launcher's workflow ``--timeout-seconds`` option is intentionally
    not an input to this non-live contract.
    """

    _sha(manifest_sha256, label="deployment manifest digest")
    if set(images) != set(_IMAGE_CONTRACTS) or set(approved_digests) != set(_IMAGE_CONTRACTS):
        raise DeploymentCheckError("deployment image set is incomplete")
    if (
        getattr(backend, "name", None) != "podman"
        or getattr(backend, "rootless", None) is not True
        or getattr(backend, "user_namespace", None) is not True
        or getattr(backend, "seccomp_enabled", None) is not True
        or not isinstance(getattr(backend, "seccomp_profile", None), str)
        or not backend.seccomp_profile
        or "unconfined" in backend.seccomp_profile.casefold()
    ):
        raise DeploymentCheckError("deployment runtime is not rootless Podman with seccomp")
    runtime = getattr(backend, "executable", None)
    if not isinstance(runtime, Path) or not runtime.is_absolute() or runtime.name != "podman":
        raise DeploymentCheckError("deployment runtime executable is invalid")
    backend_evidence_sha256 = canonical_backend_evidence_sha256(backend)
    for role in sorted(_IMAGE_CONTRACTS):
        digest = approved_digests[role]
        if (
            not isinstance(digest, str)
            or _DIGEST_RE.fullmatch(digest) is None
            or _image_digest(images[role]) != digest
        ):
            raise DeploymentCheckError("deployment image is not manifest-pinned")
    if len(set(approved_digests.values())) != len(_IMAGE_CONTRACTS):
        raise DeploymentCheckError("deployment images require distinct manifest digests")

    try:
        environment = dict(backend.environment)
    except (AttributeError, TypeError, ValueError) as exc:
        raise DeploymentCheckError("deployment runtime environment is invalid") from exc
    if tuple(sorted(environment.items())) != backend.environment:
        raise DeploymentCheckError("deployment runtime environment is not canonical")
    image_evidence: list[dict[str, object]] = []
    for role in sorted(_IMAGE_CONTRACTS):
        image = images[role]
        inspected_exit, inspect_stdout, inspect_stderr, _duration = _command(
            runner,
            (str(runtime), "image", "inspect", image),
            environment=environment,
            maximum=_MAX_INSPECT_BYTES,
            timeout_seconds=30,
        )
        if inspected_exit != 0 or inspect_stderr:
            raise DeploymentCheckError("deployment image inspection failed")
        inspect_sha256, metadata_sha256 = _inspect_image(
            role,
            image,
            approved_digests[role],
            inspect_stdout,
        )
        (
            smoke_argv_sha256,
            smoke_exit_code,
            smoke_stdout_sha256,
            smoke_stderr_sha256,
        ) = _smoke_image(
            runner,
            runtime=runtime,
            role=role,
            image=image,
            environment=environment,
            token_hex=token_hex,
        )
        image_evidence.append(
            {
                "digest": approved_digests[role],
                "inspect_sha256": inspect_sha256,
                "metadata_sha256": metadata_sha256,
                "role": role,
                "smoke_argv_sha256": smoke_argv_sha256,
                "smoke_exit_code": smoke_exit_code,
                "smoke_stderr_sha256": smoke_stderr_sha256,
                "smoke_stdout_sha256": smoke_stdout_sha256,
            }
        )
    unsigned = {
        "backend_evidence_sha256": backend_evidence_sha256,
        "credentials_read": False,
        "external_api_called": False,
        "external_network_created": False,
        "images": image_evidence,
        "manifest_sha256": manifest_sha256,
        "production_e2e_complete": False,
        "schema_version": "1.0",
        "status": "nonlive_ready",
    }
    result = {**unsigned, "deployment_evidence_sha256": _domain_sha256(unsigned)}
    return canonical_deployment_check_bytes(result)
