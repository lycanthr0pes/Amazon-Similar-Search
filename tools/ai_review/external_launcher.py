"""Root-owned production entrypoint for import-before-exec runtime preflight.

Production installs this package outside every candidate checkout and starts it
with the exact Python asset pinned by the runtime manifest, using an absolute,
root-owned no-site invocation (``/approved/python -I -S
/approved/external_launcher.py``).  The
root-owned installation is the bootstrap trust anchor; hashing this launcher by
the launcher itself would not establish trust.  Direct source-checkout use is a
diagnostic that prints FD-bound argv and never executes it.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import importlib.util
import importlib
import json
import os
import re
import secrets
import stat
import sys
from pathlib import Path
from typing import Any


def _sibling_preflight_path() -> Path:
    return Path(__file__).absolute().with_name("preflight.py")


def _load_sibling_preflight(path: Path):
    """Load only the approved stdlib-only sibling, without importing package __init__.py."""

    spec = importlib.util.spec_from_file_location("_ai_review_external_preflight", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("approved preflight module could not be loaded")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _load_verified_harness_module(evidence: Any, module_name: str):
    """Import stdlib-only outer support from one already-hashed zipapp descriptor.

    Multiple support modules may be loaded during a workflow, but every existing
    ``tools`` package component must already originate in this exact archive.
    This keeps the namespace closed without making the first import a one-shot
    operation.
    """

    archive = evidence.fd_path("harness")
    if not module_name.startswith("tools.ai_review."):
        raise LauncherTrustError("verified harness module name is outside the allowlist")

    def trusted_origin(module: Any) -> bool:
        origins: list[str] = []
        path = getattr(module, "__file__", None)
        if isinstance(path, str):
            origins.append(path)
        package_paths = getattr(module, "__path__", ())
        origins.extend(value for value in package_paths if isinstance(value, str))
        return bool(origins) and all(
            value == archive or value.startswith(archive + "/") for value in origins
        )

    relevant = {
        name: module
        for name, module in sys.modules.items()
        if name in {"tools", "tools.ai_review"} or name.startswith("tools.ai_review.")
    }
    if any(not trusted_origin(module) for module in relevant.values()):
        raise LauncherTrustError("verified harness import namespace is already contaminated")
    before = set(sys.modules)
    sys.path.insert(0, archive)
    try:
        module = importlib.import_module(module_name)
    except Exception as exc:
        raise LauncherTrustError("verified coordinator module could not be imported") from exc
    finally:
        try:
            sys.path.remove(archive)
        except ValueError:
            pass
    origin = getattr(module, "__file__", "")
    if not isinstance(origin, str) or not origin.startswith(archive + "/"):
        raise LauncherTrustError("coordinator module was not imported from the verified harness")
    imported = set(sys.modules) - before
    if any(name.split(".", 1)[0] in {"pydantic", "cryptography"} for name in imported):
        raise LauncherTrustError("outer harness support imported a site dependency")
    if any(
        not trusted_origin(value)
        for name, value in sys.modules.items()
        if name in {"tools", "tools.ai_review"} or name.startswith("tools.ai_review.")
    ):
        raise LauncherTrustError("verified harness module escaped its approved archive")
    return module


class LauncherTrustError(RuntimeError):
    """Raised when the launcher was not started from its approved host installation."""


FD_TOKENS = {
    "@task-fd": "task",
    "@dependency-lock-fd": "dependency_lock",
    "@schema-bundle-fd": "schema_bundle",
    "@coordinator-public-key-fd": "coordinator_public_key",
    "@broker-egress-policy-fd": "broker_egress_policy",
    "@openai-pricing-policy-fd": "openai_pricing_policy",
    "@manifest-fd": "manifest",
}

VALUE_TOKENS = {
    "@runtime-manifest-sha256": "manifest_sha256",
    "@coordinator-image-digest": "coordinator_image_digest",
    "@offline-runner-image-digest": "offline_runner_image_digest",
    "@broker-image-digest": "broker_image_digest",
    "@broker-gateway-image-digest": "broker_gateway_image_digest",
    "@broker-allowlist-policy-sha256": "broker_egress_policy.sha256",
    "@broker-pricing-policy-sha256": "openai_pricing_policy.sha256",
    "@broker-packet-reservation-limit": "broker_packet_reservation_limit",
    "@broker-packet-cost-limit-microusd": "broker_packet_cost_limit_microusd",
}

EMPTY_ARTIFACT_SET_SHA256 = "37517e5f3dc66819f61f5a7bb8ace1921282415f10551d2defa5c3eb0985b570"


def _inside_git_checkout(path: Path) -> bool:
    return any(
        (ancestor / ".git").exists() or (ancestor / ".git").is_symlink()
        for ancestor in path.parents
    )


def _assert_root_owned_path(path: Path, *, label: str) -> Path:
    absolute = Path(os.path.abspath(path))
    current = Path(absolute.anchor)
    try:
        for part in absolute.parts[1:]:
            current /= part
            metadata = os.lstat(current)
            if stat.S_ISLNK(metadata.st_mode):
                raise LauncherTrustError(f"{label} path must not contain symlinks")
            if metadata.st_uid != 0 or stat.S_IMODE(metadata.st_mode) & 0o022:
                raise LauncherTrustError(
                    f"{label} and every parent must be root-owned and candidate-inaccessible"
                )
        metadata = os.lstat(absolute)
    except OSError as exc:
        raise LauncherTrustError(f"{label} bootstrap path could not be inspected") from exc
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise LauncherTrustError(f"{label} must be a non-hardlinked regular file")
    return absolute


def _assert_root_owned_import_path(path: Path, *, label: str) -> Path:
    """Validate a hermetic prefix/sys.path entry without requiring an existing zip file."""

    absolute = Path(os.path.abspath(path))
    target = absolute if absolute.exists() else absolute.parent
    current = Path(target.anchor)
    try:
        for part in target.parts[1:]:
            current /= part
            metadata = os.lstat(current)
            if (
                stat.S_ISLNK(metadata.st_mode)
                or metadata.st_uid != 0
                or stat.S_IMODE(metadata.st_mode) & 0o022
            ):
                raise LauncherTrustError(
                    f"{label} must remain inside a root-owned non-writable path"
                )
    except OSError as exc:
        raise LauncherTrustError(f"{label} could not be inspected") from exc
    if not absolute.exists() and absolute.suffix != ".zip":
        raise LauncherTrustError(f"{label} contains an unavailable import directory")
    return absolute


def _assert_hermetic_python() -> None:
    if (
        not sys.flags.isolated
        or not sys.flags.no_site
        or not sys.flags.ignore_environment
        or not sys.flags.no_user_site
        or not getattr(sys.flags, "safe_path", False)
    ):
        raise LauncherTrustError(
            "production launcher requires isolated Python (-I) and no-site (-S)"
        )
    if "site" in sys.modules:
        raise LauncherTrustError(
            "production launcher must start before the site module is imported"
        )
    prefixes = {
        _assert_root_owned_import_path(Path(value), label="bootstrap Python prefix")
        for value in (sys.prefix, sys.base_prefix, sys.exec_prefix, sys.base_exec_prefix)
    }
    for raw in sys.path:
        if not isinstance(raw, str) or not raw or "site-packages" in raw or "dist-packages" in raw:
            raise LauncherTrustError("bootstrap sys.path contains a non-hermetic entry")
        path = _assert_root_owned_import_path(Path(raw), label="bootstrap sys.path entry")
        if not any(path == prefix or path.is_relative_to(prefix) for prefix in prefixes):
            raise LauncherTrustError("bootstrap sys.path escapes the approved Python prefix")


def _assert_root_owned_bootstrap(preflight_path: Path) -> Path:
    _assert_hermetic_python()
    checked: list[Path] = []
    for label, raw_path in (
        ("bootstrap Python", Path(sys.executable)),
        ("launcher", Path(__file__)),
        ("preflight module", preflight_path),
    ):
        path = _assert_root_owned_path(raw_path, label=label)
        if _inside_git_checkout(path):
            raise LauncherTrustError("production launcher must be installed outside a Git checkout")
        checked.append(path)
    if not stat.S_IMODE(os.lstat(checked[0]).st_mode) & 0o111:
        raise LauncherTrustError("bootstrap Python must be executable")
    return checked[2]


def _assert_bootstrap_matches_preflight(evidence: Any) -> None:
    """Bind the already-running interpreter to the manifest-pinned Python inode."""

    expected = evidence.python
    try:
        actual_path = Path(sys.executable).resolve(strict=True)
        expected_path = Path(expected.path).resolve(strict=True)
        metadata = os.stat(actual_path, follow_symlinks=False)
    except OSError as exc:
        raise LauncherTrustError("bootstrap Python identity could not be inspected") from exc
    if actual_path != expected_path or (metadata.st_dev, metadata.st_ino) != (
        expected.device,
        expected.inode,
    ):
        raise LauncherTrustError("bootstrap Python is not the runtime-manifest Python asset")
    digest = hashlib.sha256()
    total = 0
    try:
        with actual_path.open("rb") as stream:
            while chunk := stream.read(1024 * 1024):
                total += len(chunk)
                if total > 128 * 1024 * 1024:
                    raise LauncherTrustError("bootstrap Python exceeds its byte limit")
                digest.update(chunk)
    except OSError as exc:
        raise LauncherTrustError("bootstrap Python could not be rehashed") from exc
    if total != expected.size or not hmac.compare_digest(digest.hexdigest(), expected.sha256):
        raise LauncherTrustError("bootstrap Python changed after runtime preflight")


def expand_fd_tokens(evidence: Any, arguments: tuple[str, ...]) -> tuple[str, ...]:
    """Replace only exact coordinator tokens; substrings remain inert arguments."""

    def bound_value(attribute: str) -> str:
        value: object = evidence
        for part in attribute.split("."):
            value = getattr(value, part)
        if isinstance(value, bool) or not isinstance(value, (str, int)):
            raise LauncherTrustError("launcher value token has an invalid trusted type")
        return str(value)

    return tuple(
        evidence.fd_path(FD_TOKENS[value])
        if value in FD_TOKENS
        else bound_value(VALUE_TOKENS[value])
        if value in VALUE_TOKENS
        else value
        for value in arguments
    )


def validate_production_phase_launch(
    request: Any,
    harness_arguments: tuple[str, ...],
    *,
    candidate_repo: Path | None,
    container_phase_request: str,
    expected_phase_request_file_sha256: str,
) -> bool:
    """Return the one approved candidate-mount decision without importing before preflight."""

    phase = request.get("phase") if isinstance(request, dict) else getattr(request, "phase", None)
    if phase not in {
        "snapshot",
        "red-snapshot",
        "offline",
        "review-packet",
        "broker",
        "sign",
        "attested-judge",
    }:
        raise LauncherTrustError("production phase request type is invalid")
    if not harness_arguments or harness_arguments[0] != phase:
        raise LauncherTrustError("coordinator command does not match the production phase request")

    required = (
        ("--task", "@task-container"),
        ("--artifact-root", "@artifact-root-container"),
        ("--expected-task-sha256", "@task-sha256"),
        ("--phase-request", container_phase_request),
        (
            "--expected-phase-request-file-sha256",
            expected_phase_request_file_sha256,
        ),
    )
    tail = (
        ("--phase-payload", None),
        ("--expected-phase-payload-sha256", None),
        ("--runtime-root", "/runtime"),
        ("--runtime-manifest", "@runtime-manifest-container"),
        ("--expected-runtime-manifest-sha256", "@runtime-manifest-sha256"),
        ("--expected-coordinator-image-digest", "@coordinator-image-digest"),
    )
    if any("=" in value for value in harness_arguments[1:]):
        raise LauncherTrustError("coordinator command forbids assigned option syntax")
    expected_index = 1
    parsed: dict[str, list[str]] = {}
    for name, fixed in required:
        if harness_arguments[expected_index : expected_index + 1] != (name,):
            raise LauncherTrustError(f"coordinator command requires exactly one {name}")
        if expected_index + 1 >= len(harness_arguments):
            raise LauncherTrustError(f"coordinator command requires exactly one {name}")
        value = harness_arguments[expected_index + 1]
        if fixed is not None and value != fixed:
            raise LauncherTrustError(f"coordinator command has a non-canonical {name}")
        parsed[name] = [value]
        expected_index += 2
    history: list[str] = []
    while harness_arguments[expected_index : expected_index + 1] == ("--phase-history",):
        if expected_index + 1 >= len(harness_arguments):
            raise LauncherTrustError("coordinator command has an incomplete phase history")
        history.append(harness_arguments[expected_index + 1])
        expected_index += 2
    sequence = request.get("sequence") if isinstance(request, dict) else request.sequence
    if len(history) != sequence - 1:
        raise LauncherTrustError("coordinator command phase history count is invalid")
    if len(history) != len(set(history)) or any(
        not value.startswith("/artifacts/") for value in history
    ):
        raise LauncherTrustError("coordinator command phase history is invalid")
    parsed["--phase-history"] = history
    for name, fixed in tail:
        if harness_arguments[expected_index : expected_index + 1] != (name,):
            raise LauncherTrustError(f"coordinator command requires exactly one {name}")
        if expected_index + 1 >= len(harness_arguments):
            raise LauncherTrustError(f"coordinator command requires exactly one {name}")
        value = harness_arguments[expected_index + 1]
        if fixed is not None and value != fixed:
            raise LauncherTrustError(f"coordinator command has a non-canonical {name}")
        parsed[name] = [value]
        expected_index += 2
    if expected_index != len(harness_arguments):
        raise LauncherTrustError("coordinator command contains unknown or duplicate arguments")
    if not parsed["--phase-payload"][0].startswith("/artifacts/"):
        raise LauncherTrustError("coordinator phase payload path is invalid")
    if re.fullmatch(r"[0-9a-f]{64}", parsed["--expected-phase-payload-sha256"][0]) is None:
        raise LauncherTrustError("coordinator phase payload digest is invalid")

    if parsed["--phase-request"][0] != container_phase_request:
        raise LauncherTrustError("coordinator phase request path differs from the outer binding")
    if parsed["--expected-phase-request-file-sha256"][0] != expected_phase_request_file_sha256:
        raise LauncherTrustError("coordinator phase request digest differs from the outer binding")
    mount_candidate = phase == "snapshot"
    if mount_candidate and candidate_repo is None:
        raise LauncherTrustError("snapshot phase requires the protected candidate tree")
    if not mount_candidate and candidate_repo is not None:
        raise LauncherTrustError("candidate path is forbidden after the snapshot phase")
    return mount_candidate


def _validate_phase_request_stdlib(raw: bytes) -> dict[str, Any]:
    """Apply the minimal outer contract without importing any site package."""

    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                raise LauncherTrustError("production phase request has a duplicate key")
            value[key] = item
        return value

    try:
        request = json.loads(
            raw.decode("utf-8", errors="strict"), object_pairs_hook=reject_duplicates
        )
    except LauncherTrustError:
        raise
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise LauncherTrustError("production phase request is invalid JSON") from exc
    fields = {
        "schema_version",
        "workflow_id",
        "phase",
        "sequence",
        "previous_phase_sha256",
        "task_sha256",
        "runtime_manifest_sha256",
        "coordinator_key_id",
        "coordinator_public_key_sha256",
        "candidate_sha256",
        "candidate_snapshot_sha256",
        "review_packet_sha256",
        "input_artifacts_sha256",
        "request_sha256",
    }
    phases = (
        "snapshot",
        "red-snapshot",
        "offline",
        "review-packet",
        "broker",
        "sign",
        "attested-judge",
    )
    if not isinstance(request, dict) or set(request) != fields:
        raise LauncherTrustError("production phase request has missing or unknown fields")
    phase = request.get("phase")
    sequence = request.get("sequence")
    if (
        request.get("schema_version") != "1.0"
        or phase not in phases
        or isinstance(sequence, bool)
        or not isinstance(sequence, int)
        or sequence != phases.index(phase) + 1
    ):
        raise LauncherTrustError("production phase request order is invalid")
    required_sha = fields - {
        "schema_version",
        "phase",
        "sequence",
        "previous_phase_sha256",
        "candidate_snapshot_sha256",
        "review_packet_sha256",
    }
    optional_sha = (
        request["previous_phase_sha256"],
        request["candidate_snapshot_sha256"],
        request["review_packet_sha256"],
    )
    sha_pattern = re.compile(r"^[0-9a-f]{64}$")
    if any(
        not isinstance(request[name], str) or sha_pattern.fullmatch(request[name]) is None
        for name in required_sha
    ) or any(
        value is not None and (not isinstance(value, str) or sha_pattern.fullmatch(value) is None)
        for value in optional_sha
    ):
        raise LauncherTrustError("production phase request contains an invalid SHA-256")
    if (request["previous_phase_sha256"] is None) != (sequence == 1):
        raise LauncherTrustError("production phase request previous digest is invalid")
    if (request["candidate_snapshot_sha256"] is None) != (sequence == 1):
        raise LauncherTrustError("production phase request snapshot binding is invalid")
    if sequence == 1 and request["input_artifacts_sha256"] != EMPTY_ARTIFACT_SET_SHA256:
        raise LauncherTrustError(
            "production initial phase request requires the canonical empty artifact set"
        )
    packet_required = sequence >= phases.index("broker") + 1
    if (request["review_packet_sha256"] is not None) != packet_required:
        raise LauncherTrustError("production phase request packet binding is invalid")
    payload = {key: value for key, value in request.items() if key != "request_sha256"}
    canonical = (
        json.dumps(
            payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")
    measured = hashlib.sha256(b"amazon-explorer-phase-request-v1\0" + canonical).hexdigest()
    if not hmac.compare_digest(measured, request["request_sha256"]):
        raise LauncherTrustError("production phase request canonical digest is invalid")
    return request


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Launch a preflighted AI review zipapp")
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--expected-manifest-sha256", required=True)
    parser.add_argument("--candidate-uid", type=int, required=True)
    parser.add_argument("--diagnostic-source", action="store_true")
    parser.add_argument("--workflow", action="store_true")
    parser.add_argument("--deployment-check", action="store_true")
    parser.add_argument("--coordinator-image")
    parser.add_argument("--offline-image")
    parser.add_argument("--broker-image")
    parser.add_argument("--broker-gateway-image")
    parser.add_argument("--artifact-root", type=Path)
    parser.add_argument("--candidate-repo", type=Path)
    parser.add_argument("--phase-request", type=Path)
    parser.add_argument("--expected-phase-request-file-sha256")
    parser.add_argument("--phase-output-root", type=Path)
    parser.add_argument("--signing-key", type=Path)
    parser.add_argument("--broker-ledger", type=Path)
    parser.add_argument("--attestation-nonce-ledger-root", type=Path)
    parser.add_argument("--reviewer-credential-fd", type=int)
    parser.add_argument("--adversary-credential-fd", type=int)
    parser.add_argument("--timeout-seconds", type=int, default=300)
    parser.add_argument("harness_arguments", nargs=argparse.REMAINDER)
    return parser


def _read_credential_fd(descriptor: int, *, label: str) -> str:
    """Read one inherited credential without accepting it in argv or environment."""

    if type(descriptor) is not int or descriptor < 3:
        raise LauncherTrustError(f"{label} credential requires an inherited file descriptor")
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > 16 * 1024:
            raise LauncherTrustError(f"{label} credential descriptor is invalid")
        raw = os.pread(descriptor, 16 * 1024 + 1, 0)
    except OSError as exc:
        raise LauncherTrustError(f"{label} credential descriptor is unavailable") from exc
    if (
        not raw
        or len(raw) > 16 * 1024
        or metadata.st_size != len(raw)
        or stat.S_IMODE(metadata.st_mode) & 0o077
    ):
        raise LauncherTrustError(f"{label} credential descriptor is not private and bounded")
    try:
        value = raw.decode("ascii", errors="strict")
    except UnicodeError as exc:
        raise LauncherTrustError(f"{label} credential is not canonical ASCII") from exc
    value = value.removesuffix("\n")
    if not value or len(value) > 16 * 1024 or any(not 33 <= ord(item) <= 126 for item in value):
        raise LauncherTrustError(f"{label} credential is empty or contains unsafe bytes")
    return value


def _assert_deployment_assets_root_owned(evidence: Any) -> None:
    assets = (
        ("runtime manifest", evidence.manifest_path),
        ("runtime Python", evidence.python.path),
        ("harness", evidence.harness.path),
        ("task", evidence.task.path),
        ("dependency lock", evidence.dependency_lock.path),
        ("schema bundle", evidence.schema_bundle.path),
        ("coordinator public key", evidence.coordinator_public_key.path),
        ("broker egress policy", evidence.broker_egress_policy.path),
        ("OpenAI pricing policy", evidence.openai_pricing_policy.path),
    )
    for label, raw_path in assets:
        path = _assert_root_owned_path(Path(raw_path), label=f"deployment {label}")
        if _inside_git_checkout(path):
            raise LauncherTrustError(
                "deployment release assets must be installed outside a Git checkout"
            )


def _read_verified_task_fd_stdlib(evidence: Any) -> bytes:
    try:
        raw_path = evidence.fd_path("task")
    except Exception as exc:
        raise LauncherTrustError("deployment task descriptor is unavailable") from exc
    match = re.fullmatch(r"/proc/self/fd/(0|[1-9][0-9]*)", raw_path)
    if match is None or not hasattr(os, "pread"):
        raise LauncherTrustError("deployment task requires a verified POSIX descriptor")
    descriptor = int(match.group(1))
    stable_fields = (
        "st_dev",
        "st_ino",
        "st_mode",
        "st_uid",
        "st_gid",
        "st_size",
        "st_mtime_ns",
        "st_ctime_ns",
        "st_nlink",
    )
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or not 1 <= before.st_size <= 2 * 1024 * 1024
        ):
            raise LauncherTrustError("deployment task descriptor is not a bounded regular file")
        chunks: list[bytes] = []
        offset = 0
        digest = hashlib.sha256()
        while offset < before.st_size:
            chunk = os.pread(descriptor, min(1024 * 1024, before.st_size - offset), offset)
            if not chunk:
                raise LauncherTrustError("deployment task changed during descriptor read")
            chunks.append(chunk)
            digest.update(chunk)
            offset += len(chunk)
        after = os.fstat(descriptor)
    except LauncherTrustError:
        raise
    except OSError as exc:
        raise LauncherTrustError("deployment task descriptor could not be read") from exc
    if any(getattr(before, field) != getattr(after, field) for field in stable_fields):
        raise LauncherTrustError("deployment task changed during descriptor read")
    if not hmac.compare_digest(digest.hexdigest(), evidence.task.sha256):
        raise LauncherTrustError("deployment task digest differs from preflight")
    return b"".join(chunks)


def _assert_deployment_task_v2(evidence: Any) -> None:
    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise LauncherTrustError("deployment TaskSpec contains a duplicate key")
            result[key] = value
        return result

    def reject_constant(_value: str) -> None:
        raise LauncherTrustError("deployment TaskSpec contains a non-JSON number")

    raw = _read_verified_task_fd_stdlib(evidence)
    try:
        task = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=reject_duplicates,
            parse_constant=reject_constant,
        )
    except LauncherTrustError:
        raise
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise LauncherTrustError("deployment TaskSpec is invalid JSON") from exc
    if not isinstance(task, dict) or task.get("schema_version") != "2.0":
        raise LauncherTrustError("deployment readiness requires TaskSpec v2")
    trusted_harness_sha256 = task.get("trusted_harness_sha256")
    if (
        not isinstance(trusted_harness_sha256, str)
        or re.fullmatch(r"[0-9a-f]{64}", trusted_harness_sha256) is None
        or not hmac.compare_digest(trusted_harness_sha256, evidence.harness.sha256)
    ):
        raise LauncherTrustError("deployment TaskSpec does not bind the verified harness")


def _run_deployment_check(args: argparse.Namespace, evidence: Any) -> int:
    if args.workflow or args.diagnostic_source or not args.deployment_check:
        raise LauncherTrustError("deployment check must use its exclusive installed mode")
    forbidden = {
        "initial artifact root": args.artifact_root,
        "candidate repository": args.candidate_repo,
        "phase request": args.phase_request,
        "phase request file digest": args.expected_phase_request_file_sha256,
        "phase output root": args.phase_output_root,
        "signing key": args.signing_key,
        "broker ledger": args.broker_ledger,
        "attestation nonce ledger": args.attestation_nonce_ledger_root,
        "reviewer credential": args.reviewer_credential_fd,
        "adversary credential": args.adversary_credential_fd,
    }
    supplied = [label for label, value in forbidden.items() if value is not None]
    if supplied:
        raise LauncherTrustError("deployment check forbids workflow inputs: " + ", ".join(supplied))
    images = {
        "broker": args.broker_image,
        "broker-gateway": args.broker_gateway_image,
        "coordinator": args.coordinator_image,
        "offline-runner": args.offline_image,
    }
    if any(not isinstance(value, str) or not value for value in images.values()):
        raise LauncherTrustError("deployment check requires all four manifest-pinned images")
    launcher_uid = os.geteuid()
    candidate_uid = evidence.candidate_uid
    if (
        launcher_uid == 0
        or isinstance(candidate_uid, bool)
        or not isinstance(candidate_uid, int)
        or candidate_uid <= 0
        or candidate_uid == launcher_uid
    ):
        raise LauncherTrustError(
            "deployment check requires separate non-root launcher and candidate UIDs"
        )

    _assert_deployment_assets_root_owned(evidence)
    _assert_deployment_task_v2(evidence)
    coordinator_module = _load_verified_harness_module(
        evidence,
        "tools.ai_review.coordinator_launcher",
    )
    workflow_module = _load_verified_harness_module(
        evidence,
        "tools.ai_review.outer_workflow_runtime",
    )
    deployment_module = _load_verified_harness_module(
        evidence,
        "tools.ai_review.deployment_check",
    )
    phase_order = (
        "snapshot",
        "red-snapshot",
        "offline",
        "review-packet",
        "broker",
        "sign",
        "attested-judge",
    )
    if (
        tuple(getattr(workflow_module, "PHASE_ORDER", ())) != phase_order
        or tuple(getattr(workflow_module, "IMPLEMENTED_COORDINATOR_WORKFLOW_PHASES", ()))
        != phase_order
    ):
        raise LauncherTrustError(
            "deployment check is disabled until all seven coordinator handlers are pinned"
        )

    approved_digests = {
        "broker": evidence.broker_image_digest,
        "broker-gateway": evidence.broker_gateway_image_digest,
        "coordinator": evidence.coordinator_image_digest,
        "offline-runner": evidence.offline_runner_image_digest,
    }
    host = deployment_module.validate_launcher_environment(
        launcher_uid=launcher_uid,
        candidate_uid=candidate_uid,
    )
    backend = deployment_module.detect_deployment_backend(
        coordinator_module=coordinator_module,
        candidate_uid=candidate_uid,
        launcher_uid=launcher_uid,
        host=host,
        runner=coordinator_module._run_bounded,
    )
    raw = deployment_module.run_deployment_check(
        manifest_sha256=evidence.manifest_sha256,
        backend=backend,
        images=images,
        approved_digests=approved_digests,
        runner=coordinator_module._run_bounded,
    )
    post_host = deployment_module.validate_launcher_environment(
        launcher_uid=launcher_uid,
        candidate_uid=candidate_uid,
    )
    post_backend = deployment_module.detect_deployment_backend(
        coordinator_module=coordinator_module,
        candidate_uid=candidate_uid,
        launcher_uid=launcher_uid,
        host=post_host,
        runner=coordinator_module._run_bounded,
    )
    before_backend_sha256 = deployment_module.canonical_backend_evidence_sha256(backend)
    after_backend_sha256 = deployment_module.canonical_backend_evidence_sha256(post_backend)
    if (
        host != post_host
        or backend != post_backend
        or not hmac.compare_digest(
            before_backend_sha256,
            after_backend_sha256,
        )
    ):
        raise LauncherTrustError("deployment container runtime changed during validation")
    deployment_module.validate_deployment_check_bytes(
        raw,
        expected_manifest_sha256=evidence.manifest_sha256,
        expected_backend_evidence_sha256=after_backend_sha256,
        expected_image_digests=approved_digests,
    )
    sys.stdout.buffer.write(raw)
    sys.stdout.buffer.flush()
    return 0


def _run_production_workflow(args: argparse.Namespace, evidence: Any) -> int:
    required = {
        "coordinator image": args.coordinator_image,
        "offline image": args.offline_image,
        "broker image": args.broker_image,
        "broker gateway image": args.broker_gateway_image,
        "initial artifact root": args.artifact_root,
        "initial phase request": args.phase_request,
        "workflow output root": args.phase_output_root,
        "candidate repository": args.candidate_repo,
        "private signing key": args.signing_key,
        "broker ledger": args.broker_ledger,
        "attestation nonce ledger root": args.attestation_nonce_ledger_root,
        "reviewer credential fd": args.reviewer_credential_fd,
        "adversary credential fd": args.adversary_credential_fd,
    }
    missing = [label for label, value in required.items() if value is None]
    if missing:
        raise LauncherTrustError("production workflow lacks " + ", ".join(missing))
    if args.reviewer_credential_fd == args.adversary_credential_fd:
        raise LauncherTrustError("broker role credentials require distinct inherited descriptors")
    coordinator_module = _load_verified_harness_module(
        evidence,
        "tools.ai_review.coordinator_launcher",
    )
    workflow_module = _load_verified_harness_module(
        evidence,
        "tools.ai_review.outer_workflow_runtime",
    )
    if tuple(getattr(workflow_module, "IMPLEMENTED_COORDINATOR_WORKFLOW_PHASES", ())) != tuple(
        workflow_module.PHASE_ORDER
    ):
        raise LauncherTrustError(
            "production workflow is disabled until all seven coordinator handlers are pinned"
        )
    offline_module = _load_verified_harness_module(
        evidence,
        "tools.ai_review.offline_outer_executor",
    )
    broker_module = _load_verified_harness_module(
        evidence,
        "tools.ai_review.broker_outer_executor",
    )
    backend = coordinator_module.detect_container_backend(candidate_uid=evidence.candidate_uid)
    coordinator_module._validate_backend(backend, candidate_uid=evidence.candidate_uid)
    broker_runtime_binding = broker_module.measure_broker_outer_runtime(
        backend.executable,
        candidate_uid=evidence.candidate_uid,
    )
    credentials = {
        "reviewer": _read_credential_fd(args.reviewer_credential_fd, label="reviewer"),
        "adversary": _read_credential_fd(args.adversary_credential_fd, label="adversary"),
    }
    ledger_identity = broker_module.prepare_broker_outer_ledger(
        args.broker_ledger,
        candidate_uid=evidence.candidate_uid,
    )
    images = workflow_module.WorkflowImages(
        coordinator=args.coordinator_image,
        coordinator_digest=evidence.coordinator_image_digest,
        offline=args.offline_image,
        offline_digest=evidence.offline_runner_image_digest,
        broker=args.broker_image,
        broker_digest=evidence.broker_image_digest,
        broker_gateway=args.broker_gateway_image,
        broker_gateway_digest=evidence.broker_gateway_image_digest,
    )

    def coordinator_execute(call: Any) -> bytes:
        result = coordinator_module.execute_coordinator(
            evidence=evidence,
            image=args.coordinator_image,
            artifact_root=call.artifact_root,
            candidate_repo=call.candidate_repo,
            command=call.command,
            container_name=f"ai-review-coordinator-{secrets.token_hex(12)}",
            timeout_seconds=args.timeout_seconds,
            max_output_bytes=10_000_000,
            mount_candidate=call.candidate_repo is not None,
            phase_output_root=call.output_root,
            signing_key=call.signing_key,
            nonce_ledger_root=call.nonce_ledger_root,
            snapshot_artifact_root=call.snapshot_artifact_root,
        )
        return result.stdout

    completed = workflow_module.run_production_workflow(
        args.phase_request,
        initial_artifact_root=args.artifact_root,
        output_root=args.phase_output_root,
        candidate_repo=args.candidate_repo,
        signing_key=args.signing_key,
        nonce_ledger_root=args.attestation_nonce_ledger_root,
        candidate_uid=evidence.candidate_uid,
        images=images,
        broker_ledger_identity_sha256=ledger_identity,
        broker_runtime_binding=broker_runtime_binding,
        coordinator_execute=coordinator_execute,
        offline_execute=lambda payload, artifact_root: (
            offline_module.execute_prepared_offline_outer(
                payload,
                artifact_root=artifact_root,
                candidate_uid=evidence.candidate_uid,
            )
        ),
        broker_execute=lambda payload: broker_module.execute_prepared_broker_outer(
            payload,
            credentials=credentials,
            ledger_path=args.broker_ledger,
            runtime_executable=backend.executable,
        ),
    )
    sys.stdout.buffer.write(
        (
            json.dumps(
                {
                    "final_phase_sha256": completed.transitions[-1].result["phase_sha256"],
                    "human_approval_required": True,
                    "phase_count": len(completed.transitions),
                    "status": "complete",
                },
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        ).encode("utf-8")
    )
    sys.stdout.buffer.flush()
    return 0


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    harness_arguments = tuple(args.harness_arguments)
    if harness_arguments[:1] == ("--",):
        harness_arguments = harness_arguments[1:]
    if args.deployment_check and (
        args.workflow or args.diagnostic_source or bool(harness_arguments)
    ):
        print(
            "launcher error: deployment-check mode is exclusive",
            file=sys.stderr,
        )
        return 2
    if args.workflow and harness_arguments:
        print(
            "launcher error: workflow mode forbids caller-supplied harness arguments",
            file=sys.stderr,
        )
        return 2
    if not args.workflow and not args.deployment_check and not harness_arguments:
        print("launcher error: harness arguments are required", file=sys.stderr)
        return 2
    try:
        preflight_path = _sibling_preflight_path()
        if not args.diagnostic_source:
            preflight_path = _assert_root_owned_bootstrap(preflight_path)
        preflight_module = _load_sibling_preflight(preflight_path)
        evidence = preflight_module.preflight_runtime(
            manifest_path=args.manifest,
            expected_manifest_sha256=args.expected_manifest_sha256,
            candidate_uid=args.candidate_uid,
        )
        try:
            if not args.diagnostic_source:
                _assert_bootstrap_matches_preflight(evidence)
            if args.deployment_check:
                try:
                    return _run_deployment_check(args, evidence)
                except LauncherTrustError:
                    raise
                except Exception as exc:
                    raise LauncherTrustError("deployment check stopped fail-closed") from exc
            if args.workflow:
                if args.diagnostic_source:
                    raise LauncherTrustError("workflow mode is unavailable from a source checkout")
                try:
                    return _run_production_workflow(args, evidence)
                except LauncherTrustError:
                    raise
                except Exception as exc:
                    raise LauncherTrustError("production workflow stopped fail-closed") from exc
            expanded = expand_fd_tokens(evidence, harness_arguments)
            if args.diagnostic_source:
                print(
                    json.dumps(
                        {
                            "argv": list(
                                preflight_module.build_isolated_zipapp_argv(evidence, expanded)
                            ),
                            "diagnostic_only": True,
                        },
                        sort_keys=True,
                        separators=(",", ":"),
                    )
                )
                return 0
            if args.coordinator_image is None or args.artifact_root is None:
                raise LauncherTrustError("production coordinator requires image and artifact root")
            if args.phase_request is None or args.expected_phase_request_file_sha256 is None:
                raise LauncherTrustError("production coordinator requires a phase request binding")
            try:
                artifact_root = args.artifact_root.resolve(strict=True)
                phase_path = args.phase_request.resolve(strict=True)
            except OSError as exc:
                raise LauncherTrustError("production phase request path is unavailable") from exc
            if not phase_path.is_relative_to(artifact_root):
                raise LauncherTrustError("production phase request must be inside artifact root")
            _phase_file, raw_phase_request = preflight_module.read_protected_file(
                phase_path,
                candidate_uid=args.candidate_uid,
                label="production phase request",
                expected_sha256=args.expected_phase_request_file_sha256,
                max_bytes=128 * 1024,
            )
            request = _validate_phase_request_stdlib(raw_phase_request)
            if (
                request["task_sha256"] != evidence.task.sha256
                or request["runtime_manifest_sha256"] != evidence.manifest_sha256
                or request["coordinator_public_key_sha256"]
                != evidence.coordinator_public_key.sha256
            ):
                raise LauncherTrustError("production phase request differs from preflight")
            mount_candidate = validate_production_phase_launch(
                request,
                harness_arguments,
                candidate_repo=args.candidate_repo,
                container_phase_request=(
                    "/artifacts/" + phase_path.relative_to(artifact_root).as_posix()
                ),
                expected_phase_request_file_sha256=(args.expected_phase_request_file_sha256),
            )
            if args.phase_output_root is None:
                raise LauncherTrustError("production phase requires a new exclusive output root")
            if (args.signing_key is not None) != (request["phase"] == "sign"):
                raise LauncherTrustError("private signing key is required only for the sign phase")
            coordinator_module = _load_verified_harness_module(
                evidence,
                "tools.ai_review.coordinator_launcher",
            )
            result = coordinator_module.execute_coordinator(
                evidence=evidence,
                image=args.coordinator_image,
                artifact_root=args.artifact_root,
                candidate_repo=args.candidate_repo,
                command=harness_arguments,
                container_name=f"ai-review-coordinator-{secrets.token_hex(12)}",
                timeout_seconds=args.timeout_seconds,
                mount_candidate=mount_candidate,
                phase_output_root=args.phase_output_root,
                signing_key=args.signing_key,
            )
            sys.stdout.buffer.write(result.stdout)
            sys.stdout.buffer.flush()
            return 0
        finally:
            evidence.close()
    except LauncherTrustError as exc:
        print(f"launcher error: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:
        if "coordinator_module" in locals() and isinstance(
            exc,
            coordinator_module.CoordinatorLauncherError,
        ):
            print(f"launcher error: {exc}", file=sys.stderr)
            return 2
        if "preflight_module" not in locals() or not isinstance(
            exc, preflight_module.PreflightError
        ):
            raise
        print(f"launcher error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
