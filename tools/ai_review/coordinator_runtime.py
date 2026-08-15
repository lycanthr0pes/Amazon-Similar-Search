"""Defense-in-depth verification performed inside the pinned coordinator image."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import stat
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from tools.ai_review.egress_policy import EgressPolicyError
from tools.ai_review.egress_policy import validate_broker_egress_policy
from tools.ai_review.pricing_policy import ABSOLUTE_PACKET_COST_LIMIT_MICROUSD
from tools.ai_review.pricing_policy import maximum_packet_cost_microusd
from tools.ai_review.pricing_policy import validate_openai_pricing_policy


SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
IMAGE_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
MAX_BROKER_PACKET_RESERVATION_TOKENS = 1_088_000
MOUNTED_ASSETS = {
    "harness": "harness.pyz",
    "task": "task.json",
    "dependency_lock": "uv.lock",
    "schema_bundle": "schemas.json",
    "coordinator_public_key": "coordinator-public-key.pem",
    "broker_egress_policy": "broker-egress-policy.json",
    "openai_pricing_policy": "openai-pricing-policy.json",
}


class CoordinatorRuntimeError(RuntimeError):
    """Raised when mounted runtime bytes differ from external preflight evidence."""


@dataclass(frozen=True)
class CoordinatorRuntimeEvidence:
    manifest_sha256: str
    coordinator_image_digest: str
    harness_sha256: str
    task_sha256: str
    dependency_lock_sha256: str
    schema_bundle_sha256: str
    coordinator_public_key_sha256: str
    offline_runner_image_digest: str
    broker_image_digest: str
    broker_gateway_image_digest: str
    broker_allowlist_policy_sha256: str
    broker_packet_reservation_limit: int
    broker_pricing_policy_sha256: str
    broker_packet_cost_limit_microusd: int


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise CoordinatorRuntimeError("runtime manifest contains a duplicate JSON key")
        value[key] = item
    return value


def _read_fixed_file(path: Path, *, max_bytes: int) -> tuple[bytes, os.stat_result]:
    if path.is_symlink():
        raise CoordinatorRuntimeError("coordinator runtime asset must not be a symlink")
    try:
        before = os.lstat(path)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise CoordinatorRuntimeError("coordinator runtime asset must be a regular file")
        if stat.S_IMODE(before.st_mode) & 0o222:
            raise CoordinatorRuntimeError("coordinator runtime asset must be read-only")
        if before.st_size > max_bytes:
            raise CoordinatorRuntimeError("coordinator runtime asset exceeds its byte limit")
        with path.open("rb") as handle:
            raw = handle.read(max_bytes + 1)
        after = os.lstat(path)
    except OSError as exc:
        raise CoordinatorRuntimeError("coordinator runtime asset could not be read") from exc
    stable_fields = ("st_dev", "st_ino", "st_mode", "st_size", "st_mtime_ns", "st_ctime_ns")
    if len(raw) > max_bytes or any(
        getattr(before, field) != getattr(after, field) for field in stable_fields
    ):
        raise CoordinatorRuntimeError("coordinator runtime asset changed while being read")
    return raw, after


def verify_coordinator_runtime(
    *,
    runtime_root: Path,
    manifest_path: Path,
    expected_manifest_sha256: str,
    expected_coordinator_image_digest: str,
    expected_task_sha256: str,
    isolated: bool | None = None,
) -> CoordinatorRuntimeEvidence:
    """Re-hash every staged input after the pinned image has started."""

    digest_values = (expected_manifest_sha256, expected_task_sha256)
    if any(SHA256_RE.fullmatch(value) is None for value in digest_values):
        raise CoordinatorRuntimeError("coordinator runtime SHA-256 input is invalid")
    if IMAGE_RE.fullmatch(expected_coordinator_image_digest) is None:
        raise CoordinatorRuntimeError("coordinator image digest is invalid")
    if isolated is None:
        isolated = bool(sys.flags.isolated)
    if not isolated:
        raise CoordinatorRuntimeError("coordinator image requires isolated Python (-I)")
    root = runtime_root.resolve(strict=True)
    manifest = manifest_path.resolve(strict=True)
    if root != manifest.parent or manifest.name != "runtime-manifest.json":
        raise CoordinatorRuntimeError("runtime manifest is outside the fixed mounted root")
    root_metadata = os.lstat(root)
    if not stat.S_ISDIR(root_metadata.st_mode) or stat.S_IMODE(root_metadata.st_mode) & 0o022:
        raise CoordinatorRuntimeError("mounted runtime root is writable")

    raw_manifest, _metadata = _read_fixed_file(manifest, max_bytes=64 * 1024)
    manifest_sha256 = hashlib.sha256(raw_manifest).hexdigest()
    if not hmac.compare_digest(manifest_sha256, expected_manifest_sha256):
        raise CoordinatorRuntimeError("runtime manifest SHA-256 does not match external preflight")
    try:
        payload = json.loads(
            raw_manifest.decode("utf-8", errors="strict"),
            object_pairs_hook=_reject_duplicate_keys,
        )
    except CoordinatorRuntimeError:
        raise
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise CoordinatorRuntimeError("runtime manifest is not valid UTF-8 JSON") from exc
    expected_fields = {
        "schema_version",
        "python",
        "harness",
        "task",
        "dependency_lock",
        "schema_bundle",
        "coordinator_public_key",
        "broker_egress_policy",
        "openai_pricing_policy",
        "coordinator_image_digest",
        "offline_runner_image_digest",
        "broker_image_digest",
        "broker_gateway_image_digest",
        "broker_packet_reservation_limit",
        "broker_packet_cost_limit_microusd",
    }
    if not isinstance(payload, dict) or set(payload) != expected_fields:
        raise CoordinatorRuntimeError("runtime manifest contains missing or unknown fields")
    if (
        payload.get("schema_version") != "1.0"
        or payload.get("coordinator_image_digest") != expected_coordinator_image_digest
    ):
        raise CoordinatorRuntimeError("runtime manifest does not approve this coordinator image")
    image_digests = tuple(
        payload.get(name)
        for name in (
            "coordinator_image_digest",
            "offline_runner_image_digest",
            "broker_image_digest",
            "broker_gateway_image_digest",
        )
    )
    if any(
        not isinstance(value, str) or IMAGE_RE.fullmatch(value) is None for value in image_digests
    ):
        raise CoordinatorRuntimeError("runtime manifest image digest is invalid")
    if len(set(image_digests)) != len(image_digests):
        raise CoordinatorRuntimeError("runtime manifest images must be distinct")
    reservation_limit = payload.get("broker_packet_reservation_limit")
    if (
        isinstance(reservation_limit, bool)
        or not isinstance(reservation_limit, int)
        or not 1 <= reservation_limit <= MAX_BROKER_PACKET_RESERVATION_TOKENS
    ):
        raise CoordinatorRuntimeError("runtime manifest broker packet reservation limit is invalid")
    cost_limit = payload.get("broker_packet_cost_limit_microusd")
    if (
        isinstance(cost_limit, bool)
        or not isinstance(cost_limit, int)
        or not 1 <= cost_limit <= ABSOLUTE_PACKET_COST_LIMIT_MICROUSD
    ):
        raise CoordinatorRuntimeError("runtime manifest broker packet cost limit is invalid")
    for name in (
        "python",
        "harness",
        "task",
        "dependency_lock",
        "schema_bundle",
        "coordinator_public_key",
        "broker_egress_policy",
        "openai_pricing_policy",
    ):
        contract = payload.get(name)
        if (
            not isinstance(contract, dict)
            or set(contract) != {"path", "sha256"}
            or not isinstance(contract.get("path"), str)
            or not Path(contract["path"]).is_absolute()
            or not isinstance(contract.get("sha256"), str)
            or SHA256_RE.fullmatch(contract["sha256"]) is None
        ):
            raise CoordinatorRuntimeError("runtime manifest asset contract is invalid")

    measured: dict[str, str] = {}
    for name, filename in MOUNTED_ASSETS.items():
        contract = payload.get(name)
        assert isinstance(contract, dict)
        raw, _asset_metadata = _read_fixed_file(root / filename, max_bytes=32 * 1024 * 1024)
        actual = hashlib.sha256(raw).hexdigest()
        if not hmac.compare_digest(actual, contract["sha256"]):
            raise CoordinatorRuntimeError("mounted runtime asset differs from external preflight")
        measured[name] = actual
    if not hmac.compare_digest(measured["task"], expected_task_sha256):
        raise CoordinatorRuntimeError("mounted task differs from the coordinator-fixed task")
    try:
        policy_raw, _policy_metadata = _read_fixed_file(
            root / MOUNTED_ASSETS["broker_egress_policy"],
            max_bytes=64 * 1024,
        )
        policy_sha256 = validate_broker_egress_policy(policy_raw)
    except EgressPolicyError as exc:
        raise CoordinatorRuntimeError(str(exc)) from exc
    if not hmac.compare_digest(policy_sha256, measured["broker_egress_policy"]):
        raise CoordinatorRuntimeError("mounted broker egress policy digest is inconsistent")
    try:
        pricing_raw, _pricing_metadata = _read_fixed_file(
            root / MOUNTED_ASSETS["openai_pricing_policy"],
            max_bytes=64 * 1024,
        )
        pricing = validate_openai_pricing_policy(pricing_raw)
        maximum_cost = maximum_packet_cost_microusd(
            pricing,
            reserved_tokens=reservation_limit,
        )
    except ValueError as exc:
        raise CoordinatorRuntimeError(str(exc)) from exc
    if (
        not hmac.compare_digest(pricing.sha256, measured["openai_pricing_policy"])
        or cost_limit > maximum_cost
    ):
        raise CoordinatorRuntimeError("mounted OpenAI pricing contract is inconsistent")
    return CoordinatorRuntimeEvidence(
        manifest_sha256=manifest_sha256,
        coordinator_image_digest=expected_coordinator_image_digest,
        harness_sha256=measured["harness"],
        task_sha256=measured["task"],
        dependency_lock_sha256=measured["dependency_lock"],
        schema_bundle_sha256=measured["schema_bundle"],
        coordinator_public_key_sha256=measured["coordinator_public_key"],
        offline_runner_image_digest=payload["offline_runner_image_digest"],
        broker_image_digest=payload["broker_image_digest"],
        broker_gateway_image_digest=payload["broker_gateway_image_digest"],
        broker_allowlist_policy_sha256=policy_sha256,
        broker_packet_reservation_limit=reservation_limit,
        broker_pricing_policy_sha256=pricing.sha256,
        broker_packet_cost_limit_microusd=cost_limit,
    )
