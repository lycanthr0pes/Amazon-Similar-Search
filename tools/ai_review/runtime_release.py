"""Build deterministic assets consumed by the external preflight launcher.

This builder does not make its source checkout trusted.  Production callers must run it from a
human-approved commit in a candidate-inaccessible build environment, then install the launcher,
manifest, assets, and public key under a root-owned trust root.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import ValidationError

from tools.ai_review.attestation import public_key_id
from tools.ai_review.egress_policy import validate_broker_egress_policy
from tools.ai_review.hashing import sha256_file
from tools.ai_review.models import TaskSpec
from tools.ai_review.path_safety import resolve_safe_input
from tools.ai_review.path_safety import write_text_exclusive
from tools.ai_review.pricing_policy import ABSOLUTE_PACKET_COST_LIMIT_MICROUSD
from tools.ai_review.pricing_policy import maximum_packet_cost_microusd
from tools.ai_review.pricing_policy import validate_openai_pricing_policy


_IMAGE_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
MAX_BROKER_PACKET_RESERVATION_TOKENS = 1_088_000
_SCHEMA_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,127}\.schema\.json$")


class RuntimeReleaseError(ValueError):
    """Raised when release assets cannot form one immutable runtime contract."""


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise RuntimeReleaseError("schema contains a duplicate JSON key")
        result[key] = value
    return result


def _canonical_json_bytes(value: object, *, newline: bool = False) -> bytes:
    try:
        raw = json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise RuntimeReleaseError("runtime release data is not canonical JSON") from exc
    return raw + (b"\n" if newline else b"")


def validate_release_task(raw: bytes, *, harness_sha256: str) -> TaskSpec:
    """Strictly parse the production TaskSpec and bind it to the exact harness bytes."""

    def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise RuntimeReleaseError(f"TaskSpec contains a duplicate JSON key: {key}")
            result[key] = value
        return result

    try:
        payload = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=reject_duplicate_keys,
        )
        task = TaskSpec.model_validate(payload)
    except RuntimeReleaseError:
        raise
    except (UnicodeError, json.JSONDecodeError, ValidationError) as exc:
        raise RuntimeReleaseError("release task must be a strict valid TaskSpec") from exc
    if task.schema_version != "2.0":
        raise RuntimeReleaseError("production runtime manifest requires TaskSpec v2")
    if task.trusted_harness_sha256 != harness_sha256:
        raise RuntimeReleaseError("TaskSpec trusted harness SHA-256 differs from the exact asset")
    return task


def build_schema_bundle(schemas: Mapping[str, Mapping[str, Any]], output: Path) -> str:
    """Write one canonical schema bundle and return the raw-file SHA-256."""

    if not schemas or len(schemas) > 100:
        raise RuntimeReleaseError("schema bundle must contain between 1 and 100 schemas")
    canonical_schemas: dict[str, Mapping[str, Any]] = {}
    schema_sha256: dict[str, str] = {}
    for name in sorted(schemas):
        schema = schemas[name]
        if _SCHEMA_NAME_RE.fullmatch(name) is None or not isinstance(schema, Mapping):
            raise RuntimeReleaseError("schema bundle contains an invalid name or schema")
        raw_schema = _canonical_json_bytes(schema)
        canonical_schemas[name] = schema
        schema_sha256[name] = hashlib.sha256(raw_schema).hexdigest()
    payload = {
        "schema_version": "1.0",
        "schema_sha256": schema_sha256,
        "schemas": canonical_schemas,
    }
    raw = _canonical_json_bytes(payload, newline=True)
    write_text_exclusive(output, raw.decode("utf-8"))
    return hashlib.sha256(raw).hexdigest()


def load_schema_directory(directory: Path) -> dict[str, Mapping[str, Any]]:
    """Load only canonical-named JSON Schemas from a trusted release directory."""

    root = directory.resolve(strict=True)
    if root != Path(directory).absolute() or not root.is_dir():
        raise RuntimeReleaseError("schema directory must be a symlink-free directory")
    paths = sorted(root.glob("*.schema.json"))
    if not paths:
        raise RuntimeReleaseError("schema directory contains no schema files")
    schemas: dict[str, Mapping[str, Any]] = {}
    for path in paths:
        safe = resolve_safe_input(path)
        try:
            schema = json.loads(
                safe.read_text(encoding="utf-8"),
                object_pairs_hook=_reject_duplicate_keys,
            )
        except RuntimeReleaseError:
            raise
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise RuntimeReleaseError("schema directory contains invalid JSON") from exc
        if not isinstance(schema, Mapping):
            raise RuntimeReleaseError("every schema must be a JSON object")
        schemas[path.name] = schema
    return schemas


def generate_coordinator_keypair(*, private_key: Path, public_key: Path) -> dict[str, str]:
    """Create a new Ed25519 keypair without ever returning or printing private key bytes."""

    if private_key.absolute() == public_key.absolute():
        raise RuntimeReleaseError("private and public key outputs must be distinct")
    key = Ed25519PrivateKey.generate()
    private_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    write_text_exclusive(private_key, private_pem.decode("ascii"))
    try:
        write_text_exclusive(public_key, public_pem.decode("ascii"))
    except Exception:
        private_key.unlink(missing_ok=True)
        raise
    return {
        "key_id": public_key_id(key.public_key()),
        "public_key_sha256": hashlib.sha256(public_pem).hexdigest(),
    }


def _asset(path: Path, *, label: str) -> dict[str, str]:
    try:
        safe = resolve_safe_input(path)
    except (OSError, ValueError) as exc:
        raise RuntimeReleaseError(f"{label} asset is not a safe regular file") from exc
    return {"path": str(safe), "sha256": sha256_file(safe)}


def build_runtime_manifest(
    *,
    output: Path,
    python: Path,
    harness: Path,
    task: Path,
    dependency_lock: Path,
    schema_bundle: Path,
    coordinator_public_key: Path,
    broker_egress_policy: Path,
    openai_pricing_policy: Path,
    coordinator_image_digest: str,
    offline_runner_image_digest: str,
    broker_image_digest: str,
    broker_gateway_image_digest: str,
    broker_packet_reservation_limit: int,
    broker_packet_cost_limit_microusd: int,
) -> str:
    """Write a canonical manifest that preflight can raw-hash before harness import."""

    image_digests = (
        coordinator_image_digest,
        offline_runner_image_digest,
        broker_image_digest,
        broker_gateway_image_digest,
    )
    if any(_IMAGE_DIGEST_RE.fullmatch(value) is None for value in image_digests):
        raise RuntimeReleaseError("runtime images must be pinned by canonical sha256 digests")
    if len(set(image_digests)) != len(image_digests):
        raise RuntimeReleaseError(
            "coordinator, offline runner, broker, and egress gateway images must be distinct"
        )
    if (
        isinstance(broker_packet_reservation_limit, bool)
        or not isinstance(broker_packet_reservation_limit, int)
        or not 1 <= broker_packet_reservation_limit <= MAX_BROKER_PACKET_RESERVATION_TOKENS
    ):
        raise RuntimeReleaseError("broker packet reservation limit is invalid")
    assets = {
        "python": _asset(python, label="python"),
        "harness": _asset(harness, label="harness"),
        "task": _asset(task, label="task"),
        "dependency_lock": _asset(dependency_lock, label="dependency lock"),
        "schema_bundle": _asset(schema_bundle, label="schema bundle"),
        "coordinator_public_key": _asset(
            coordinator_public_key,
            label="coordinator public key",
        ),
        "broker_egress_policy": _asset(
            broker_egress_policy,
            label="broker egress policy",
        ),
        "openai_pricing_policy": _asset(
            openai_pricing_policy,
            label="OpenAI pricing policy",
        ),
    }
    try:
        policy_path = resolve_safe_input(broker_egress_policy)
        policy_sha256 = validate_broker_egress_policy(policy_path.read_bytes())
    except (OSError, ValueError) as exc:
        raise RuntimeReleaseError("broker egress policy is not approved") from exc
    if policy_sha256 != assets["broker_egress_policy"]["sha256"]:
        raise RuntimeReleaseError("broker egress policy changed during release")
    try:
        pricing_path = resolve_safe_input(openai_pricing_policy)
        pricing = validate_openai_pricing_policy(pricing_path.read_bytes())
    except (OSError, ValueError) as exc:
        raise RuntimeReleaseError("OpenAI pricing policy is not approved") from exc
    if pricing.sha256 != assets["openai_pricing_policy"]["sha256"]:
        raise RuntimeReleaseError("OpenAI pricing policy changed during release")
    maximum_cost = maximum_packet_cost_microusd(
        pricing,
        reserved_tokens=broker_packet_reservation_limit,
    )
    if (
        isinstance(broker_packet_cost_limit_microusd, bool)
        or not isinstance(broker_packet_cost_limit_microusd, int)
        or not 1 <= broker_packet_cost_limit_microusd <= maximum_cost
        or broker_packet_cost_limit_microusd > ABSOLUTE_PACKET_COST_LIMIT_MICROUSD
    ):
        raise RuntimeReleaseError("broker packet cost limit is invalid")
    try:
        task_path = resolve_safe_input(task)
        task_raw = task_path.read_bytes()
    except (OSError, ValueError) as exc:
        raise RuntimeReleaseError("task asset could not be read safely") from exc
    if hashlib.sha256(task_raw).hexdigest() != assets["task"]["sha256"]:
        raise RuntimeReleaseError("task asset changed during release")
    validate_release_task(task_raw, harness_sha256=assets["harness"]["sha256"])
    asset_paths = [entry["path"] for entry in assets.values()]
    if len(asset_paths) != len(set(asset_paths)):
        raise RuntimeReleaseError("runtime manifest assets must use distinct regular files")
    payload = {
        "schema_version": "1.0",
        **assets,
        "coordinator_image_digest": coordinator_image_digest,
        "offline_runner_image_digest": offline_runner_image_digest,
        "broker_image_digest": broker_image_digest,
        "broker_gateway_image_digest": broker_gateway_image_digest,
        "broker_packet_reservation_limit": broker_packet_reservation_limit,
        "broker_packet_cost_limit_microusd": broker_packet_cost_limit_microusd,
    }
    raw = _canonical_json_bytes(payload, newline=True)
    write_text_exclusive(output, raw.decode("utf-8"))
    return hashlib.sha256(raw).hexdigest()


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Build approved AI review runtime assets")
    subparsers = parser.add_subparsers(dest="command", required=True)

    schemas = subparsers.add_parser("schema-bundle")
    schemas.add_argument("--schema-dir", type=Path, required=True)
    schemas.add_argument("--output", type=Path, required=True)

    keys = subparsers.add_parser("keygen")
    keys.add_argument("--private-key", type=Path, required=True)
    keys.add_argument("--public-key", type=Path, required=True)

    manifest = subparsers.add_parser("manifest")
    manifest.add_argument("--output", type=Path, required=True)
    manifest.add_argument("--python", type=Path, required=True)
    manifest.add_argument("--harness", type=Path, required=True)
    manifest.add_argument("--task", type=Path, required=True)
    manifest.add_argument("--dependency-lock", type=Path, required=True)
    manifest.add_argument("--schema-bundle", type=Path, required=True)
    manifest.add_argument("--coordinator-public-key", type=Path, required=True)
    manifest.add_argument("--broker-egress-policy", type=Path, required=True)
    manifest.add_argument("--openai-pricing-policy", type=Path, required=True)
    manifest.add_argument("--coordinator-image-digest", required=True)
    manifest.add_argument("--offline-runner-image-digest", required=True)
    manifest.add_argument("--broker-image-digest", required=True)
    manifest.add_argument("--broker-gateway-image-digest", required=True)
    manifest.add_argument("--broker-packet-reservation-limit", type=int, required=True)
    manifest.add_argument("--broker-packet-cost-limit-microusd", type=int, required=True)

    workflow = subparsers.add_parser("workflow-init")
    workflow.add_argument("--task", type=Path, required=True)
    workflow.add_argument("--runtime-manifest", type=Path, required=True)
    workflow.add_argument("--expected-runtime-manifest-sha256", required=True)
    workflow.add_argument("--coordinator-public-key", type=Path, required=True)
    workflow.add_argument("--candidate-repo", type=Path, required=True)
    workflow.add_argument("--candidate-uid", type=int, required=True)
    workflow.add_argument("--expected-patch-sha256", required=True)
    workflow.add_argument("--output-dir", type=Path, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "schema-bundle":
            digest = build_schema_bundle(load_schema_directory(args.schema_dir), args.output)
            print(json.dumps({"schema_bundle_sha256": digest}, sort_keys=True))
        elif args.command == "keygen":
            print(
                json.dumps(
                    generate_coordinator_keypair(
                        private_key=args.private_key,
                        public_key=args.public_key,
                    ),
                    sort_keys=True,
                )
            )
        elif args.command == "manifest":
            digest = build_runtime_manifest(
                output=args.output,
                python=args.python,
                harness=args.harness,
                task=args.task,
                dependency_lock=args.dependency_lock,
                schema_bundle=args.schema_bundle,
                coordinator_public_key=args.coordinator_public_key,
                broker_egress_policy=args.broker_egress_policy,
                openai_pricing_policy=args.openai_pricing_policy,
                coordinator_image_digest=args.coordinator_image_digest,
                offline_runner_image_digest=args.offline_runner_image_digest,
                broker_image_digest=args.broker_image_digest,
                broker_gateway_image_digest=args.broker_gateway_image_digest,
                broker_packet_reservation_limit=args.broker_packet_reservation_limit,
                broker_packet_cost_limit_microusd=args.broker_packet_cost_limit_microusd,
            )
            print(json.dumps({"runtime_manifest_sha256": digest}, sort_keys=True))
        else:
            from tools.ai_review.workflow_init import initialize_workflow

            initialized = initialize_workflow(
                task=args.task,
                runtime_manifest=args.runtime_manifest,
                expected_runtime_manifest_sha256=args.expected_runtime_manifest_sha256,
                coordinator_public_key=args.coordinator_public_key,
                candidate_repo=args.candidate_repo,
                candidate_uid=args.candidate_uid,
                expected_patch_sha256=args.expected_patch_sha256,
                output_dir=args.output_dir,
            )
            print(json.dumps(initialized.safe_digests(), sort_keys=True))
        return 0
    except (OSError, ValueError) as exc:
        print(f"runtime release error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
