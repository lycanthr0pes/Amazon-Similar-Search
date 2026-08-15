"""Coordinator-owned prepare/finalize protocol for the stdlib broker outer executor.

The coordinator creates one canonical, self-digesting batch containing exactly the reviewer and
adversary descriptors.  Credentials, the protected ledger pathname, and the container-runtime
pathname are deliberately absent: the root-owned outer launcher supplies those out of band and
must remeasure them against the identities bound here.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
from dataclasses import dataclass
from dataclasses import replace
from pathlib import Path
from typing import Any
from typing import Iterable

from tools.ai_review.broker_egress_provisioner import BrokerEgressLifecycleEvidence
from tools.ai_review.broker_egress_provisioner import BrokerEgressProvisioningError
from tools.ai_review.broker_egress_provisioner import GATEWAY_ALIAS
from tools.ai_review.broker_egress_provisioner import GATEWAY_PORT
from tools.ai_review.broker_egress_provisioner import ProvisionedBrokerExecutionEvidence
from tools.ai_review.broker_egress_provisioner import RuntimeCommandEvidence
from tools.ai_review.broker_egress_provisioner import _command_evidence_sha256
from tools.ai_review.broker_egress_provisioner import _container_absence_argv
from tools.ai_review.broker_egress_provisioner import _container_inspect_argv
from tools.ai_review.broker_egress_provisioner import _container_remove_argv
from tools.ai_review.broker_egress_provisioner import _gateway_name
from tools.ai_review.broker_egress_provisioner import _gateway_run_argv
from tools.ai_review.broker_egress_provisioner import _lifecycle_sha256
from tools.ai_review.broker_egress_provisioner import _network_absence_argv
from tools.ai_review.broker_egress_provisioner import _network_connect_argv
from tools.ai_review.broker_egress_provisioner import _network_create_argv
from tools.ai_review.broker_egress_provisioner import _network_inspect_argv
from tools.ai_review.broker_egress_provisioner import _network_remove_argv
from tools.ai_review.broker_egress_provisioner import _owner_sha256
from tools.ai_review.broker_egress_provisioner import _provisioned_execution_sha256
from tools.ai_review.broker_egress_provisioner import _validate_gateway_inspect
from tools.ai_review.broker_egress_provisioner import _validate_network_inspect
from tools.ai_review.broker_egress_provisioner import _validate_owned_resource_inspect
from tools.ai_review.broker_egress_provisioner import broker_gateway_external_network_name
from tools.ai_review.broker_executor import BrokerExecutionEvidence
from tools.ai_review.broker_executor import BrokerExecutionError
from tools.ai_review.broker_executor import BrokerLedgerEvidence
from tools.ai_review.broker_executor import EgressBoundaryEvidence
from tools.ai_review.broker_executor import MAX_BROKER_STDERR_BYTES
from tools.ai_review.broker_executor import MAX_BROKER_STDIN_BYTES
from tools.ai_review.broker_executor import MAX_BROKER_STDOUT_BYTES
from tools.ai_review.broker_executor import MAX_BROKER_TIMEOUT_SECONDS
from tools.ai_review.broker_executor import _BrokerProcessResult
from tools.ai_review.broker_executor import _CleanupResult
from tools.ai_review.broker_executor import _build_ledger_evidence
from tools.ai_review.broker_executor import _evidence_sha256
from tools.ai_review.broker_executor import _parse_canonical_envelope
from tools.ai_review.broker_executor import _reservation_record_sha256
from tools.ai_review.broker_executor import _validate_limits
from tools.ai_review.broker_executor import broker_egress_boundary_sha256
from tools.ai_review.broker_executor import validate_frozen_broker_ledger_evidence
from tools.ai_review.broker_executor import (
    validate_successful_broker_executions_against_final_ledger,
)
from tools.ai_review.codex_adapter import IsolatedBrokerInvocation
from tools.ai_review.egress_policy import validate_broker_egress_policy
from tools.ai_review.preflight import ensure_separate_candidate_uid
from tools.ai_review.pricing_policy import APPROVED_OPENAI_PRICING_POLICY
from tools.ai_review.pricing_policy import DEFAULT_PACKET_COST_LIMIT_MICROUSD
from tools.ai_review.pricing_policy import canonical_openai_pricing_policy_bytes
from tools.ai_review.pricing_policy import reserve_request_cost_microusd
from tools.ai_review.pricing_policy import validate_openai_pricing_policy
from tools.ai_review.offline_runner import ContainerBackend


_RUN_DOMAIN = b"amazon-explorer-prepared-broker-run-v1\0"
_BATCH_DOMAIN = b"amazon-explorer-prepared-broker-batch-v1\0"
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_IMAGE_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_PINNED_IMAGE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/:+-]*@(sha256:[0-9a-f]{64})$")
_ROLE_ORDER = ("reviewer", "adversary")
_OUTER_RUN_DOMAIN = b"amazon-explorer-outer-broker-run-v1\0"
_OUTER_BATCH_DOMAIN = b"amazon-explorer-outer-broker-batch-v1\0"
_FROZEN_LEDGER_DOMAIN = b"amazon-explorer-frozen-broker-ledger-v1\0"
_MAX_PREPARED_BATCH_BYTES = 2_000_000
_MAX_OUTER_EVIDENCE_BYTES = 6_000_000
_MAX_OUTER_STDOUT_BYTES = 1_000_000


class BrokerPhaseProtocolError(ValueError):
    """Raised when coordinator/outer broker artifacts are not exact canonical contracts."""


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
        raise BrokerPhaseProtocolError("broker phase artifact is not canonical JSON") from exc


def _strict_json(raw: bytes, *, label: str) -> dict[str, Any]:
    def pairs(values: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in values:
            if key in result:
                raise BrokerPhaseProtocolError(f"{label} contains a duplicate key")
            result[key] = value
        return result

    maximum = (
        _MAX_OUTER_EVIDENCE_BYTES if label == "outer broker evidence" else _MAX_PREPARED_BATCH_BYTES
    )
    if not isinstance(raw, bytes) or not raw or len(raw) > maximum:
        raise BrokerPhaseProtocolError(f"{label} must be non-empty bytes")
    try:
        parsed = json.loads(raw.decode("utf-8", errors="strict"), object_pairs_hook=pairs)
    except BrokerPhaseProtocolError:
        raise
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise BrokerPhaseProtocolError(f"{label} is not strict JSON") from exc
    if not isinstance(parsed, dict) or raw != _canonical_json(parsed):
        raise BrokerPhaseProtocolError(f"{label} must use canonical JSON encoding")
    return parsed


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _domain_sha256(domain: bytes, payload: dict[str, object]) -> str:
    return _sha256(domain + _canonical_json(payload))


def _is_sha256(value: object) -> bool:
    return isinstance(value, str) and _SHA256_RE.fullmatch(value) is not None


@dataclass(frozen=True)
class BrokerRuntimeBinding:
    """Coordinator-approved runtime identity, excluding its host pathname."""

    name: str
    executable_sha256: str
    environment_sha256: str
    rootless: bool
    user_namespace: bool
    seccomp_profile: str
    security_evidence_sha256: str

    def __post_init__(self) -> None:
        expected_security = _domainless_security_sha256(
            name=self.name,
            rootless=self.rootless,
            user_namespace=self.user_namespace,
            seccomp_profile=self.seccomp_profile,
        )
        if (
            self.name not in {"podman", "docker"}
            or not _is_sha256(self.executable_sha256)
            or not _is_sha256(self.environment_sha256)
            or type(self.rootless) is not bool
            or type(self.user_namespace) is not bool
            or (not self.rootless and not self.user_namespace)
            or not isinstance(self.seccomp_profile, str)
            or not self.seccomp_profile
            or "unconfined" in self.seccomp_profile.casefold()
            or not _is_sha256(self.security_evidence_sha256)
            or not hmac.compare_digest(self.security_evidence_sha256, expected_security)
        ):
            raise BrokerPhaseProtocolError("broker runtime binding is invalid")


def _domainless_security_sha256(
    *, name: str, rootless: bool, user_namespace: bool, seccomp_profile: str
) -> str:
    return _sha256(
        _canonical_json(
            {
                "name": name,
                "rootless": rootless,
                "seccomp_profile": seccomp_profile,
                "user_namespace": user_namespace,
            }
        )
        + b"\n"
    )


@dataclass(frozen=True)
class PreparedBrokerRun:
    """One caller-nondiscretionary packet-only broker descriptor."""

    schema_version: str
    role: str
    attempt: int
    packet_sha256: str
    request_sha256: str
    boundary_evidence_sha256: str
    container_runtime: str
    runtime_rootless: bool
    runtime_user_namespace: bool
    container_name: str
    broker_internal_network: str
    image: str
    approved_image_digest: str
    credential_env_name: str
    descriptor_argv: tuple[str, ...]
    descriptor_argv_sha256: str
    stdin: bytes
    stdin_sha256: str
    reserved_tokens: int
    reserved_cost_microusd: int
    descriptor_sha256: str

    def invocation(self) -> IsolatedBrokerInvocation:
        return IsolatedBrokerInvocation(
            argv=self.descriptor_argv,
            stdin_text=self.stdin.decode("utf-8", errors="strict"),
            container_runtime=self.container_runtime,  # type: ignore[arg-type]
            runtime_rootless=self.runtime_rootless,
            runtime_user_namespace=self.runtime_user_namespace,
            container_name=self.container_name,
            broker_internal_network=self.broker_internal_network,
            image=self.image,
            approved_image_digest=self.approved_image_digest,
            credential_env_name=self.credential_env_name,  # type: ignore[arg-type]
            packet_sha256=self.packet_sha256,
            request_sha256=self.request_sha256,
            role=self.role,  # type: ignore[arg-type]
            attempt=self.attempt,
            reserved_tokens=self.reserved_tokens,
            stdin_sha256=self.stdin_sha256,
            argv_sha256=self.descriptor_argv_sha256,
            boundary_evidence_sha256=self.boundary_evidence_sha256,
        )


@dataclass(frozen=True)
class PreparedBrokerBatch:
    """Exact reviewer/adversary batch crossing from coordinator to the outer launcher."""

    schema_version: str
    workflow_id: str
    phase_request_sha256: str
    task_sha256: str
    runtime_manifest_sha256: str
    candidate_snapshot_sha256: str
    review_packet_sha256: str
    candidate_uid: int
    runtime: BrokerRuntimeBinding
    gateway_image: str
    broker_gateway_image_digest: str
    broker_allowlist_policy_sha256: str
    broker_pricing_policy_sha256: str
    broker_ledger_identity_sha256: str
    broker_packet_reservation_limit: int
    broker_packet_cost_limit_microusd: int
    timeout_seconds: int
    max_stdin_bytes: int
    max_stdout_bytes: int
    max_stderr_bytes: int
    runs: tuple[PreparedBrokerRun, ...]
    batch_sha256: str

    @property
    def canonical_sha256(self) -> str:
        return _sha256(canonical_prepared_broker_batch_bytes(self))

    @classmethod
    def parse(cls, raw: bytes) -> PreparedBrokerBatch:
        return _parse_prepared_broker_batch(raw, require_two=True)


def _runtime_payload(runtime: BrokerRuntimeBinding) -> dict[str, object]:
    return {
        "environment_sha256": runtime.environment_sha256,
        "executable_sha256": runtime.executable_sha256,
        "name": runtime.name,
        "rootless": runtime.rootless,
        "seccomp_profile": runtime.seccomp_profile,
        "security_evidence_sha256": runtime.security_evidence_sha256,
        "user_namespace": runtime.user_namespace,
    }


def _run_payload(run: PreparedBrokerRun, *, include_digest: bool) -> dict[str, object]:
    payload: dict[str, object] = {
        "approved_image_digest": run.approved_image_digest,
        "attempt": run.attempt,
        "boundary_evidence_sha256": run.boundary_evidence_sha256,
        "broker_internal_network": run.broker_internal_network,
        "container_name": run.container_name,
        "container_runtime": run.container_runtime,
        "credential_env_name": run.credential_env_name,
        "descriptor_argv": list(run.descriptor_argv),
        "descriptor_argv_sha256": run.descriptor_argv_sha256,
        "image": run.image,
        "packet_sha256": run.packet_sha256,
        "request_sha256": run.request_sha256,
        "reserved_cost_microusd": run.reserved_cost_microusd,
        "reserved_tokens": run.reserved_tokens,
        "role": run.role,
        "runtime_rootless": run.runtime_rootless,
        "runtime_user_namespace": run.runtime_user_namespace,
        "schema_version": run.schema_version,
        "stdin_base64": base64.b64encode(run.stdin).decode("ascii"),
        "stdin_sha256": run.stdin_sha256,
    }
    if include_digest:
        payload["descriptor_sha256"] = run.descriptor_sha256
    return payload


def _batch_payload(batch: PreparedBrokerBatch, *, include_digest: bool) -> dict[str, object]:
    payload: dict[str, object] = {
        "broker_allowlist_policy_sha256": batch.broker_allowlist_policy_sha256,
        "broker_gateway_image_digest": batch.broker_gateway_image_digest,
        "broker_ledger_identity_sha256": batch.broker_ledger_identity_sha256,
        "broker_packet_cost_limit_microusd": batch.broker_packet_cost_limit_microusd,
        "broker_packet_reservation_limit": batch.broker_packet_reservation_limit,
        "broker_pricing_policy_sha256": batch.broker_pricing_policy_sha256,
        "candidate_snapshot_sha256": batch.candidate_snapshot_sha256,
        "candidate_uid": batch.candidate_uid,
        "gateway_image": batch.gateway_image,
        "max_stderr_bytes": batch.max_stderr_bytes,
        "max_stdin_bytes": batch.max_stdin_bytes,
        "max_stdout_bytes": batch.max_stdout_bytes,
        "phase_request_sha256": batch.phase_request_sha256,
        "review_packet_sha256": batch.review_packet_sha256,
        "runs": [_run_payload(run, include_digest=True) for run in batch.runs],
        "runtime": _runtime_payload(batch.runtime),
        "runtime_manifest_sha256": batch.runtime_manifest_sha256,
        "schema_version": batch.schema_version,
        "task_sha256": batch.task_sha256,
        "timeout_seconds": batch.timeout_seconds,
        "workflow_id": batch.workflow_id,
    }
    if include_digest:
        payload["batch_sha256"] = batch.batch_sha256
    return payload


def canonical_prepared_broker_batch_bytes(batch: PreparedBrokerBatch) -> bytes:
    """Serialize one typed batch with its exact canonical JSON encoding."""

    if type(batch) is not PreparedBrokerBatch:
        raise BrokerPhaseProtocolError("prepared broker batch type is invalid")
    raw = _canonical_json(_batch_payload(batch, include_digest=True))
    measured = _parse_prepared_broker_batch(raw, require_two=len(batch.runs) == 2)
    if measured != batch:
        raise BrokerPhaseProtocolError("prepared broker batch changed during serialization")
    return raw


def _parse_run(payload: object) -> PreparedBrokerRun:
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
    if not isinstance(payload, dict) or set(payload) != fields:
        raise BrokerPhaseProtocolError("prepared broker run has missing or unknown fields")
    unsigned = {key: value for key, value in payload.items() if key != "descriptor_sha256"}
    digest = payload["descriptor_sha256"]
    if not _is_sha256(digest) or not hmac.compare_digest(
        digest,
        _domain_sha256(_RUN_DOMAIN, unsigned),
    ):
        raise BrokerPhaseProtocolError("prepared broker run digest is invalid")
    try:
        stdin = base64.b64decode(payload["stdin_base64"], validate=True)
        run = PreparedBrokerRun(
            schema_version=payload["schema_version"],
            role=payload["role"],
            attempt=payload["attempt"],
            packet_sha256=payload["packet_sha256"],
            request_sha256=payload["request_sha256"],
            boundary_evidence_sha256=payload["boundary_evidence_sha256"],
            container_runtime=payload["container_runtime"],
            runtime_rootless=payload["runtime_rootless"],
            runtime_user_namespace=payload["runtime_user_namespace"],
            container_name=payload["container_name"],
            broker_internal_network=payload["broker_internal_network"],
            image=payload["image"],
            approved_image_digest=payload["approved_image_digest"],
            credential_env_name=payload["credential_env_name"],
            descriptor_argv=tuple(payload["descriptor_argv"]),
            descriptor_argv_sha256=payload["descriptor_argv_sha256"],
            stdin=stdin,
            stdin_sha256=payload["stdin_sha256"],
            reserved_tokens=payload["reserved_tokens"],
            reserved_cost_microusd=payload["reserved_cost_microusd"],
            descriptor_sha256=digest,
        )
        invocation = run.invocation()
    except (TypeError, ValueError, UnicodeError) as exc:
        raise BrokerPhaseProtocolError("prepared broker run is invalid") from exc
    if (
        run.schema_version != "1.0"
        or run.role not in _ROLE_ORDER
        or run.role != invocation.role
        or run.attempt != invocation.attempt
        or run.stdin != invocation.stdin_text.encode("utf-8")
        or not isinstance(run.reserved_cost_microusd, int)
        or isinstance(run.reserved_cost_microusd, bool)
        or run.reserved_cost_microusd <= 0
    ):
        raise BrokerPhaseProtocolError("prepared broker run is invalid")
    return run


def _parse_runtime(payload: object) -> BrokerRuntimeBinding:
    fields = {
        "environment_sha256",
        "executable_sha256",
        "name",
        "rootless",
        "seccomp_profile",
        "security_evidence_sha256",
        "user_namespace",
    }
    if not isinstance(payload, dict) or set(payload) != fields:
        raise BrokerPhaseProtocolError("prepared broker runtime has missing or unknown fields")
    try:
        return BrokerRuntimeBinding(**payload)
    except (TypeError, ValueError) as exc:
        raise BrokerPhaseProtocolError("prepared broker runtime is invalid") from exc


def _parse_prepared_broker_batch(raw: bytes, *, require_two: bool) -> PreparedBrokerBatch:
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
    if set(payload) != fields:
        raise BrokerPhaseProtocolError("prepared broker batch has missing or unknown fields")
    unsigned = {key: value for key, value in payload.items() if key != "batch_sha256"}
    if not _is_sha256(payload["batch_sha256"]) or not hmac.compare_digest(
        payload["batch_sha256"],
        _domain_sha256(_BATCH_DOMAIN, unsigned),
    ):
        raise BrokerPhaseProtocolError("prepared broker batch digest is invalid")
    try:
        runs = tuple(_parse_run(value) for value in payload["runs"])
        batch = PreparedBrokerBatch(
            schema_version=payload["schema_version"],
            workflow_id=payload["workflow_id"],
            phase_request_sha256=payload["phase_request_sha256"],
            task_sha256=payload["task_sha256"],
            runtime_manifest_sha256=payload["runtime_manifest_sha256"],
            candidate_snapshot_sha256=payload["candidate_snapshot_sha256"],
            review_packet_sha256=payload["review_packet_sha256"],
            candidate_uid=payload["candidate_uid"],
            runtime=_parse_runtime(payload["runtime"]),
            gateway_image=payload["gateway_image"],
            broker_gateway_image_digest=payload["broker_gateway_image_digest"],
            broker_allowlist_policy_sha256=payload["broker_allowlist_policy_sha256"],
            broker_pricing_policy_sha256=payload["broker_pricing_policy_sha256"],
            broker_ledger_identity_sha256=payload["broker_ledger_identity_sha256"],
            broker_packet_reservation_limit=payload["broker_packet_reservation_limit"],
            broker_packet_cost_limit_microusd=payload["broker_packet_cost_limit_microusd"],
            timeout_seconds=payload["timeout_seconds"],
            max_stdin_bytes=payload["max_stdin_bytes"],
            max_stdout_bytes=payload["max_stdout_bytes"],
            max_stderr_bytes=payload["max_stderr_bytes"],
            runs=runs,
            batch_sha256=payload["batch_sha256"],
        )
    except (TypeError, ValueError) as exc:
        raise BrokerPhaseProtocolError("prepared broker batch is invalid") from exc
    _validate_batch(batch, require_two=require_two)
    return batch


def _validate_batch(batch: PreparedBrokerBatch, *, require_two: bool) -> None:
    digests = (
        batch.workflow_id,
        batch.phase_request_sha256,
        batch.task_sha256,
        batch.runtime_manifest_sha256,
        batch.candidate_snapshot_sha256,
        batch.review_packet_sha256,
        batch.broker_allowlist_policy_sha256,
        batch.broker_pricing_policy_sha256,
        batch.broker_ledger_identity_sha256,
        batch.batch_sha256,
    )
    match = _PINNED_IMAGE_RE.fullmatch(batch.gateway_image or "")
    try:
        ensure_separate_candidate_uid(batch.candidate_uid)
        _validate_limits(
            timeout_seconds=batch.timeout_seconds,
            max_stdin_bytes=batch.max_stdin_bytes,
            max_stdout_bytes=batch.max_stdout_bytes,
            max_stderr_bytes=batch.max_stderr_bytes,
            packet_reservation_limit=batch.broker_packet_reservation_limit,
            packet_cost_limit_microusd=batch.broker_packet_cost_limit_microusd,
        )
    except (TypeError, ValueError) as exc:
        raise BrokerPhaseProtocolError("prepared broker batch limits are invalid") from exc
    if require_two and tuple(run.role for run in batch.runs) != _ROLE_ORDER:
        raise BrokerPhaseProtocolError(
            "prepared broker batch requires exactly reviewer and adversary"
        )
    if (
        batch.schema_version != "1.0"
        or any(not _is_sha256(value) for value in digests)
        or _IMAGE_DIGEST_RE.fullmatch(batch.broker_gateway_image_digest or "") is None
        or match is None
        or match.group(1) != batch.broker_gateway_image_digest
        or (not require_two and not 1 <= len(batch.runs) <= 2)
        or len({run.role for run in batch.runs}) != len(batch.runs)
        or any(run.packet_sha256 != batch.review_packet_sha256 for run in batch.runs)
        or any(run.container_runtime != batch.runtime.name for run in batch.runs)
        or any(run.runtime_rootless is not batch.runtime.rootless for run in batch.runs)
        or any(run.runtime_user_namespace is not batch.runtime.user_namespace for run in batch.runs)
        or sum(run.reserved_tokens for run in batch.runs) > batch.broker_packet_reservation_limit
        or sum(run.reserved_cost_microusd for run in batch.runs)
        > batch.broker_packet_cost_limit_microusd
        or batch.max_stdout_bytes > _MAX_OUTER_STDOUT_BYTES
    ):
        raise BrokerPhaseProtocolError("prepared broker batch is invalid")


def _prepare_runs(
    invocations: Iterable[IsolatedBrokerInvocation],
    *,
    pricing_policy: bytes,
) -> tuple[PreparedBrokerRun, ...]:
    trusted_pricing = validate_openai_pricing_policy(pricing_policy)
    measured: list[PreparedBrokerRun] = []
    for invocation in invocations:
        try:
            trusted = IsolatedBrokerInvocation(**vars(invocation))
            reserved_cost = reserve_request_cost_microusd(
                trusted_pricing,
                input_tokens=trusted.reserved_tokens - 12_000,
                output_tokens=12_000,
            )
        except (TypeError, ValueError) as exc:
            raise BrokerPhaseProtocolError("broker invocation is invalid") from exc
        run = PreparedBrokerRun(
            schema_version="1.0",
            role=trusted.role,
            attempt=trusted.attempt,
            packet_sha256=trusted.packet_sha256,
            request_sha256=trusted.request_sha256,
            boundary_evidence_sha256=trusted.boundary_evidence_sha256,
            container_runtime=trusted.container_runtime,
            runtime_rootless=trusted.runtime_rootless,
            runtime_user_namespace=trusted.runtime_user_namespace,
            container_name=trusted.container_name,
            broker_internal_network=trusted.broker_internal_network,
            image=trusted.image,
            approved_image_digest=trusted.approved_image_digest,
            credential_env_name=trusted.credential_env_name,
            descriptor_argv=trusted.argv,
            descriptor_argv_sha256=trusted.argv_sha256,
            stdin=trusted.stdin_text.encode("utf-8"),
            stdin_sha256=trusted.stdin_sha256,
            reserved_tokens=trusted.reserved_tokens,
            reserved_cost_microusd=reserved_cost,
            descriptor_sha256="0" * 64,
        )
        measured.append(
            replace(
                run,
                descriptor_sha256=_domain_sha256(
                    _RUN_DOMAIN,
                    _run_payload(run, include_digest=False),
                ),
            )
        )
    return tuple(sorted(measured, key=lambda run: _ROLE_ORDER.index(run.role)))


def _prepare_batch(
    *,
    workflow_id: str,
    phase_request_sha256: str,
    task_sha256: str,
    runtime_manifest_sha256: str,
    candidate_snapshot_sha256: str,
    review_packet_sha256: str,
    invocations: Iterable[IsolatedBrokerInvocation],
    runtime: BrokerRuntimeBinding,
    gateway_image: str,
    broker_gateway_image_digest: str,
    allowlist_policy: bytes,
    broker_allowlist_policy_sha256: str,
    pricing_policy: bytes,
    broker_pricing_policy_sha256: str,
    broker_ledger_identity_sha256: str,
    broker_packet_reservation_limit: int,
    broker_packet_cost_limit_microusd: int,
    candidate_uid: int,
    timeout_seconds: int,
    max_stdin_bytes: int,
    max_stdout_bytes: int,
    max_stderr_bytes: int,
    require_two: bool,
) -> PreparedBrokerBatch:
    try:
        policy_sha256 = validate_broker_egress_policy(allowlist_policy)
        trusted_pricing = validate_openai_pricing_policy(pricing_policy)
    except (TypeError, ValueError) as exc:
        raise BrokerPhaseProtocolError("broker policy binding is invalid") from exc
    if (
        policy_sha256 != broker_allowlist_policy_sha256
        or trusted_pricing.sha256 != broker_pricing_policy_sha256
        or trusted_pricing.sha256 != APPROVED_OPENAI_PRICING_POLICY.sha256
    ):
        raise BrokerPhaseProtocolError("broker policy binding is invalid")
    runs = _prepare_runs(invocations, pricing_policy=pricing_policy)
    batch = PreparedBrokerBatch(
        schema_version="1.0",
        workflow_id=workflow_id,
        phase_request_sha256=phase_request_sha256,
        task_sha256=task_sha256,
        runtime_manifest_sha256=runtime_manifest_sha256,
        candidate_snapshot_sha256=candidate_snapshot_sha256,
        review_packet_sha256=review_packet_sha256,
        candidate_uid=candidate_uid,
        runtime=runtime,
        gateway_image=gateway_image,
        broker_gateway_image_digest=broker_gateway_image_digest,
        broker_allowlist_policy_sha256=broker_allowlist_policy_sha256,
        broker_pricing_policy_sha256=broker_pricing_policy_sha256,
        broker_ledger_identity_sha256=broker_ledger_identity_sha256,
        broker_packet_reservation_limit=broker_packet_reservation_limit,
        broker_packet_cost_limit_microusd=broker_packet_cost_limit_microusd,
        timeout_seconds=timeout_seconds,
        max_stdin_bytes=max_stdin_bytes,
        max_stdout_bytes=max_stdout_bytes,
        max_stderr_bytes=max_stderr_bytes,
        runs=runs,
        batch_sha256="0" * 64,
    )
    batch = replace(
        batch,
        batch_sha256=_domain_sha256(
            _BATCH_DOMAIN,
            _batch_payload(batch, include_digest=False),
        ),
    )
    _validate_batch(batch, require_two=require_two)
    return batch


def prepare_provisioned_broker_execution(
    *,
    workflow_id: str,
    phase_request_sha256: str,
    task_sha256: str,
    runtime_manifest_sha256: str,
    candidate_snapshot_sha256: str,
    review_packet_sha256: str,
    invocations: Iterable[IsolatedBrokerInvocation],
    runtime: BrokerRuntimeBinding,
    gateway_image: str,
    broker_gateway_image_digest: str,
    allowlist_policy: bytes,
    broker_allowlist_policy_sha256: str,
    pricing_policy: bytes = canonical_openai_pricing_policy_bytes(),
    broker_pricing_policy_sha256: str = APPROVED_OPENAI_PRICING_POLICY.sha256,
    broker_ledger_identity_sha256: str,
    broker_packet_reservation_limit: int,
    broker_packet_cost_limit_microusd: int = DEFAULT_PACKET_COST_LIMIT_MICROUSD,
    candidate_uid: int,
    timeout_seconds: int = 240,
    max_stdin_bytes: int = MAX_BROKER_STDIN_BYTES,
    max_stdout_bytes: int = _MAX_OUTER_STDOUT_BYTES,
    max_stderr_bytes: int = MAX_BROKER_STDERR_BYTES,
) -> PreparedBrokerBatch:
    """Build the exact two-run reviewer/adversary production descriptor batch."""

    return _prepare_batch(
        workflow_id=workflow_id,
        phase_request_sha256=phase_request_sha256,
        task_sha256=task_sha256,
        runtime_manifest_sha256=runtime_manifest_sha256,
        candidate_snapshot_sha256=candidate_snapshot_sha256,
        review_packet_sha256=review_packet_sha256,
        invocations=invocations,
        runtime=runtime,
        gateway_image=gateway_image,
        broker_gateway_image_digest=broker_gateway_image_digest,
        allowlist_policy=allowlist_policy,
        broker_allowlist_policy_sha256=broker_allowlist_policy_sha256,
        pricing_policy=pricing_policy,
        broker_pricing_policy_sha256=broker_pricing_policy_sha256,
        broker_ledger_identity_sha256=broker_ledger_identity_sha256,
        broker_packet_reservation_limit=broker_packet_reservation_limit,
        broker_packet_cost_limit_microusd=broker_packet_cost_limit_microusd,
        candidate_uid=candidate_uid,
        timeout_seconds=timeout_seconds,
        max_stdin_bytes=max_stdin_bytes,
        max_stdout_bytes=max_stdout_bytes,
        max_stderr_bytes=max_stderr_bytes,
        require_two=True,
    )


def _decode_raw_command(payload: object) -> RuntimeCommandEvidence:
    fields = {
        "argv",
        "duration_ms",
        "exit_code",
        "stderr_base64",
        "stderr_sha256",
        "stdout_base64",
        "stdout_sha256",
    }
    if not isinstance(payload, dict) or set(payload) != fields:
        raise BrokerPhaseProtocolError("outer broker command has missing or unknown fields")
    try:
        argv = tuple(payload["argv"])
        stdout = base64.b64decode(payload["stdout_base64"], validate=True)
        stderr = base64.b64decode(payload["stderr_base64"], validate=True)
    except (TypeError, ValueError) as exc:
        raise BrokerPhaseProtocolError("outer broker command encoding is invalid") from exc
    duration_ms = payload["duration_ms"]
    exit_code = payload["exit_code"]
    if (
        not argv
        or not Path(argv[0]).is_absolute()
        or any(
            not isinstance(value, str)
            or not value
            or any(character in value for character in "\x00\r\n")
            for value in argv
        )
        or isinstance(exit_code, bool)
        or not isinstance(exit_code, int)
        or isinstance(duration_ms, bool)
        or not isinstance(duration_ms, int)
        or not 0 <= duration_ms <= MAX_BROKER_TIMEOUT_SECONDS * 1_000
        or len(stdout) > MAX_BROKER_STDOUT_BYTES
        or len(stderr) > MAX_BROKER_STDERR_BYTES
        or payload["stdout_sha256"] != _sha256(stdout)
        or payload["stderr_sha256"] != _sha256(stderr)
        or b"OPENAI_API_KEY=" in stdout
        or b"OPENAI_API_KEY=" in stderr
    ):
        raise BrokerPhaseProtocolError("outer broker command is invalid")
    return RuntimeCommandEvidence(
        argv=argv,
        exit_code=exit_code,
        stdout=stdout,
        stderr=stderr,
        stdout_sha256=_sha256(stdout),
        stderr_sha256=_sha256(stderr),
        duration_ms=duration_ms,
        evidence_sha256=_command_evidence_sha256(
            argv=argv,
            exit_code=exit_code,
            stdout=stdout,
            stderr=stderr,
            duration_ms=duration_ms,
        ),
    )


def _decode_runtime_measurement(
    payload: object,
    *,
    runtime: BrokerRuntimeBinding,
    runtime_path: Path | None,
) -> tuple[dict[str, object], Path]:
    fields = {
        "command",
        "device",
        "inode",
        "runtime_sha256",
        "security_evidence_sha256",
    }
    if not isinstance(payload, dict) or set(payload) != fields:
        raise BrokerPhaseProtocolError("outer broker runtime evidence is invalid")
    command = _decode_raw_command(payload["command"])
    expected_argv = (
        (str(Path(command.argv[0])), "info", "--format", "json")
        if runtime.name == "podman"
        else (str(Path(command.argv[0])), "info", "--format", "{{json .SecurityOptions}}")
    )
    measured_path = Path(command.argv[0])
    if (
        command.argv != expected_argv
        or command.exit_code != 0
        or not measured_path.is_absolute()
        or (runtime_path is not None and measured_path != runtime_path)
        or isinstance(payload["device"], bool)
        or not isinstance(payload["device"], int)
        or payload["device"] < 0
        or isinstance(payload["inode"], bool)
        or not isinstance(payload["inode"], int)
        or payload["inode"] <= 0
        or payload["runtime_sha256"] != runtime.executable_sha256
        or payload["security_evidence_sha256"] != runtime.security_evidence_sha256
    ):
        raise BrokerPhaseProtocolError("outer broker runtime evidence is invalid")
    try:
        probed = json.loads(command.stdout.decode("utf-8", errors="strict"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise BrokerPhaseProtocolError("outer broker runtime probe is invalid") from exc
    if runtime.name == "podman":
        try:
            security = probed["host"]["security"]
            rootless = security["rootless"]
            seccomp_enabled = security["seccompEnabled"]
            seccomp_profile = security["seccompProfilePath"]
        except (KeyError, TypeError) as exc:
            raise BrokerPhaseProtocolError("outer broker runtime probe is invalid") from exc
        user_namespace = True
    else:
        if not isinstance(probed, list) or not all(isinstance(item, str) for item in probed):
            raise BrokerPhaseProtocolError("outer broker runtime probe is invalid")
        normalized = {item.casefold() for item in probed}
        rootless = any("rootless" in item for item in normalized)
        user_namespace = rootless or any("userns" in item for item in normalized)
        seccomp_enabled = any(
            item.startswith("name=seccomp,") and "profile=builtin" in item for item in normalized
        )
        seccomp_profile = "builtin"
    if (
        rootless is not runtime.rootless
        or user_namespace is not runtime.user_namespace
        or seccomp_enabled is not True
        or seccomp_profile != runtime.seccomp_profile
    ):
        raise BrokerPhaseProtocolError("outer broker runtime probe is invalid")
    return payload, measured_path


def _decode_frozen_ledger(
    payload: object,
    *,
    batch: PreparedBrokerBatch,
) -> BrokerLedgerEvidence:
    fields = {
        "broker_ledger_identity_sha256",
        "broker_packet_cost_limit_microusd",
        "broker_packet_reservation_limit",
        "broker_pricing_policy_sha256",
        "cumulative_reserved_cost_microusd",
        "cumulative_reserved_tokens",
        "final_ledger_sha256",
        "ledger_device",
        "ledger_inode",
        "ledger_path",
        "measured_unix_ns",
        "packet_sha256",
        "records",
        "records_sha256",
        "schema_version",
    }
    if not isinstance(payload, dict) or set(payload) != fields:
        raise BrokerPhaseProtocolError("outer broker frozen ledger is invalid")
    unsigned = {key: value for key, value in payload.items() if key != "final_ledger_sha256"}
    if (
        payload["schema_version"] != "1.0"
        or not _is_sha256(payload["final_ledger_sha256"])
        or payload["final_ledger_sha256"] != _domain_sha256(_FROZEN_LEDGER_DOMAIN, unsigned)
        or payload["broker_ledger_identity_sha256"] != batch.broker_ledger_identity_sha256
        or payload["packet_sha256"] != batch.review_packet_sha256
        or payload["broker_packet_reservation_limit"] != batch.broker_packet_reservation_limit
        or payload["broker_packet_cost_limit_microusd"] != batch.broker_packet_cost_limit_microusd
        or payload["broker_pricing_policy_sha256"] != batch.broker_pricing_policy_sha256
        or not isinstance(payload["ledger_path"], str)
        or not Path(payload["ledger_path"]).is_absolute()
        or not isinstance(payload["records"], list)
        or not payload["records"]
    ):
        raise BrokerPhaseProtocolError("outer broker frozen ledger binding is invalid")
    record_fields = {
        "attempt",
        "packet_sha256",
        "reservation_unix_ns",
        "reserved_cost_microusd",
        "reserved_tokens",
        "role",
    }
    if any(
        not isinstance(record, dict) or set(record) != record_fields
        for record in payload["records"]
    ):
        raise BrokerPhaseProtocolError("outer broker frozen ledger records are invalid")
    rows = [
        (
            record["packet_sha256"],
            record["role"],
            record["attempt"],
            record["reserved_tokens"],
            record["reserved_cost_microusd"],
            record["reservation_unix_ns"],
        )
        for record in payload["records"]
    ]
    ledger = _build_ledger_evidence(
        ledger_path=Path(payload["ledger_path"]),
        ledger_device=payload["ledger_device"],
        ledger_inode=payload["ledger_inode"],
        ledger_identity_sha256=batch.broker_ledger_identity_sha256,
        packet_sha256=batch.review_packet_sha256,
        packet_reservation_limit=batch.broker_packet_reservation_limit,
        packet_cost_limit_microusd=batch.broker_packet_cost_limit_microusd,
        pricing_policy_sha256=batch.broker_pricing_policy_sha256,
        rows=rows,
        measured_unix_ns=payload["measured_unix_ns"],
    )
    if (
        ledger.records_sha256 != payload["records_sha256"]
        or ledger.cumulative_reserved_tokens != payload["cumulative_reserved_tokens"]
        or ledger.cumulative_reserved_cost_microusd != payload["cumulative_reserved_cost_microusd"]
    ):
        raise BrokerPhaseProtocolError("outer broker frozen ledger totals are invalid")
    validate_frozen_broker_ledger_evidence(
        ledger,
        expected_packet_sha256=batch.review_packet_sha256,
        broker_packet_reservation_limit=batch.broker_packet_reservation_limit,
        expected_broker_ledger_identity_sha256=batch.broker_ledger_identity_sha256,
        broker_packet_cost_limit_microusd=batch.broker_packet_cost_limit_microusd,
        broker_pricing_policy_sha256=batch.broker_pricing_policy_sha256,
    )
    return ledger


def _decode_reservation(
    payload: object,
    *,
    batch: PreparedBrokerBatch,
    run: PreparedBrokerRun,
    final_ledger: BrokerLedgerEvidence,
):
    fields = {
        "broker_ledger_identity_sha256",
        "cumulative_reserved_cost_microusd",
        "cumulative_reserved_tokens",
        "ledger_device",
        "ledger_inode",
        "measured_unix_ns",
        "records",
        "reservation_unix_ns",
    }
    if not isinstance(payload, dict) or set(payload) != fields:
        raise BrokerPhaseProtocolError("outer broker reservation is invalid")
    raw_records = payload["records"]
    if not isinstance(raw_records, list) or not raw_records:
        raise BrokerPhaseProtocolError("outer broker reservation records are invalid")
    record_fields = {
        "attempt",
        "packet_sha256",
        "reservation_unix_ns",
        "reserved_cost_microusd",
        "reserved_tokens",
        "role",
    }
    records: list[dict[str, int | str]] = []
    for raw_record in raw_records:
        if not isinstance(raw_record, dict) or set(raw_record) != record_fields:
            raise BrokerPhaseProtocolError("outer broker reservation records are invalid")
        records.append(dict(raw_record))
    if records != sorted(records, key=lambda value: (str(value["role"]), int(value["attempt"]))):
        raise BrokerPhaseProtocolError("outer broker reservation records are reordered")
    matching = [
        record
        for record in records
        if record["role"] == run.role and record["attempt"] == run.attempt
    ]
    if (
        payload["broker_ledger_identity_sha256"] != batch.broker_ledger_identity_sha256
        or payload["ledger_device"] != final_ledger.ledger_device
        or payload["ledger_inode"] != final_ledger.ledger_inode
        or isinstance(payload["ledger_device"], bool)
        or not isinstance(payload["ledger_device"], int)
        or isinstance(payload["ledger_inode"], bool)
        or not isinstance(payload["ledger_inode"], int)
        or payload["ledger_inode"] <= 0
        or isinstance(payload["measured_unix_ns"], bool)
        or not isinstance(payload["measured_unix_ns"], int)
        or payload["measured_unix_ns"] <= 0
        or len(matching) != 1
        or matching[0]["packet_sha256"] != run.packet_sha256
        or matching[0]["reserved_tokens"] != run.reserved_tokens
        or matching[0]["reserved_cost_microusd"] != run.reserved_cost_microusd
        or matching[0]["reservation_unix_ns"] != payload["reservation_unix_ns"]
    ):
        raise BrokerPhaseProtocolError("outer broker reservation is invalid")
    rows = [
        (
            record["packet_sha256"],
            record["role"],
            record["attempt"],
            record["reserved_tokens"],
            record["reserved_cost_microusd"],
            record["reservation_unix_ns"],
        )
        for record in records
    ]
    ledger = _build_ledger_evidence(
        ledger_path=final_ledger.ledger_path,
        ledger_device=payload["ledger_device"],
        ledger_inode=payload["ledger_inode"],
        ledger_identity_sha256=batch.broker_ledger_identity_sha256,
        packet_sha256=run.packet_sha256,
        packet_reservation_limit=batch.broker_packet_reservation_limit,
        packet_cost_limit_microusd=batch.broker_packet_cost_limit_microusd,
        pricing_policy_sha256=batch.broker_pricing_policy_sha256,
        rows=rows,
        measured_unix_ns=payload["measured_unix_ns"],
    )
    if (
        ledger.cumulative_reserved_tokens != payload["cumulative_reserved_tokens"]
        or ledger.cumulative_reserved_cost_microusd != payload["cumulative_reserved_cost_microusd"]
    ):
        raise BrokerPhaseProtocolError("outer broker reservation totals are invalid")
    try:
        validate_frozen_broker_ledger_evidence(
            ledger,
            expected_packet_sha256=run.packet_sha256,
            broker_packet_reservation_limit=batch.broker_packet_reservation_limit,
            expected_broker_ledger_identity_sha256=batch.broker_ledger_identity_sha256,
            broker_packet_cost_limit_microusd=batch.broker_packet_cost_limit_microusd,
            broker_pricing_policy_sha256=batch.broker_pricing_policy_sha256,
        )
    except BrokerExecutionError as exc:
        raise BrokerPhaseProtocolError("outer broker frozen ledger validation failed") from exc
    return ledger, matching[0]


def _expected_lifecycle_argv(
    *,
    backend: ContainerBackend,
    invocation: IsolatedBrokerInvocation,
    gateway_name: str,
    external_network: str,
    gateway_image: str,
    owner_sha256: str,
    session_sha256: str,
) -> tuple[tuple[tuple[str, ...], ...], ...]:
    preflight = (
        _container_absence_argv(backend, gateway_name),
        _network_absence_argv(backend, invocation.broker_internal_network),
        _network_absence_argv(backend, external_network),
    )
    provision = (
        *preflight,
        _network_create_argv(
            backend,
            name=invocation.broker_internal_network,
            internal=True,
            owner_sha256=owner_sha256,
            session_sha256=session_sha256,
            kind="broker-internal",
        ),
        _network_create_argv(
            backend,
            name=external_network,
            internal=False,
            owner_sha256=owner_sha256,
            session_sha256=session_sha256,
            kind="gateway-external",
        ),
        _gateway_run_argv(
            backend,
            gateway_name=gateway_name,
            external_network=external_network,
            gateway_image=gateway_image,
            owner_sha256=owner_sha256,
            session_sha256=session_sha256,
        ),
        _network_connect_argv(
            backend,
            internal_network=invocation.broker_internal_network,
            gateway_name=gateway_name,
        ),
        _network_inspect_argv(backend, invocation.broker_internal_network),
        _network_inspect_argv(backend, external_network),
        _container_inspect_argv(backend, gateway_name),
    )
    post = provision[-3:]
    cleanup = (
        _container_inspect_argv(backend, gateway_name),
        _container_remove_argv(backend, gateway_name),
        _network_inspect_argv(backend, invocation.broker_internal_network),
        _network_remove_argv(backend, invocation.broker_internal_network),
        _network_inspect_argv(backend, external_network),
        _network_remove_argv(backend, external_network),
    )
    absence = preflight
    return provision, post, cleanup, absence


def _construct_provisioned_evidence(
    *,
    batch: PreparedBrokerBatch,
    run: PreparedBrokerRun,
    raw: dict[str, Any],
    allowlist_policy: bytes,
    final_ledger: BrokerLedgerEvidence,
) -> ProvisionedBrokerExecutionEvidence:
    run_fields = {
        "broker_cleanup_command",
        "broker_command",
        "broker_started_unix_ns",
        "cleanup_commands",
        "cleanup_succeeded",
        "descriptor_sha256",
        "duration_ms",
        "environment_sha256",
        "gateway_container_name",
        "gateway_external_network",
        "owner_sha256",
        "post_cleanup_absence_commands",
        "post_execution_inspect_commands",
        "provisioning_commands",
        "reservation",
        "role",
        "run_evidence_sha256",
        "runtime_post",
        "runtime_pre",
        "schema_version",
        "session_sha256",
        "started_unix_ns",
    }
    if set(raw) != run_fields:
        raise BrokerPhaseProtocolError("outer broker run has missing or unknown fields")
    unsigned = {key: value for key, value in raw.items() if key != "run_evidence_sha256"}
    if (
        raw["schema_version"] != "1.0"
        or raw["descriptor_sha256"] != run.descriptor_sha256
        or raw["role"] != run.role
        or not _is_sha256(raw["session_sha256"])
        or not _is_sha256(raw["owner_sha256"])
        or not _is_sha256(raw["environment_sha256"])
        or raw["environment_sha256"] != batch.runtime.environment_sha256
        or raw["cleanup_succeeded"] is not True
        or not _is_sha256(raw["run_evidence_sha256"])
        or raw["run_evidence_sha256"] != _domain_sha256(_OUTER_RUN_DOMAIN, unsigned)
    ):
        raise BrokerPhaseProtocolError("outer broker run binding is invalid")
    invocation = run.invocation()
    pre_runtime, runtime_path = _decode_runtime_measurement(
        raw["runtime_pre"], runtime=batch.runtime, runtime_path=None
    )
    post_runtime, post_runtime_path = _decode_runtime_measurement(
        raw["runtime_post"], runtime=batch.runtime, runtime_path=runtime_path
    )
    if (
        post_runtime_path != runtime_path
        or pre_runtime["device"] != post_runtime["device"]
        or pre_runtime["inode"] != post_runtime["inode"]
    ):
        raise BrokerPhaseProtocolError("outer broker runtime changed during execution")
    backend = ContainerBackend(
        name=batch.runtime.name,
        executable=runtime_path,
        rootless=batch.runtime.rootless,
        user_namespace=batch.runtime.user_namespace,
        seccomp_enabled=True,
        seccomp_profile=batch.runtime.seccomp_profile,
        sha256=batch.runtime.executable_sha256,
        security_evidence_sha256=batch.runtime.security_evidence_sha256,
    )
    gateway_name = _gateway_name(invocation)
    external_network = broker_gateway_external_network_name(invocation)
    owner_sha256 = _owner_sha256(invocation)
    if (
        raw["gateway_container_name"] != gateway_name
        or raw["gateway_external_network"] != external_network
        or raw["owner_sha256"] != owner_sha256
    ):
        raise BrokerPhaseProtocolError("outer broker lifecycle names are invalid")
    groups = []
    for name in (
        "provisioning_commands",
        "post_execution_inspect_commands",
        "cleanup_commands",
        "post_cleanup_absence_commands",
    ):
        value = raw[name]
        if not isinstance(value, list):
            raise BrokerPhaseProtocolError("outer broker lifecycle commands are invalid")
        groups.append(tuple(_decode_raw_command(item) for item in value))
    provisioning_commands, post_commands, cleanup_commands, absence_commands = groups
    expected_groups = _expected_lifecycle_argv(
        backend=backend,
        invocation=invocation,
        gateway_name=gateway_name,
        external_network=external_network,
        gateway_image=batch.gateway_image,
        owner_sha256=owner_sha256,
        session_sha256=raw["session_sha256"],
    )
    if any(
        tuple(record.argv for record in records) != expected
        for records, expected in zip(groups, expected_groups, strict=True)
    ):
        raise BrokerPhaseProtocolError("outer broker lifecycle argv is invalid")
    if (
        len(provisioning_commands) != 10
        or len(post_commands) != 3
        or len(cleanup_commands) != 6
        or len(absence_commands) != 3
        or any(
            record.exit_code != 0
            for record in (
                *provisioning_commands,
                *post_commands,
                *cleanup_commands,
                *absence_commands,
            )
        )
        or any(record.stdout for record in provisioning_commands[:3])
        or any(record.stdout for record in absence_commands)
    ):
        raise BrokerPhaseProtocolError("outer broker lifecycle command result is invalid")
    session_sha256 = raw["session_sha256"]
    pre_internal = _validate_network_inspect(
        provisioning_commands[-3].stdout,
        expected_name=invocation.broker_internal_network,
        expected_internal=True,
        expected_gateway_name=gateway_name,
        owner_sha256=owner_sha256,
        session_sha256=session_sha256,
        kind="broker-internal",
    )
    pre_external = _validate_network_inspect(
        provisioning_commands[-2].stdout,
        expected_name=external_network,
        expected_internal=False,
        expected_gateway_name=gateway_name,
        owner_sha256=owner_sha256,
        session_sha256=session_sha256,
        kind="gateway-external",
    )
    pre_gateway = _validate_gateway_inspect(
        provisioning_commands[-1].stdout,
        gateway_name=gateway_name,
        gateway_image=batch.gateway_image,
        internal_network=invocation.broker_internal_network,
        external_network=external_network,
        owner_sha256=owner_sha256,
        session_sha256=session_sha256,
        require_running=True,
    )
    if (
        _validate_network_inspect(
            post_commands[0].stdout,
            expected_name=invocation.broker_internal_network,
            expected_internal=True,
            expected_gateway_name=gateway_name,
            owner_sha256=owner_sha256,
            session_sha256=session_sha256,
            kind="broker-internal",
        )
        != pre_internal
        or _validate_network_inspect(
            post_commands[1].stdout,
            expected_name=external_network,
            expected_internal=False,
            expected_gateway_name=gateway_name,
            owner_sha256=owner_sha256,
            session_sha256=session_sha256,
            kind="gateway-external",
        )
        != pre_external
        or _validate_gateway_inspect(
            post_commands[2].stdout,
            gateway_name=gateway_name,
            gateway_image=batch.gateway_image,
            internal_network=invocation.broker_internal_network,
            external_network=external_network,
            owner_sha256=owner_sha256,
            session_sha256=session_sha256,
            require_running=False,
        )
        != pre_gateway
    ):
        raise BrokerPhaseProtocolError("outer broker post-inspect boundary changed")
    _validate_owned_resource_inspect(
        cleanup_commands[0].stdout,
        resource_type="container",
        expected_name=gateway_name,
        expected_kind="gateway",
        owner_sha256=owner_sha256,
        session_sha256=session_sha256,
    )
    _validate_owned_resource_inspect(
        cleanup_commands[2].stdout,
        resource_type="network",
        expected_name=invocation.broker_internal_network,
        expected_kind="broker-internal",
        owner_sha256=owner_sha256,
        session_sha256=session_sha256,
    )
    _validate_owned_resource_inspect(
        cleanup_commands[4].stdout,
        resource_type="network",
        expected_name=external_network,
        expected_kind="gateway-external",
        owner_sha256=owner_sha256,
        session_sha256=session_sha256,
    )
    provisioning = _canonical_json(
        {
            "broker_internal_network": invocation.broker_internal_network,
            "commands": [item.evidence_sha256 for item in provisioning_commands],
            "environment_sha256": raw["environment_sha256"],
            "gateway_alias": GATEWAY_ALIAS,
            "gateway_external_network": external_network,
            "gateway_external_network_inspect_sha256": _sha256(pre_external),
            "gateway_port": GATEWAY_PORT,
            "owner_sha256": owner_sha256,
            "runtime_executable": str(runtime_path),
            "runtime_security_sha256": batch.runtime.security_evidence_sha256,
            "runtime_sha256": batch.runtime.executable_sha256,
            "schema_version": "1.0",
            "session_sha256": session_sha256,
        }
    )
    boundary = EgressBoundaryEvidence(
        schema_version="1.0",
        runtime_name=batch.runtime.name,
        broker_internal_network=invocation.broker_internal_network,
        broker_network_inspect=pre_internal,
        broker_network_inspect_sha256=_sha256(pre_internal),
        gateway_container_name=gateway_name,
        gateway_image=batch.gateway_image,
        broker_gateway_image_digest=batch.broker_gateway_image_digest,
        gateway_container_inspect=pre_gateway,
        gateway_container_inspect_sha256=_sha256(pre_gateway),
        allowlist_policy=allowlist_policy,
        broker_allowlist_policy_sha256=batch.broker_allowlist_policy_sha256,
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
    boundary = replace(
        boundary,
        broker_egress_boundary_sha256=broker_egress_boundary_sha256(boundary),
    )
    if (
        isinstance(raw["started_unix_ns"], bool)
        or not isinstance(raw["started_unix_ns"], int)
        or raw["started_unix_ns"] <= 0
        or isinstance(raw["duration_ms"], bool)
        or not isinstance(raw["duration_ms"], int)
        or not 0 <= raw["duration_ms"] <= MAX_BROKER_TIMEOUT_SECONDS * 2_000
    ):
        raise BrokerPhaseProtocolError("outer broker lifecycle timing is invalid")
    lifecycle = BrokerEgressLifecycleEvidence(
        schema_version="1.0",
        runtime_name=batch.runtime.name,
        runtime_executable=runtime_path,
        runtime_pre_sha256=batch.runtime.executable_sha256,
        runtime_pre_security_sha256=batch.runtime.security_evidence_sha256,
        runtime_post_sha256=batch.runtime.executable_sha256,
        runtime_post_security_sha256=batch.runtime.security_evidence_sha256,
        runtime_rootless=batch.runtime.rootless,
        runtime_user_namespace=batch.runtime.user_namespace,
        runtime_seccomp_profile=batch.runtime.seccomp_profile,
        environment_sha256=raw["environment_sha256"],
        session_sha256=session_sha256,
        broker_internal_network=invocation.broker_internal_network,
        gateway_external_network=external_network,
        gateway_container_name=gateway_name,
        gateway_image=batch.gateway_image,
        broker_gateway_image_digest=batch.broker_gateway_image_digest,
        broker_allowlist_policy_sha256=batch.broker_allowlist_policy_sha256,
        boundary_evidence=boundary,
        gateway_external_network_inspect=pre_external,
        gateway_external_network_inspect_sha256=_sha256(pre_external),
        provisioning_commands=provisioning_commands,
        post_execution_inspect_commands=post_commands,
        cleanup_commands=cleanup_commands,
        post_cleanup_absence_commands=absence_commands,
        started_unix_ns=raw["started_unix_ns"],
        duration_ms=raw["duration_ms"],
        cleanup_succeeded=True,
        evidence_sha256="0" * 64,
    )
    lifecycle = replace(lifecycle, evidence_sha256=_lifecycle_sha256(lifecycle))

    ledger, reservation_record = _decode_reservation(
        raw["reservation"], batch=batch, run=run, final_ledger=final_ledger
    )
    broker_command = _decode_raw_command(raw["broker_command"])
    broker_cleanup = _decode_raw_command(raw["broker_cleanup_command"])
    expected_broker_argv = (str(runtime_path), *run.descriptor_argv[1:])
    expected_cleanup_argv = (str(runtime_path), "rm", "-f", "--", run.container_name)
    if (
        broker_command.argv != expected_broker_argv
        or broker_command.exit_code != 0
        or len(broker_command.stdout) > batch.max_stdout_bytes
        or len(broker_command.stderr) > batch.max_stderr_bytes
        or broker_cleanup.argv != expected_cleanup_argv
        or broker_cleanup.exit_code != 0
        or isinstance(raw["broker_started_unix_ns"], bool)
        or not isinstance(raw["broker_started_unix_ns"], int)
        or raw["broker_started_unix_ns"] <= 0
    ):
        raise BrokerPhaseProtocolError("outer broker process evidence is invalid")
    response_sha256, request_id = _parse_canonical_envelope(
        broker_command.stdout,
        request_sha256=run.request_sha256,
    )
    process_result = _BrokerProcessResult(
        exit_code=broker_command.exit_code,
        stdout=broker_command.stdout,
        stderr=broker_command.stderr,
        stdout_sha256=broker_command.stdout_sha256,
        stderr_sha256=broker_command.stderr_sha256,
        duration_ms=broker_command.duration_ms,
    )
    cleanup_result = _CleanupResult(
        argv=broker_cleanup.argv,
        exit_code=broker_cleanup.exit_code,
        duration_ms=broker_cleanup.duration_ms,
        succeeded=True,
    )
    executed_argv_sha256 = _sha256(_canonical_json(list(expected_broker_argv)))
    reservation_record_sha256 = _reservation_record_sha256(reservation_record)
    evidence_sha256 = _evidence_sha256(
        invocation=invocation,
        before=backend,
        after=backend,
        executed_argv=expected_broker_argv,
        executed_argv_sha256=executed_argv_sha256,
        cumulative_reserved_tokens=ledger.cumulative_reserved_tokens,
        reserved_cost_microusd=run.reserved_cost_microusd,
        ledger_evidence=ledger,
        reservation_record_sha256=reservation_record_sha256,
        egress_boundary=boundary,
        result=process_result,
        started_unix_ns=raw["broker_started_unix_ns"],
        response_sha256=response_sha256,
        request_id=request_id,
        cleanup_result=cleanup_result,
    )
    execution = BrokerExecutionEvidence(
        schema_version="1.0",
        packet_sha256=run.packet_sha256,
        request_sha256=run.request_sha256,
        boundary_evidence_sha256=run.boundary_evidence_sha256,
        role=run.role,
        attempt=run.attempt,
        reserved_tokens=run.reserved_tokens,
        reserved_cost_microusd=run.reserved_cost_microusd,
        cumulative_reserved_tokens=ledger.cumulative_reserved_tokens,
        cumulative_reserved_cost_microusd=ledger.cumulative_reserved_cost_microusd,
        reservation_record_sha256=reservation_record_sha256,
        broker_packet_reservation_limit=batch.broker_packet_reservation_limit,
        broker_packet_cost_limit_microusd=batch.broker_packet_cost_limit_microusd,
        broker_pricing_policy_sha256=batch.broker_pricing_policy_sha256,
        broker_ledger_identity_sha256=batch.broker_ledger_identity_sha256,
        broker_egress_boundary_sha256=boundary.broker_egress_boundary_sha256,
        ledger=ledger,
        broker_egress_boundary=boundary,
        runtime_name=batch.runtime.name,
        runtime_executable=runtime_path,
        runtime_sha256=batch.runtime.executable_sha256,
        runtime_security_sha256=batch.runtime.security_evidence_sha256,
        runtime_pre_sha256=batch.runtime.executable_sha256,
        runtime_pre_security_sha256=batch.runtime.security_evidence_sha256,
        runtime_post_sha256=batch.runtime.executable_sha256,
        runtime_post_security_sha256=batch.runtime.security_evidence_sha256,
        runtime_rootless=batch.runtime.rootless,
        runtime_user_namespace=batch.runtime.user_namespace,
        runtime_seccomp_profile=batch.runtime.seccomp_profile,
        image=run.image,
        approved_image_digest=run.approved_image_digest,
        container_name=run.container_name,
        descriptor_argv=run.descriptor_argv,
        descriptor_argv_sha256=run.descriptor_argv_sha256,
        argv=expected_broker_argv,
        argv_sha256=executed_argv_sha256,
        stdin=run.stdin,
        stdin_sha256=run.stdin_sha256,
        exit_code=broker_command.exit_code,
        stdout=broker_command.stdout,
        stderr=broker_command.stderr,
        stdout_sha256=broker_command.stdout_sha256,
        stderr_sha256=broker_command.stderr_sha256,
        started_unix_ns=raw["broker_started_unix_ns"],
        duration_ms=broker_command.duration_ms,
        cleanup_succeeded=True,
        cleanup_argv=broker_cleanup.argv,
        cleanup_argv_sha256=_sha256(_canonical_json(list(broker_cleanup.argv))),
        cleanup_exit_code=broker_cleanup.exit_code,
        cleanup_duration_ms=broker_cleanup.duration_ms,
        canonical_envelope=broker_command.stdout,
        response_sha256=response_sha256,
        request_id=request_id,
        evidence_sha256=evidence_sha256,
    )
    provisioned = ProvisionedBrokerExecutionEvidence(
        schema_version="1.0",
        execution=execution,
        egress_lifecycle=lifecycle,
        execution_evidence_sha256=execution.evidence_sha256,
        broker_egress_lifecycle_sha256=lifecycle.evidence_sha256,
        evidence_sha256="0" * 64,
    )
    return replace(
        provisioned,
        evidence_sha256=_provisioned_execution_sha256(provisioned),
    )


def _finalize_provisioned_broker_execution(
    prepared_batch: PreparedBrokerBatch | bytes,
    outer_evidence: bytes,
    *,
    allowlist_policy: bytes,
    pricing_policy: bytes,
    require_two: bool,
) -> tuple[ProvisionedBrokerExecutionEvidence, ...]:
    """Reconstruct exact typed evidence and its frozen protected-ledger snapshot.

    No runtime socket is needed in the coordinator.  Raw pre/post probes and inspect streams are
    semantically re-parsed here.  The protected outer process freezes the final ledger into this
    same canonical, batch-bound stream so a later coordinator namespace never substitutes a path.
    """

    try:
        prepared_raw = (
            prepared_batch
            if isinstance(prepared_batch, bytes)
            else canonical_prepared_broker_batch_bytes(prepared_batch)
        )
        batch = _parse_prepared_broker_batch(prepared_raw, require_two=require_two)
        if (
            validate_broker_egress_policy(allowlist_policy) != batch.broker_allowlist_policy_sha256
            or validate_openai_pricing_policy(pricing_policy).sha256
            != batch.broker_pricing_policy_sha256
        ):
            raise BrokerPhaseProtocolError("broker finalize policy binding is invalid")
        payload = _strict_json(outer_evidence, label="outer broker evidence")
        fields = {
            "batch_sha256",
            "duration_ms",
            "final_ledger",
            "outer_evidence_sha256",
            "runs",
            "schema_version",
            "started_unix_ns",
        }
        if set(payload) != fields:
            raise BrokerPhaseProtocolError("outer broker evidence has missing or unknown fields")
        unsigned = {key: value for key, value in payload.items() if key != "outer_evidence_sha256"}
        if (
            payload["schema_version"] != "1.0"
            or payload["batch_sha256"] != batch.batch_sha256
            or not _is_sha256(payload["outer_evidence_sha256"])
            or payload["outer_evidence_sha256"] != _domain_sha256(_OUTER_BATCH_DOMAIN, unsigned)
            or not isinstance(payload["runs"], list)
            or len(payload["runs"]) != len(batch.runs)
        ):
            raise BrokerPhaseProtocolError("outer broker evidence binding is invalid")
        raw_roles = [
            value.get("role") if isinstance(value, dict) else None for value in payload["runs"]
        ]
        if raw_roles != [run.role for run in batch.runs]:
            raise BrokerPhaseProtocolError("outer broker evidence is duplicated or reordered")
        final_ledger = _decode_frozen_ledger(payload["final_ledger"], batch=batch)
        results = tuple(
            _construct_provisioned_evidence(
                batch=batch,
                run=run,
                raw=raw,
                allowlist_policy=allowlist_policy,
                final_ledger=final_ledger,
            )
            for run, raw in zip(batch.runs, payload["runs"], strict=True)
        )
        if require_two:
            validate_successful_broker_executions_against_final_ledger(
                tuple(item.execution for item in results),
                final_ledger,
            )
        elif (
            len(results) != 1
            or results[0].execution.ledger.records != final_ledger.records
            or results[0].execution.ledger.records_sha256 != final_ledger.records_sha256
        ):
            raise BrokerPhaseProtocolError("single broker ledger finalization failed")
        return results
    except BrokerPhaseProtocolError:
        raise
    except (
        BrokerExecutionError,
        BrokerEgressProvisioningError,
        OSError,
        TypeError,
        ValueError,
    ) as exc:
        raise BrokerPhaseProtocolError("broker outer evidence finalization failed") from exc


def finalize_provisioned_broker_execution(
    prepared_batch: PreparedBrokerBatch | bytes,
    outer_evidence: bytes,
    *,
    allowlist_policy: bytes,
    pricing_policy: bytes,
) -> tuple[ProvisionedBrokerExecutionEvidence, ProvisionedBrokerExecutionEvidence]:
    """Finalize the exact reviewer/adversary batch without a host-ledger pathname."""

    results = _finalize_provisioned_broker_execution(
        prepared_batch,
        outer_evidence,
        allowlist_policy=allowlist_policy,
        pricing_policy=pricing_policy,
        require_two=True,
    )
    return results[0], results[1]
