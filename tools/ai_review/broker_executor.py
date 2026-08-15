"""Fail-closed executor for the packet-only network broker.

The candidate never receives this credential or container runtime.  The coordinator remeasures
the protected runtime immediately before and after one exact, mountless invocation, reserves the
attempt budget durably before launch, and returns raw evidence instead of trusting a descriptor's
claims.  This module deliberately contains no API client.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import selectors
import shutil
import signal
import sqlite3
import stat
import subprocess
import time
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from typing import Callable

from tools.ai_review.broker_entry import BrokerError
from tools.ai_review.broker_entry import canonical_request_bytes
from tools.ai_review.codex_adapter import BROKER_CREDENTIAL_ENV
from tools.ai_review.codex_adapter import BROKER_INTERNAL_NETWORK_PREFIX
from tools.ai_review.codex_adapter import CONTEXT_WINDOW_TOKENS
from tools.ai_review.codex_adapter import MAX_OUTPUT_TOKENS
from tools.ai_review.codex_adapter import IsolatedBrokerInvocation
from tools.ai_review.offline_runner import ContainerBackend
from tools.ai_review.offline_runner import OfflineRunnerError
from tools.ai_review.offline_runner import _base_host_environment
from tools.ai_review.offline_runner import detect_container_backend
from tools.ai_review.preflight import PreflightError
from tools.ai_review.preflight import assert_candidate_cannot_mutate
from tools.ai_review.pricing_policy import ABSOLUTE_PACKET_COST_LIMIT_MICROUSD
from tools.ai_review.pricing_policy import APPROVED_OPENAI_PRICING_POLICY
from tools.ai_review.pricing_policy import DEFAULT_PACKET_COST_LIMIT_MICROUSD
from tools.ai_review.pricing_policy import PricingPolicyError
from tools.ai_review.pricing_policy import canonical_openai_pricing_policy_bytes
from tools.ai_review.pricing_policy import reserve_request_cost_microusd
from tools.ai_review.pricing_policy import validate_openai_pricing_policy


SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
IMAGE_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
PINNED_IMAGE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/:+-]*@sha256:[0-9a-f]{64}$")
MAX_PACKET_RESERVED_TOKENS = 4 * CONTEXT_WINDOW_TOKENS
MAX_BROKER_STDIN_BYTES = 1_000_001
MAX_BROKER_STDOUT_BYTES = 6_000_000
MAX_BROKER_STDERR_BYTES = 64_000
MAX_BROKER_TIMEOUT_SECONDS = 300
_EVIDENCE_DOMAIN = b"amazon-explorer-isolated-broker-execution-v1\0"
_LEDGER_IDENTITY_DOMAIN = b"amazon-explorer-broker-ledger-identity-v1\0"
_LEDGER_EVIDENCE_DOMAIN = b"amazon-explorer-broker-ledger-evidence-v1\0"
_RESERVATION_RECORD_DOMAIN = b"amazon-explorer-broker-reservation-record-v1\0"
_EGRESS_EVIDENCE_DOMAIN = b"amazon-explorer-broker-egress-boundary-v1\0"


class BrokerExecutionError(RuntimeError):
    """A deliberately generic executor failure that never includes secret or packet text."""


@dataclass(frozen=True)
class BrokerLedgerEvidence:
    """Canonical packet-wide reservation records from one protected SQLite ledger."""

    schema_version: str
    ledger_path: Path
    ledger_device: int
    ledger_inode: int
    broker_ledger_identity_sha256: str
    packet_sha256: str
    broker_packet_reservation_limit: int
    broker_packet_cost_limit_microusd: int
    broker_pricing_policy_sha256: str
    records: bytes
    records_sha256: str
    cumulative_reserved_tokens: int
    cumulative_reserved_cost_microusd: int
    measured_unix_ns: int
    evidence_sha256: str


@dataclass(frozen=True)
class EgressBoundaryEvidence:
    """Root-owned inspection result for the fixed internal-network TCP gateway topology.

    The separate egress measurer must interpret the raw inspect artifacts.  This executor only
    accepts its digest when the coordinator supplies the independently trusted expected digest.
    """

    schema_version: str
    runtime_name: str
    broker_internal_network: str
    broker_network_inspect: bytes
    broker_network_inspect_sha256: str
    gateway_container_name: str
    gateway_image: str
    broker_gateway_image_digest: str
    gateway_container_inspect: bytes
    gateway_container_inspect_sha256: str
    allowlist_policy: bytes
    broker_allowlist_policy_sha256: str
    provisioning: bytes
    provisioning_sha256: str
    api_host: str
    api_port: int
    gateway_network_alias: str
    gateway_port: int
    broker_network_internal_verified: bool
    broker_external_network_absent: bool
    broker_network_only_gateway_peer_verified: bool
    gateway_dual_homed_verified: bool
    gateway_network_alias_verified: bool
    gateway_tcp_proxy_verified: bool
    gateway_candidate_mounts_absent: bool
    gateway_broker_credential_absent: bool
    fixed_destination_verified: bool
    broker_egress_boundary_sha256: str


@dataclass(frozen=True)
class BrokerExecutionEvidence:
    """Raw, independently measured evidence for one consumed broker attempt."""

    schema_version: str
    packet_sha256: str
    request_sha256: str
    boundary_evidence_sha256: str
    role: str
    attempt: int
    reserved_tokens: int
    reserved_cost_microusd: int
    cumulative_reserved_tokens: int
    cumulative_reserved_cost_microusd: int
    reservation_record_sha256: str
    broker_packet_reservation_limit: int
    broker_packet_cost_limit_microusd: int
    broker_pricing_policy_sha256: str
    broker_ledger_identity_sha256: str
    broker_egress_boundary_sha256: str
    ledger: BrokerLedgerEvidence
    broker_egress_boundary: EgressBoundaryEvidence
    runtime_name: str
    runtime_executable: Path
    runtime_sha256: str
    runtime_security_sha256: str
    runtime_pre_sha256: str
    runtime_pre_security_sha256: str
    runtime_post_sha256: str
    runtime_post_security_sha256: str
    runtime_rootless: bool
    runtime_user_namespace: bool
    runtime_seccomp_profile: str
    image: str
    approved_image_digest: str
    container_name: str
    descriptor_argv: tuple[str, ...]
    descriptor_argv_sha256: str
    argv: tuple[str, ...]
    argv_sha256: str
    stdin: bytes
    stdin_sha256: str
    exit_code: int
    stdout: bytes
    stderr: bytes
    stdout_sha256: str
    stderr_sha256: str
    started_unix_ns: int
    duration_ms: int
    cleanup_succeeded: bool
    cleanup_argv: tuple[str, ...]
    cleanup_argv_sha256: str
    cleanup_exit_code: int
    cleanup_duration_ms: int
    canonical_envelope: bytes
    response_sha256: str
    request_id: str
    evidence_sha256: str


@dataclass(frozen=True)
class _BrokerProcessResult:
    exit_code: int
    stdout: bytes
    stderr: bytes
    stdout_sha256: str
    stderr_sha256: str
    duration_ms: int


@dataclass(frozen=True)
class _CleanupResult:
    argv: tuple[str, ...]
    exit_code: int
    duration_ms: int
    succeeded: bool


class _AttemptReservationRejected(Exception):
    pass


class _TokenReservationRejected(Exception):
    pass


class _CostReservationRejected(Exception):
    pass


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
        raise BrokerExecutionError("broker evidence canonicalization failed") from exc


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _is_sha256(value: object) -> bool:
    return isinstance(value, str) and SHA256_RE.fullmatch(value) is not None


def _system_which(name: str) -> str | None:
    return shutil.which(name, path=os.defpath)


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise BrokerExecutionError("broker canonical envelope validation failed")
        value[key] = item
    return value


def _validate_canonical_json_artifact(raw: bytes) -> None:
    if not isinstance(raw, bytes) or not 2 <= len(raw) <= 256_000:
        raise BrokerExecutionError("broker egress boundary validation failed")
    try:
        payload = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=_reject_duplicate_keys,
        )
    except (BrokerExecutionError, UnicodeError, json.JSONDecodeError) as exc:
        raise BrokerExecutionError("broker egress boundary validation failed") from exc
    try:
        canonical = _canonical_json(payload)
    except BrokerExecutionError as exc:
        raise BrokerExecutionError("broker egress boundary validation failed") from exc
    if not isinstance(payload, (dict, list)) or raw not in {canonical, canonical + b"\n"}:
        raise BrokerExecutionError("broker egress boundary validation failed")


def broker_egress_boundary_sha256(evidence: EgressBoundaryEvidence) -> str:
    """Recompute the canonical dynamic topology digest, excluding its digest field."""

    if type(evidence) is not EgressBoundaryEvidence:
        raise BrokerExecutionError("broker egress boundary validation failed")
    _validate_canonical_json_artifact(evidence.broker_network_inspect)
    _validate_canonical_json_artifact(evidence.gateway_container_inspect)
    _validate_canonical_json_artifact(evidence.allowlist_policy)
    _validate_canonical_json_artifact(evidence.provisioning)
    expected_gateway_name = (
        "ai-review-egress-gateway-" + evidence.broker_internal_network.rsplit("-", 1)[-1][-16:]
    )
    if (
        evidence.schema_version != "1.0"
        or evidence.runtime_name not in {"podman", "docker"}
        or re.fullmatch(
            re.escape(BROKER_INTERNAL_NETWORK_PREFIX) + r"[0-9a-f]{24}",
            evidence.broker_internal_network,
        )
        is None
        or evidence.gateway_container_name != expected_gateway_name
        or PINNED_IMAGE_RE.fullmatch(evidence.gateway_image) is None
        or IMAGE_DIGEST_RE.fullmatch(evidence.broker_gateway_image_digest) is None
        or evidence.gateway_image.rsplit("@", 1)[1] != evidence.broker_gateway_image_digest
        or evidence.broker_network_inspect_sha256 != _sha256(evidence.broker_network_inspect)
        or evidence.gateway_container_inspect_sha256 != _sha256(evidence.gateway_container_inspect)
        or evidence.broker_allowlist_policy_sha256 != _sha256(evidence.allowlist_policy)
        or evidence.provisioning_sha256 != _sha256(evidence.provisioning)
        or evidence.api_host != "api.openai.com"
        or evidence.api_port != 443
        or evidence.gateway_network_alias != "ai-review-egress-gateway"
        or evidence.gateway_port != 8443
        or BROKER_CREDENTIAL_ENV.encode("ascii") in evidence.gateway_container_inspect
        or BROKER_CREDENTIAL_ENV.encode("ascii") in evidence.allowlist_policy
        or any(
            value is not True
            for value in (
                evidence.broker_network_internal_verified,
                evidence.broker_external_network_absent,
                evidence.broker_network_only_gateway_peer_verified,
                evidence.gateway_dual_homed_verified,
                evidence.gateway_network_alias_verified,
                evidence.gateway_tcp_proxy_verified,
                evidence.gateway_candidate_mounts_absent,
                evidence.gateway_broker_credential_absent,
                evidence.fixed_destination_verified,
            )
        )
    ):
        raise BrokerExecutionError("broker egress boundary validation failed")
    payload = {
        "broker_allowlist_policy_sha256": evidence.broker_allowlist_policy_sha256,
        "api_host": evidence.api_host,
        "api_port": evidence.api_port,
        "broker_external_network_absent": evidence.broker_external_network_absent,
        "broker_internal_network": evidence.broker_internal_network,
        "broker_network_only_gateway_peer_verified": (
            evidence.broker_network_only_gateway_peer_verified
        ),
        "broker_network_inspect_sha256": evidence.broker_network_inspect_sha256,
        "broker_network_internal_verified": evidence.broker_network_internal_verified,
        "fixed_destination_verified": evidence.fixed_destination_verified,
        "gateway_broker_credential_absent": evidence.gateway_broker_credential_absent,
        "gateway_candidate_mounts_absent": evidence.gateway_candidate_mounts_absent,
        "gateway_container_inspect_sha256": evidence.gateway_container_inspect_sha256,
        "gateway_container_name": evidence.gateway_container_name,
        "gateway_dual_homed_verified": evidence.gateway_dual_homed_verified,
        "gateway_image": evidence.gateway_image,
        "broker_gateway_image_digest": evidence.broker_gateway_image_digest,
        "gateway_network_alias": evidence.gateway_network_alias,
        "gateway_network_alias_verified": evidence.gateway_network_alias_verified,
        "gateway_port": evidence.gateway_port,
        "gateway_tcp_proxy_verified": evidence.gateway_tcp_proxy_verified,
        "runtime_name": evidence.runtime_name,
        "provisioning_sha256": evidence.provisioning_sha256,
        "schema_version": "1.0",
    }
    return _sha256(_EGRESS_EVIDENCE_DOMAIN + _canonical_json(payload))


def validate_broker_egress_boundary_evidence(
    evidence: EgressBoundaryEvidence,
    *,
    expected_broker_egress_boundary_sha256: str,
    expected_broker_gateway_image_digest: str,
    expected_broker_allowlist_policy_sha256: str,
) -> EgressBoundaryEvidence:
    """Bind root-owned raw gateway inspection to trusted runtime-policy digests."""

    try:
        measured = broker_egress_boundary_sha256(evidence)
        if (
            not _is_sha256(expected_broker_egress_boundary_sha256)
            or IMAGE_DIGEST_RE.fullmatch(expected_broker_gateway_image_digest or "") is None
            or not _is_sha256(expected_broker_allowlist_policy_sha256)
            or evidence.broker_egress_boundary_sha256 != measured
            or not hmac.compare_digest(measured, expected_broker_egress_boundary_sha256)
            or not hmac.compare_digest(
                evidence.broker_gateway_image_digest,
                expected_broker_gateway_image_digest,
            )
            or not hmac.compare_digest(
                evidence.broker_allowlist_policy_sha256,
                expected_broker_allowlist_policy_sha256,
            )
        ):
            raise BrokerExecutionError("broker egress boundary validation failed")
        return evidence
    except BrokerExecutionError:
        raise
    except (TypeError, ValueError) as exc:
        raise BrokerExecutionError("broker egress boundary validation failed") from exc


def _revalidate_invocation(invocation: IsolatedBrokerInvocation) -> IsolatedBrokerInvocation:
    if type(invocation) is not IsolatedBrokerInvocation:
        raise BrokerExecutionError("broker invocation validation failed")
    try:
        measured = IsolatedBrokerInvocation(**vars(invocation))
    except (TypeError, ValueError, UnicodeError) as exc:
        raise BrokerExecutionError("broker invocation validation failed") from exc
    if measured != invocation:
        raise BrokerExecutionError("broker invocation validation failed")
    return measured


def _validate_request_stdin(invocation: IsolatedBrokerInvocation) -> bytes:
    try:
        raw = invocation.stdin_text.encode("utf-8", errors="strict")
        if not raw.endswith(b"\n") or raw.endswith((b"\n\n", b"\r\n")):
            raise BrokerExecutionError("broker invocation validation failed")
        payload = json.loads(
            raw[:-1].decode("utf-8", errors="strict"),
            object_pairs_hook=_reject_duplicate_keys,
        )
        canonical = canonical_request_bytes(payload)
    except BrokerExecutionError:
        raise
    except (BrokerError, UnicodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
        raise BrokerExecutionError("broker invocation validation failed") from exc
    if canonical + b"\n" != raw or not hmac.compare_digest(
        _sha256(canonical), invocation.request_sha256
    ):
        raise BrokerExecutionError("broker invocation validation failed")
    return raw


def _validate_trusted_bindings(
    invocation: IsolatedBrokerInvocation,
    *,
    expected_packet_sha256: str,
    expected_request_sha256: str,
    expected_boundary_evidence_sha256: str,
    expected_role: str,
    expected_attempt: int,
    approved_image_digest: str,
    expected_argv_sha256: str,
    expected_stdin_sha256: str,
) -> None:
    if (
        any(
            not _is_sha256(value)
            for value in (
                expected_packet_sha256,
                expected_request_sha256,
                expected_boundary_evidence_sha256,
                expected_argv_sha256,
                expected_stdin_sha256,
            )
        )
        or IMAGE_DIGEST_RE.fullmatch(approved_image_digest or "") is None
    ):
        raise BrokerExecutionError("broker trusted binding validation failed")
    pairs = (
        (invocation.packet_sha256, expected_packet_sha256),
        (invocation.request_sha256, expected_request_sha256),
        (invocation.boundary_evidence_sha256, expected_boundary_evidence_sha256),
        (invocation.approved_image_digest, approved_image_digest),
        (invocation.argv_sha256, expected_argv_sha256),
        (invocation.stdin_sha256, expected_stdin_sha256),
    )
    if any(not hmac.compare_digest(actual, expected) for actual, expected in pairs):
        raise BrokerExecutionError("broker trusted binding validation failed")
    if invocation.role != expected_role or invocation.attempt != expected_attempt:
        raise BrokerExecutionError("broker trusted binding validation failed")


def _validate_limits(
    *,
    timeout_seconds: int,
    max_stdin_bytes: int,
    max_stdout_bytes: int,
    max_stderr_bytes: int,
    packet_reservation_limit: int,
    packet_cost_limit_microusd: int,
) -> None:
    limits = (
        (timeout_seconds, 1, MAX_BROKER_TIMEOUT_SECONDS),
        (max_stdin_bytes, 2, MAX_BROKER_STDIN_BYTES),
        (max_stdout_bytes, 2, MAX_BROKER_STDOUT_BYTES),
        (max_stderr_bytes, 1, MAX_BROKER_STDERR_BYTES),
        (packet_reservation_limit, MAX_OUTPUT_TOKENS, MAX_PACKET_RESERVED_TOKENS),
        (
            packet_cost_limit_microusd,
            1,
            ABSOLUTE_PACKET_COST_LIMIT_MICROUSD,
        ),
    )
    if any(
        isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum
        for value, minimum, maximum in limits
    ):
        raise BrokerExecutionError("broker execution limits are invalid")


def _validate_credential(credential: str) -> None:
    if (
        not isinstance(credential, str)
        or not 1 <= len(credential) <= 512
        or any(ord(character) < 33 or ord(character) > 126 for character in credential)
    ):
        raise BrokerExecutionError("broker credential validation failed")


def _detect_exact_backend(
    invocation: IsolatedBrokerInvocation,
    *,
    candidate_uid: int,
    which: Callable[[str], str | None],
    probe: Callable[..., subprocess.CompletedProcess] | None,
    enforce_invocation_mode: bool = True,
) -> ContainerBackend:
    def selected_which(name: str) -> str | None:
        if name != invocation.container_runtime:
            return None
        return which(name)

    try:
        backend = detect_container_backend(
            candidate_uid=candidate_uid,
            which=selected_which,
            probe=probe,
        )
    except (OfflineRunnerError, OSError, TypeError, ValueError) as exc:
        raise BrokerExecutionError("broker runtime isolation validation failed") from exc
    if (
        backend.name != invocation.container_runtime
        or (
            enforce_invocation_mode
            and (
                backend.rootless is not invocation.runtime_rootless
                or backend.user_namespace is not invocation.runtime_user_namespace
            )
        )
        or backend.seccomp_enabled is not True
        or not backend.seccomp_profile
        or "unconfined" in backend.seccomp_profile.casefold()
    ):
        raise BrokerExecutionError("broker runtime isolation validation failed")
    return backend


def _same_backend(before: ContainerBackend, after: ContainerBackend) -> bool:
    return (
        before.name == after.name
        and before.executable == after.executable
        and hmac.compare_digest(before.sha256, after.sha256)
        and before.rootless is after.rootless
        and before.user_namespace is after.user_namespace
        and before.seccomp_enabled is after.seccomp_enabled is True
        and before.seccomp_profile == after.seccomp_profile
        and hmac.compare_digest(
            before.security_evidence_sha256,
            after.security_evidence_sha256,
        )
    )


def _ledger_identity(path: Path, *, candidate_uid: int) -> tuple[Path, int, int, str]:
    absolute = Path(os.path.abspath(path))
    try:
        trusted = assert_candidate_cannot_mutate(absolute, candidate_uid=candidate_uid)
        metadata = os.lstat(trusted)
    except (OSError, PreflightError) as exc:
        raise BrokerExecutionError("broker attempt ledger validation failed") from exc
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or stat.S_IMODE(metadata.st_mode) & 0o077
        or metadata.st_dev < 0
        or metadata.st_ino <= 0
    ):
        raise BrokerExecutionError("broker attempt ledger validation failed")
    payload = {
        "ledger_device": metadata.st_dev,
        "ledger_inode": metadata.st_ino,
        "ledger_path": str(trusted),
        "schema_version": "1.0",
    }
    identity_sha256 = _sha256(_LEDGER_IDENTITY_DOMAIN + _canonical_json(payload))
    return trusted, metadata.st_dev, metadata.st_ino, identity_sha256


def _validate_ledger_schema(connection: sqlite3.Connection) -> None:
    expected_columns = [
        ("packet_sha256", "TEXT", 1, 1),
        ("role", "TEXT", 1, 2),
        ("attempt", "INTEGER", 1, 3),
        ("reserved_tokens", "INTEGER", 1, 0),
        ("reserved_cost_microusd", "INTEGER", 1, 0),
        ("reservation_unix_ns", "INTEGER", 1, 0),
    ]
    columns = [
        (str(row[1]), str(row[2]), int(row[3]), int(row[5]))
        for row in connection.execute("PRAGMA table_info(broker_reservations)")
    ]
    if columns != expected_columns:
        raise BrokerExecutionError("broker attempt ledger validation failed")
    table_rows = [
        row for row in connection.execute("PRAGMA table_list") if row[1] == "broker_reservations"
    ]
    if len(table_rows) != 1 or int(table_rows[0][5]) != 1:
        raise BrokerExecutionError("broker attempt ledger validation failed")


def _reservation_record(
    *,
    packet_sha256: str,
    role: str,
    attempt: int,
    reserved_tokens: int,
    reserved_cost_microusd: int,
    reservation_unix_ns: int,
) -> dict[str, int | str]:
    return {
        "attempt": attempt,
        "packet_sha256": packet_sha256,
        "reservation_unix_ns": reservation_unix_ns,
        "reserved_tokens": reserved_tokens,
        "reserved_cost_microusd": reserved_cost_microusd,
        "role": role,
    }


def _reservation_record_sha256(record: dict[str, int | str]) -> str:
    return _sha256(_RESERVATION_RECORD_DOMAIN + _canonical_json(record))


def _build_ledger_evidence(
    *,
    ledger_path: Path,
    ledger_device: int,
    ledger_inode: int,
    ledger_identity_sha256: str,
    packet_sha256: str,
    packet_reservation_limit: int,
    packet_cost_limit_microusd: int,
    pricing_policy_sha256: str,
    rows: list[tuple[object, ...]],
    measured_unix_ns: int | None = None,
) -> BrokerLedgerEvidence:
    records: list[dict[str, int | str]] = []
    attempts: dict[str, list[int]] = {"reviewer": [], "adversary": []}
    for row in rows:
        if len(row) != 6:
            raise BrokerExecutionError("broker attempt ledger validation failed")
        packet, role, attempt, reserved_tokens, reserved_cost_microusd, reservation_unix_ns = row
        if (
            packet != packet_sha256
            or role not in attempts
            or isinstance(attempt, bool)
            or not isinstance(attempt, int)
            or not 1 <= attempt <= 2
            or isinstance(reserved_tokens, bool)
            or not isinstance(reserved_tokens, int)
            or not 1 <= reserved_tokens <= CONTEXT_WINDOW_TOKENS
            or isinstance(reserved_cost_microusd, bool)
            or not isinstance(reserved_cost_microusd, int)
            or not 1 <= reserved_cost_microusd <= ABSOLUTE_PACKET_COST_LIMIT_MICROUSD
            or isinstance(reservation_unix_ns, bool)
            or not isinstance(reservation_unix_ns, int)
            or reservation_unix_ns <= 0
        ):
            raise BrokerExecutionError("broker attempt ledger validation failed")
        attempts[role].append(attempt)
        records.append(
            _reservation_record(
                packet_sha256=packet,
                role=role,
                attempt=attempt,
                reserved_tokens=reserved_tokens,
                reserved_cost_microusd=reserved_cost_microusd,
                reservation_unix_ns=reservation_unix_ns,
            )
        )
    if any(values != list(range(1, len(values) + 1)) for values in attempts.values()):
        raise BrokerExecutionError("broker attempt ledger validation failed")
    cumulative = sum(int(record["reserved_tokens"]) for record in records)
    cumulative_cost = sum(int(record["reserved_cost_microusd"]) for record in records)
    if (
        cumulative > packet_reservation_limit
        or cumulative_cost > packet_cost_limit_microusd
        or pricing_policy_sha256 != APPROVED_OPENAI_PRICING_POLICY.sha256
    ):
        raise BrokerExecutionError("broker attempt ledger validation failed")
    raw_records = _canonical_json(
        {
            "packet_sha256": packet_sha256,
            "records": records,
            "schema_version": "1.0",
        }
    )
    records_sha256 = _sha256(raw_records)
    if measured_unix_ns is None:
        measured_unix_ns = time.time_ns()
    if (
        isinstance(measured_unix_ns, bool)
        or not isinstance(measured_unix_ns, int)
        or measured_unix_ns <= 0
    ):
        raise BrokerExecutionError("broker attempt ledger validation failed")
    payload = {
        "cumulative_reserved_tokens": cumulative,
        "cumulative_reserved_cost_microusd": cumulative_cost,
        "ledger_device": ledger_device,
        "broker_ledger_identity_sha256": ledger_identity_sha256,
        "ledger_inode": ledger_inode,
        "ledger_path": str(ledger_path),
        "measured_unix_ns": measured_unix_ns,
        "broker_packet_reservation_limit": packet_reservation_limit,
        "broker_packet_cost_limit_microusd": packet_cost_limit_microusd,
        "broker_pricing_policy_sha256": pricing_policy_sha256,
        "packet_sha256": packet_sha256,
        "records_sha256": records_sha256,
        "schema_version": "1.0",
    }
    return BrokerLedgerEvidence(
        schema_version="1.0",
        ledger_path=ledger_path,
        ledger_device=ledger_device,
        ledger_inode=ledger_inode,
        broker_ledger_identity_sha256=ledger_identity_sha256,
        packet_sha256=packet_sha256,
        broker_packet_reservation_limit=packet_reservation_limit,
        broker_packet_cost_limit_microusd=packet_cost_limit_microusd,
        broker_pricing_policy_sha256=pricing_policy_sha256,
        records=raw_records,
        records_sha256=records_sha256,
        cumulative_reserved_tokens=cumulative,
        cumulative_reserved_cost_microusd=cumulative_cost,
        measured_unix_ns=measured_unix_ns,
        evidence_sha256=_sha256(_LEDGER_EVIDENCE_DOMAIN + _canonical_json(payload)),
    )


def _ledger_rows(connection: sqlite3.Connection, packet_sha256: str) -> list[tuple[object, ...]]:
    return list(
        connection.execute(
            """
            SELECT packet_sha256, role, attempt, reserved_tokens,
                   reserved_cost_microusd, reservation_unix_ns
            FROM broker_reservations
            WHERE packet_sha256 = ?
            ORDER BY role, attempt
            """,
            (packet_sha256,),
        )
    )


def _open_ledger(
    path: Path,
    *,
    candidate_uid: int,
) -> tuple[sqlite3.Connection, tuple[Path, int, int, str]]:
    absolute = Path(os.path.abspath(path))
    connection: sqlite3.Connection | None = None
    if absolute == Path(absolute.anchor) or absolute.name in {"", ".", ".."}:
        raise BrokerExecutionError("broker attempt ledger validation failed")
    try:
        parent = assert_candidate_cannot_mutate(absolute.parent, candidate_uid=candidate_uid)
        metadata = os.lstat(parent)
        if not stat.S_ISDIR(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) & 0o077:
            raise BrokerExecutionError("broker attempt ledger validation failed")
        try:
            file_metadata = os.lstat(absolute)
        except FileNotFoundError:
            file_metadata = None
        if file_metadata is not None:
            if (
                not stat.S_ISREG(file_metadata.st_mode)
                or file_metadata.st_nlink != 1
                or stat.S_IMODE(file_metadata.st_mode) & 0o077
            ):
                raise BrokerExecutionError("broker attempt ledger validation failed")
            assert_candidate_cannot_mutate(absolute, candidate_uid=candidate_uid)
        else:
            flags = os.O_RDWR | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
            try:
                descriptor = os.open(absolute, flags, 0o600)
            except FileExistsError:
                file_metadata = os.lstat(absolute)
                if (
                    not stat.S_ISREG(file_metadata.st_mode)
                    or file_metadata.st_nlink != 1
                    or stat.S_IMODE(file_metadata.st_mode) & 0o077
                ):
                    raise BrokerExecutionError("broker attempt ledger validation failed")
                assert_candidate_cannot_mutate(absolute, candidate_uid=candidate_uid)
            else:
                os.close(descriptor)
        identity = _ledger_identity(absolute, candidate_uid=candidate_uid)
        connection = sqlite3.connect(
            absolute,
            timeout=5,
            isolation_level=None,
        )
        connection.execute("PRAGMA busy_timeout = 5000")
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA trusted_schema = OFF")
        connection.execute("PRAGMA journal_mode = DELETE")
        connection.execute("PRAGMA synchronous = FULL")
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS broker_reservations (
                packet_sha256 TEXT NOT NULL,
                role TEXT NOT NULL CHECK (role IN ('reviewer', 'adversary')),
                attempt INTEGER NOT NULL CHECK (attempt BETWEEN 1 AND 2),
                reserved_tokens INTEGER NOT NULL CHECK (reserved_tokens > 0),
                reserved_cost_microusd INTEGER NOT NULL CHECK (reserved_cost_microusd > 0),
                reservation_unix_ns INTEGER NOT NULL CHECK (reservation_unix_ns > 0),
                PRIMARY KEY (packet_sha256, role, attempt)
            ) STRICT
            """
        )
        _validate_ledger_schema(connection)
        return connection, identity
    except BrokerExecutionError:
        if connection is not None:
            connection.close()
        raise
    except (OSError, sqlite3.Error, PreflightError, TypeError, ValueError) as exc:
        if connection is not None:
            connection.close()
        raise BrokerExecutionError("broker attempt ledger validation failed") from exc


def prepare_broker_ledger(ledger_path: Path, *, candidate_uid: int) -> str:
    """Create/validate the session ledger once and return its protected inode identity."""

    connection, identity = _open_ledger(ledger_path, candidate_uid=candidate_uid)
    connection.close()
    return identity[3]


def _reserve_attempt(
    *,
    ledger_path: Path,
    invocation: IsolatedBrokerInvocation,
    packet_reservation_limit: int,
    packet_cost_limit_microusd: int,
    pricing_policy_sha256: str,
    reserved_cost_microusd: int,
    candidate_uid: int,
    expected_ledger_identity_sha256: str,
) -> tuple[BrokerLedgerEvidence, str]:
    connection, identity = _open_ledger(ledger_path, candidate_uid=candidate_uid)
    try:
        if not _is_sha256(expected_ledger_identity_sha256) or not hmac.compare_digest(
            identity[3],
            expected_ledger_identity_sha256,
        ):
            raise BrokerExecutionError("broker attempt ledger validation failed")
        connection.execute("BEGIN IMMEDIATE")
        attempts = [
            int(row[0])
            for row in connection.execute(
                """
                SELECT attempt FROM broker_reservations
                WHERE packet_sha256 = ? AND role = ? ORDER BY attempt
                """,
                (invocation.packet_sha256, invocation.role),
            )
        ]
        if attempts != list(range(1, len(attempts) + 1)):
            raise _AttemptReservationRejected
        expected_attempt = len(attempts) + 1
        if expected_attempt > 2 or invocation.attempt != expected_attempt:
            raise _AttemptReservationRejected
        row = connection.execute(
            """
            SELECT COALESCE(SUM(reserved_tokens), 0),
                   COALESCE(SUM(reserved_cost_microusd), 0)
            FROM broker_reservations
            WHERE packet_sha256 = ?
            """,
            (invocation.packet_sha256,),
        ).fetchone()
        if (
            row is None
            or len(row) != 2
            or any(isinstance(value, bool) or not isinstance(value, int) for value in row)
        ):
            raise BrokerExecutionError("broker attempt ledger validation failed")
        cumulative = row[0] + invocation.reserved_tokens
        if cumulative > packet_reservation_limit:
            raise _TokenReservationRejected
        cumulative_cost = row[1] + reserved_cost_microusd
        if cumulative_cost > packet_cost_limit_microusd:
            raise _CostReservationRejected
        reservation_unix_ns = time.time_ns()
        connection.execute(
            """
            INSERT INTO broker_reservations
                (packet_sha256, role, attempt, reserved_tokens,
                 reserved_cost_microusd, reservation_unix_ns)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                invocation.packet_sha256,
                invocation.role,
                invocation.attempt,
                invocation.reserved_tokens,
                reserved_cost_microusd,
                reservation_unix_ns,
            ),
        )
        ledger_evidence = _build_ledger_evidence(
            ledger_path=identity[0],
            ledger_device=identity[1],
            ledger_inode=identity[2],
            ledger_identity_sha256=identity[3],
            packet_sha256=invocation.packet_sha256,
            packet_reservation_limit=packet_reservation_limit,
            packet_cost_limit_microusd=packet_cost_limit_microusd,
            pricing_policy_sha256=pricing_policy_sha256,
            rows=_ledger_rows(connection, invocation.packet_sha256),
        )
        reservation_sha256 = _reservation_record_sha256(
            _reservation_record(
                packet_sha256=invocation.packet_sha256,
                role=invocation.role,
                attempt=invocation.attempt,
                reserved_tokens=invocation.reserved_tokens,
                reserved_cost_microusd=reserved_cost_microusd,
                reservation_unix_ns=reservation_unix_ns,
            )
        )
        connection.execute("COMMIT")
        if _ledger_identity(ledger_path, candidate_uid=candidate_uid) != identity:
            raise BrokerExecutionError("broker attempt ledger validation failed")
        return ledger_evidence, reservation_sha256
    except _AttemptReservationRejected as exc:
        if connection.in_transaction:
            connection.execute("ROLLBACK")
        raise BrokerExecutionError("broker attempt reservation rejected") from exc
    except _TokenReservationRejected as exc:
        if connection.in_transaction:
            connection.execute("ROLLBACK")
        raise BrokerExecutionError("broker token reservation rejected") from exc
    except _CostReservationRejected as exc:
        if connection.in_transaction:
            connection.execute("ROLLBACK")
        raise BrokerExecutionError("broker cost reservation rejected") from exc
    except BrokerExecutionError:
        if connection.in_transaction:
            connection.execute("ROLLBACK")
        raise
    except (sqlite3.Error, OSError, TypeError, ValueError) as exc:
        if connection.in_transaction:
            try:
                connection.execute("ROLLBACK")
            except sqlite3.Error:
                pass
        raise BrokerExecutionError("broker attempt ledger validation failed") from exc
    finally:
        connection.close()


def _validated_ledger_records(
    evidence: BrokerLedgerEvidence,
    *,
    expected_packet_sha256: str,
    expected_packet_reservation_limit: int,
    expected_packet_cost_limit_microusd: int,
    expected_pricing_policy_sha256: str,
) -> list[dict[str, int | str]]:
    if type(evidence) is not BrokerLedgerEvidence:
        raise BrokerExecutionError("broker ledger evidence validation failed")
    if (
        evidence.schema_version != "1.0"
        or evidence.packet_sha256 != expected_packet_sha256
        or evidence.broker_packet_reservation_limit != expected_packet_reservation_limit
        or evidence.broker_packet_cost_limit_microusd != expected_packet_cost_limit_microusd
        or evidence.broker_pricing_policy_sha256 != expected_pricing_policy_sha256
        or not isinstance(evidence.ledger_path, Path)
        or not evidence.ledger_path.is_absolute()
        or isinstance(evidence.ledger_device, bool)
        or not isinstance(evidence.ledger_device, int)
        or evidence.ledger_device < 0
        or isinstance(evidence.ledger_inode, bool)
        or not isinstance(evidence.ledger_inode, int)
        or evidence.ledger_inode <= 0
        or not _is_sha256(evidence.broker_ledger_identity_sha256)
        or not isinstance(evidence.records, bytes)
        or evidence.records_sha256 != _sha256(evidence.records)
        or isinstance(evidence.cumulative_reserved_tokens, bool)
        or not isinstance(evidence.cumulative_reserved_tokens, int)
        or not 0 <= evidence.cumulative_reserved_tokens <= expected_packet_reservation_limit
        or isinstance(evidence.cumulative_reserved_cost_microusd, bool)
        or not isinstance(evidence.cumulative_reserved_cost_microusd, int)
        or not 0
        <= evidence.cumulative_reserved_cost_microusd
        <= expected_packet_cost_limit_microusd
        or isinstance(evidence.measured_unix_ns, bool)
        or not isinstance(evidence.measured_unix_ns, int)
        or evidence.measured_unix_ns <= 0
        or not _is_sha256(evidence.evidence_sha256)
    ):
        raise BrokerExecutionError("broker ledger evidence validation failed")
    identity_payload = {
        "ledger_device": evidence.ledger_device,
        "ledger_inode": evidence.ledger_inode,
        "ledger_path": str(evidence.ledger_path),
        "schema_version": "1.0",
    }
    if evidence.broker_ledger_identity_sha256 != _sha256(
        _LEDGER_IDENTITY_DOMAIN + _canonical_json(identity_payload)
    ):
        raise BrokerExecutionError("broker ledger evidence validation failed")
    try:
        payload = json.loads(
            evidence.records.decode("utf-8", errors="strict"),
            object_pairs_hook=_reject_duplicate_keys,
        )
    except (BrokerExecutionError, UnicodeError, json.JSONDecodeError) as exc:
        raise BrokerExecutionError("broker ledger evidence validation failed") from exc
    if (
        not isinstance(payload, dict)
        or set(payload) != {"packet_sha256", "records", "schema_version"}
        or payload["schema_version"] != "1.0"
        or payload["packet_sha256"] != expected_packet_sha256
        or not isinstance(payload["records"], list)
        or _canonical_json(payload) != evidence.records
    ):
        raise BrokerExecutionError("broker ledger evidence validation failed")
    rows: list[tuple[object, ...]] = []
    for record in payload["records"]:
        if not isinstance(record, dict) or set(record) != {
            "attempt",
            "packet_sha256",
            "reservation_unix_ns",
            "reserved_cost_microusd",
            "reserved_tokens",
            "role",
        }:
            raise BrokerExecutionError("broker ledger evidence validation failed")
        rows.append(
            (
                record["packet_sha256"],
                record["role"],
                record["attempt"],
                record["reserved_tokens"],
                record["reserved_cost_microusd"],
                record["reservation_unix_ns"],
            )
        )
    rebuilt = _build_ledger_evidence(
        ledger_path=evidence.ledger_path,
        ledger_device=evidence.ledger_device,
        ledger_inode=evidence.ledger_inode,
        ledger_identity_sha256=evidence.broker_ledger_identity_sha256,
        packet_sha256=expected_packet_sha256,
        packet_reservation_limit=expected_packet_reservation_limit,
        packet_cost_limit_microusd=expected_packet_cost_limit_microusd,
        pricing_policy_sha256=expected_pricing_policy_sha256,
        rows=rows,
    )
    evidence_payload = {
        "cumulative_reserved_tokens": rebuilt.cumulative_reserved_tokens,
        "cumulative_reserved_cost_microusd": rebuilt.cumulative_reserved_cost_microusd,
        "ledger_device": evidence.ledger_device,
        "broker_ledger_identity_sha256": evidence.broker_ledger_identity_sha256,
        "ledger_inode": evidence.ledger_inode,
        "ledger_path": str(evidence.ledger_path),
        "measured_unix_ns": evidence.measured_unix_ns,
        "broker_packet_reservation_limit": expected_packet_reservation_limit,
        "broker_packet_cost_limit_microusd": expected_packet_cost_limit_microusd,
        "broker_pricing_policy_sha256": expected_pricing_policy_sha256,
        "packet_sha256": expected_packet_sha256,
        "records_sha256": rebuilt.records_sha256,
        "schema_version": "1.0",
    }
    if (
        rebuilt.records != evidence.records
        or rebuilt.records_sha256 != evidence.records_sha256
        or rebuilt.cumulative_reserved_tokens != evidence.cumulative_reserved_tokens
        or rebuilt.cumulative_reserved_cost_microusd != evidence.cumulative_reserved_cost_microusd
        or evidence.broker_packet_cost_limit_microusd != expected_packet_cost_limit_microusd
        or evidence.broker_pricing_policy_sha256 != expected_pricing_policy_sha256
        or evidence.evidence_sha256
        != _sha256(_LEDGER_EVIDENCE_DOMAIN + _canonical_json(evidence_payload))
    ):
        raise BrokerExecutionError("broker ledger evidence validation failed")
    return payload["records"]


def measure_broker_ledger(
    ledger_path: Path,
    *,
    packet_sha256: str,
    broker_packet_reservation_limit: int,
    candidate_uid: int,
    broker_packet_cost_limit_microusd: int = DEFAULT_PACKET_COST_LIMIT_MICROUSD,
    broker_pricing_policy_sha256: str = APPROVED_OPENAI_PRICING_POLICY.sha256,
) -> BrokerLedgerEvidence:
    """Read one final packet-wide ledger snapshot without creating or updating the database."""

    if (
        not _is_sha256(packet_sha256)
        or isinstance(broker_packet_reservation_limit, bool)
        or not isinstance(broker_packet_reservation_limit, int)
        or not MAX_OUTPUT_TOKENS <= broker_packet_reservation_limit <= MAX_PACKET_RESERVED_TOKENS
        or isinstance(broker_packet_cost_limit_microusd, bool)
        or not isinstance(broker_packet_cost_limit_microusd, int)
        or not 1 <= broker_packet_cost_limit_microusd <= ABSOLUTE_PACKET_COST_LIMIT_MICROUSD
        or broker_pricing_policy_sha256 != APPROVED_OPENAI_PRICING_POLICY.sha256
    ):
        raise BrokerExecutionError("broker ledger evidence validation failed")
    try:
        identity = _ledger_identity(ledger_path, candidate_uid=candidate_uid)
        connection = sqlite3.connect(
            identity[0].as_uri() + "?mode=ro",
            uri=True,
            timeout=5,
            isolation_level=None,
        )
        try:
            connection.execute("PRAGMA busy_timeout = 5000")
            connection.execute("PRAGMA trusted_schema = OFF")
            connection.execute("PRAGMA query_only = ON")
            _validate_ledger_schema(connection)
            connection.execute("BEGIN")
            rows = _ledger_rows(connection, packet_sha256)
            evidence = _build_ledger_evidence(
                ledger_path=identity[0],
                ledger_device=identity[1],
                ledger_inode=identity[2],
                ledger_identity_sha256=identity[3],
                packet_sha256=packet_sha256,
                packet_reservation_limit=broker_packet_reservation_limit,
                packet_cost_limit_microusd=broker_packet_cost_limit_microusd,
                pricing_policy_sha256=broker_pricing_policy_sha256,
                rows=rows,
            )
            connection.execute("COMMIT")
        finally:
            connection.close()
        if _ledger_identity(ledger_path, candidate_uid=candidate_uid) != identity:
            raise BrokerExecutionError("broker ledger evidence validation failed")
        return evidence
    except BrokerExecutionError as exc:
        if str(exc) == "broker ledger evidence validation failed":
            raise
        raise BrokerExecutionError("broker ledger evidence validation failed") from exc
    except (OSError, TypeError, ValueError) as exc:
        raise BrokerExecutionError("broker ledger evidence validation failed") from exc
    except (OSError, sqlite3.Error, PreflightError, TypeError, ValueError) as exc:
        raise BrokerExecutionError("broker ledger evidence validation failed") from exc


def validate_broker_ledger_evidence(
    evidence: BrokerLedgerEvidence,
    *,
    ledger_path: Path,
    expected_packet_sha256: str,
    broker_packet_reservation_limit: int,
    expected_broker_ledger_identity_sha256: str,
    candidate_uid: int,
    require_current_records: bool = True,
    broker_packet_cost_limit_microusd: int = DEFAULT_PACKET_COST_LIMIT_MICROUSD,
    broker_pricing_policy_sha256: str = APPROVED_OPENAI_PRICING_POLICY.sha256,
) -> BrokerLedgerEvidence:
    """Validate canonical records and bind them to the currently protected ledger inode."""

    if type(require_current_records) is not bool or not _is_sha256(
        expected_broker_ledger_identity_sha256
    ):
        raise BrokerExecutionError("broker ledger evidence validation failed")
    try:
        records = _validated_ledger_records(
            evidence,
            expected_packet_sha256=expected_packet_sha256,
            expected_packet_reservation_limit=broker_packet_reservation_limit,
            expected_packet_cost_limit_microusd=broker_packet_cost_limit_microusd,
            expected_pricing_policy_sha256=broker_pricing_policy_sha256,
        )
        current = measure_broker_ledger(
            ledger_path,
            packet_sha256=expected_packet_sha256,
            broker_packet_reservation_limit=broker_packet_reservation_limit,
            candidate_uid=candidate_uid,
            broker_packet_cost_limit_microusd=broker_packet_cost_limit_microusd,
            broker_pricing_policy_sha256=broker_pricing_policy_sha256,
        )
        current_records = _validated_ledger_records(
            current,
            expected_packet_sha256=expected_packet_sha256,
            expected_packet_reservation_limit=broker_packet_reservation_limit,
            expected_packet_cost_limit_microusd=broker_packet_cost_limit_microusd,
            expected_pricing_policy_sha256=broker_pricing_policy_sha256,
        )
        if (
            evidence.ledger_path != current.ledger_path
            or evidence.ledger_device != current.ledger_device
            or evidence.ledger_inode != current.ledger_inode
            or evidence.broker_ledger_identity_sha256 != current.broker_ledger_identity_sha256
            or not hmac.compare_digest(
                current.broker_ledger_identity_sha256,
                expected_broker_ledger_identity_sha256,
            )
            or (require_current_records and records != current_records)
            or (
                not require_current_records
                and any(record not in current_records for record in records)
            )
        ):
            raise BrokerExecutionError("broker ledger evidence validation failed")
        return evidence
    except BrokerExecutionError as exc:
        if str(exc) == "broker ledger evidence validation failed":
            raise
        raise BrokerExecutionError("broker ledger evidence validation failed") from exc


def validate_frozen_broker_ledger_evidence(
    evidence: BrokerLedgerEvidence,
    *,
    expected_packet_sha256: str,
    broker_packet_reservation_limit: int,
    expected_broker_ledger_identity_sha256: str,
    broker_packet_cost_limit_microusd: int = DEFAULT_PACKET_COST_LIMIT_MICROUSD,
    broker_pricing_policy_sha256: str = APPROVED_OPENAI_PRICING_POLICY.sha256,
) -> BrokerLedgerEvidence:
    """Validate a canonical ledger snapshot emitted by the protected outer process.

    Unlike :func:`validate_broker_ledger_evidence`, this validator deliberately performs no live
    pathname lookup.  It is suitable only after the root-owned outer executor's canonical output
    provenance has been verified.  The embedded pathname/device/inode tuple is still rehashed and
    bound to the coordinator-approved identity, while every record, total, cap, and evidence
    digest is rebuilt from bytes.
    """

    if not _is_sha256(expected_broker_ledger_identity_sha256):
        raise BrokerExecutionError("broker ledger evidence validation failed")
    try:
        _validated_ledger_records(
            evidence,
            expected_packet_sha256=expected_packet_sha256,
            expected_packet_reservation_limit=broker_packet_reservation_limit,
            expected_packet_cost_limit_microusd=broker_packet_cost_limit_microusd,
            expected_pricing_policy_sha256=broker_pricing_policy_sha256,
        )
        if not hmac.compare_digest(
            evidence.broker_ledger_identity_sha256,
            expected_broker_ledger_identity_sha256,
        ):
            raise BrokerExecutionError("broker ledger evidence validation failed")
        return evidence
    except BrokerExecutionError:
        raise
    except (AttributeError, TypeError, ValueError) as exc:
        raise BrokerExecutionError("broker ledger evidence validation failed") from exc


def validate_successful_broker_executions_against_final_ledger(
    executions: Sequence[BrokerExecutionEvidence],
    final_ledger: BrokerLedgerEvidence,
) -> BrokerLedgerEvidence:
    """Accept charged failed attempts while proving each role stops at its one success.

    The final protected ledger is authoritative for cost.  A successful execution may therefore
    account for attempt 2 after attempt 1 failed without producing an execution envelope.  Every
    earlier reservation remains charged, but a reservation after the successful attempt, a gap,
    an unknown role, or an execution missing from the final ledger is rejected.
    """

    try:
        values = tuple(executions)
        if len(values) != 2 or any(type(item) is not BrokerExecutionEvidence for item in values):
            raise BrokerExecutionError("broker final ledger validation failed")
        by_role = {item.role: item for item in values}
        if len(by_role) != 2 or set(by_role) != {"reviewer", "adversary"}:
            raise BrokerExecutionError("broker final ledger validation failed")
        final_records = _validated_ledger_records(
            final_ledger,
            expected_packet_sha256=final_ledger.packet_sha256,
            expected_packet_reservation_limit=final_ledger.broker_packet_reservation_limit,
            expected_packet_cost_limit_microusd=(final_ledger.broker_packet_cost_limit_microusd),
            expected_pricing_policy_sha256=final_ledger.broker_pricing_policy_sha256,
        )
        for role, execution in by_role.items():
            role_records = [record for record in final_records if record["role"] == role]
            attempts = [int(record["attempt"]) for record in role_records]
            if attempts != list(range(1, execution.attempt + 1)):
                raise BrokerExecutionError("broker final ledger validation failed")
            successful_record = role_records[-1]
            if (
                successful_record["reserved_tokens"] != execution.reserved_tokens
                or execution.reservation_record_sha256
                != _reservation_record_sha256(successful_record)
                or execution.packet_sha256 != final_ledger.packet_sha256
                or execution.broker_ledger_identity_sha256
                != final_ledger.broker_ledger_identity_sha256
                or execution.broker_packet_reservation_limit
                != final_ledger.broker_packet_reservation_limit
                or execution.broker_packet_cost_limit_microusd
                != final_ledger.broker_packet_cost_limit_microusd
                or execution.broker_pricing_policy_sha256
                != final_ledger.broker_pricing_policy_sha256
                or execution.reserved_cost_microusd != successful_record["reserved_cost_microusd"]
                or execution.cumulative_reserved_tokens
                != execution.ledger.cumulative_reserved_tokens
                or execution.cumulative_reserved_cost_microusd
                != execution.ledger.cumulative_reserved_cost_microusd
            ):
                raise BrokerExecutionError("broker final ledger validation failed")
            execution_records = _validated_ledger_records(
                execution.ledger,
                expected_packet_sha256=final_ledger.packet_sha256,
                expected_packet_reservation_limit=(final_ledger.broker_packet_reservation_limit),
                expected_packet_cost_limit_microusd=(
                    final_ledger.broker_packet_cost_limit_microusd
                ),
                expected_pricing_policy_sha256=final_ledger.broker_pricing_policy_sha256,
            )
            if any(record not in final_records for record in execution_records):
                raise BrokerExecutionError("broker final ledger validation failed")
        cumulative = [item.cumulative_reserved_tokens for item in values]
        latest = max(values, key=lambda item: item.cumulative_reserved_tokens)
        if (
            len(set(cumulative)) != len(cumulative)
            or max(cumulative) != final_ledger.cumulative_reserved_tokens
            or latest.ledger.records != final_ledger.records
            or latest.ledger.records_sha256 != final_ledger.records_sha256
        ):
            raise BrokerExecutionError("broker final ledger validation failed")
        return final_ledger
    except BrokerExecutionError:
        raise
    except (AttributeError, IndexError, TypeError, ValueError) as exc:
        raise BrokerExecutionError("broker final ledger validation failed") from exc


def _kill_process_group(process: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except (OSError, ProcessLookupError):
        try:
            process.kill()
        except OSError:
            pass


def _run_bounded_broker(
    argv: tuple[str, ...],
    *,
    stdin_bytes: bytes,
    environment: dict[str, str],
    timeout_seconds: int,
    max_stdin_bytes: int,
    max_stdout_bytes: int,
    max_stderr_bytes: int,
) -> _BrokerProcessResult:
    """Run exact argv with bounded nonblocking streams and no inherited environment."""

    if (
        not isinstance(stdin_bytes, bytes)
        or len(stdin_bytes) > max_stdin_bytes
        or any(not isinstance(value, str) or not value or "\x00" in value for value in argv)
    ):
        raise BrokerExecutionError("isolated broker process failed")
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
            bufsize=0,
        )
    except (OSError, ValueError) as exc:
        raise BrokerExecutionError("isolated broker process failed") from exc
    if process.stdin is None or process.stdout is None or process.stderr is None:
        _kill_process_group(process)
        raise BrokerExecutionError("isolated broker process failed")

    selector = selectors.DefaultSelector()
    stdout = bytearray()
    stderr = bytearray()
    stdout_digest = hashlib.sha256()
    stderr_digest = hashlib.sha256()
    streams = {
        process.stdout: (stdout, stdout_digest, max_stdout_bytes),
        process.stderr: (stderr, stderr_digest, max_stderr_bytes),
    }
    stdin_offset = 0
    try:
        for stream in (*streams, process.stdin):
            os.set_blocking(stream.fileno(), False)
        selector.register(process.stdout, selectors.EVENT_READ)
        selector.register(process.stderr, selectors.EVENT_READ)
        selector.register(process.stdin, selectors.EVENT_WRITE)
        deadline = time.monotonic() + timeout_seconds
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise BrokerExecutionError("isolated broker process failed")
            events = selector.select(min(remaining, 0.25))
            if not events and process.poll() is not None:
                # EOF notifications can lag a child exit; one more nonblocking pass drains them.
                events = selector.select(0)
            for key, mask in events:
                stream = key.fileobj
                if stream is process.stdin and mask & selectors.EVENT_WRITE:
                    try:
                        written = os.write(process.stdin.fileno(), stdin_bytes[stdin_offset:])
                    except BrokenPipeError:
                        written = 0
                    stdin_offset += written
                    if written == 0 or stdin_offset == len(stdin_bytes):
                        selector.unregister(process.stdin)
                        process.stdin.close()
                    continue
                if not mask & selectors.EVENT_READ:
                    continue
                try:
                    chunk = os.read(stream.fileno(), 65_536)
                except BlockingIOError:
                    continue
                if not chunk:
                    selector.unregister(stream)
                    stream.close()
                    continue
                buffer, digest, maximum = streams[stream]
                if len(buffer) + len(chunk) > maximum:
                    raise BrokerExecutionError("isolated broker process failed")
                buffer.extend(chunk)
                digest.update(chunk)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise BrokerExecutionError("isolated broker process failed")
        exit_code = process.wait(timeout=remaining)
        return _BrokerProcessResult(
            exit_code=exit_code,
            stdout=bytes(stdout),
            stderr=bytes(stderr),
            stdout_sha256=stdout_digest.hexdigest(),
            stderr_sha256=stderr_digest.hexdigest(),
            duration_ms=max(0, (time.monotonic_ns() - started) // 1_000_000),
        )
    except (BrokerExecutionError, OSError, subprocess.TimeoutExpired) as exc:
        _kill_process_group(process)
        if isinstance(exc, BrokerExecutionError):
            raise
        raise BrokerExecutionError("isolated broker process failed") from exc
    finally:
        selector.close()
        for stream in (process.stdin, process.stdout, process.stderr):
            if stream is not None and not stream.closed:
                stream.close()
        if process.poll() is None:
            _kill_process_group(process)
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                pass


def _cleanup_named_container(
    backend: ContainerBackend,
    container_name: str,
    environment: dict[str, str],
) -> _CleanupResult:
    argv = (str(backend.executable), "rm", "-f", "--", container_name)
    started = time.monotonic_ns()
    try:
        result = subprocess.run(
            argv,
            check=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=environment,
            shell=False,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired):
        return _CleanupResult(
            argv=argv,
            exit_code=-1,
            duration_ms=max(0, (time.monotonic_ns() - started) // 1_000_000),
            succeeded=False,
        )
    return _CleanupResult(
        argv=argv,
        exit_code=result.returncode,
        duration_ms=max(0, (time.monotonic_ns() - started) // 1_000_000),
        succeeded=result.returncode == 0,
    )


def _measure_cleanup_result(
    result: object,
    *,
    expected_argv: tuple[str, ...],
    observed_duration_ms: int,
) -> _CleanupResult:
    if type(result) is bool:
        return _CleanupResult(
            argv=expected_argv,
            exit_code=0 if result else -1,
            duration_ms=observed_duration_ms,
            succeeded=result,
        )
    try:
        argv = tuple(result.argv)  # type: ignore[attr-defined]
        exit_code = result.exit_code  # type: ignore[attr-defined]
        duration_ms = result.duration_ms  # type: ignore[attr-defined]
        succeeded = result.succeeded  # type: ignore[attr-defined]
    except (AttributeError, TypeError, ValueError) as exc:
        raise BrokerExecutionError("broker container cleanup could not be attested") from exc
    if (
        argv != expected_argv
        or isinstance(exit_code, bool)
        or not isinstance(exit_code, int)
        or isinstance(duration_ms, bool)
        or not isinstance(duration_ms, int)
        or not 0 <= duration_ms <= 30_000
        or not 0 <= observed_duration_ms <= 30_000
        or type(succeeded) is not bool
        or succeeded is not (exit_code == 0)
    ):
        raise BrokerExecutionError("broker container cleanup could not be attested")
    return _CleanupResult(
        argv=expected_argv,
        exit_code=exit_code,
        duration_ms=max(duration_ms, observed_duration_ms),
        succeeded=succeeded,
    )


def _measure_process_result(
    result: object,
    *,
    credential: str,
    timeout_seconds: int,
    max_stdout_bytes: int,
    max_stderr_bytes: int,
    observed_duration_ms: int,
) -> _BrokerProcessResult:
    try:
        exit_code = result.exit_code  # type: ignore[attr-defined]
        stdout = result.stdout  # type: ignore[attr-defined]
        stderr = result.stderr  # type: ignore[attr-defined]
        reported_stdout_sha256 = result.stdout_sha256  # type: ignore[attr-defined]
        reported_stderr_sha256 = result.stderr_sha256  # type: ignore[attr-defined]
        duration_ms = result.duration_ms  # type: ignore[attr-defined]
    except (AttributeError, TypeError) as exc:
        raise BrokerExecutionError("isolated broker process failed") from exc
    if (
        isinstance(exit_code, bool)
        or not isinstance(exit_code, int)
        or not isinstance(stdout, bytes)
        or not isinstance(stderr, bytes)
        or len(stdout) > max_stdout_bytes
        or len(stderr) > max_stderr_bytes
        or isinstance(duration_ms, bool)
        or not isinstance(duration_ms, int)
        or not 0 <= duration_ms <= timeout_seconds * 1_000
        or not 0 <= observed_duration_ms <= timeout_seconds * 1_000
    ):
        raise BrokerExecutionError("isolated broker process failed")
    measured_stdout_sha256 = _sha256(stdout)
    measured_stderr_sha256 = _sha256(stderr)
    if (
        not isinstance(reported_stdout_sha256, str)
        or not hmac.compare_digest(reported_stdout_sha256, measured_stdout_sha256)
        or not isinstance(reported_stderr_sha256, str)
        or not hmac.compare_digest(reported_stderr_sha256, measured_stderr_sha256)
        or credential.encode("ascii") in stdout
        or credential.encode("ascii") in stderr
        or exit_code != 0
    ):
        raise BrokerExecutionError("isolated broker process failed")
    return _BrokerProcessResult(
        exit_code=exit_code,
        stdout=stdout,
        stderr=stderr,
        stdout_sha256=measured_stdout_sha256,
        stderr_sha256=measured_stderr_sha256,
        duration_ms=max(duration_ms, observed_duration_ms),
    )


def _parse_canonical_envelope(raw: bytes, *, request_sha256: str) -> tuple[str, str]:
    try:
        if not raw.endswith(b"\n") or raw.endswith((b"\n\n", b"\r\n")):
            raise BrokerExecutionError("broker canonical envelope validation failed")
        payload = json.loads(
            raw[:-1].decode("utf-8", errors="strict"),
            object_pairs_hook=_reject_duplicate_keys,
        )
        if not isinstance(payload, dict) or set(payload) != {
            "schema_version",
            "request_sha256",
            "response_sha256",
            "request_id",
            "response",
        }:
            raise BrokerExecutionError("broker canonical envelope validation failed")
        if payload["schema_version"] != "1.0" or _canonical_json(payload) + b"\n" != raw:
            raise BrokerExecutionError("broker canonical envelope validation failed")
        if not isinstance(payload["request_sha256"], str) or not hmac.compare_digest(
            payload["request_sha256"], request_sha256
        ):
            raise BrokerExecutionError("broker canonical envelope validation failed")
        response = payload["response"]
        response_sha256 = payload["response_sha256"]
        if (
            not isinstance(response, dict)
            or not isinstance(response_sha256, str)
            or not hmac.compare_digest(response_sha256, _sha256(_canonical_json(response)))
        ):
            raise BrokerExecutionError("broker canonical envelope validation failed")
        request_id = payload["request_id"]
        if (
            not isinstance(request_id, str)
            or not 1 <= len(request_id) <= 256
            or any(ord(character) < 33 or ord(character) > 126 for character in request_id)
        ):
            raise BrokerExecutionError("broker canonical envelope validation failed")
        return response_sha256, request_id
    except BrokerExecutionError:
        raise
    except (UnicodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
        raise BrokerExecutionError("broker canonical envelope validation failed") from exc


def _evidence_sha256(
    *,
    invocation: IsolatedBrokerInvocation,
    before: ContainerBackend,
    after: ContainerBackend,
    executed_argv: tuple[str, ...],
    executed_argv_sha256: str,
    cumulative_reserved_tokens: int,
    reserved_cost_microusd: int,
    ledger_evidence: BrokerLedgerEvidence,
    reservation_record_sha256: str,
    egress_boundary: EgressBoundaryEvidence,
    result: _BrokerProcessResult,
    started_unix_ns: int,
    response_sha256: str,
    request_id: str,
    cleanup_result: _CleanupResult,
) -> str:
    payload = {
        "approved_image_digest": invocation.approved_image_digest,
        "argv": list(executed_argv),
        "argv_sha256": executed_argv_sha256,
        "attempt": invocation.attempt,
        "boundary_evidence_sha256": invocation.boundary_evidence_sha256,
        "cleanup_succeeded": True,
        "cleanup_argv": list(cleanup_result.argv),
        "cleanup_argv_sha256": _sha256(_canonical_json(list(cleanup_result.argv))),
        "cleanup_duration_ms": cleanup_result.duration_ms,
        "cleanup_exit_code": cleanup_result.exit_code,
        "container_name": invocation.container_name,
        "cumulative_reserved_tokens": cumulative_reserved_tokens,
        "cumulative_reserved_cost_microusd": (ledger_evidence.cumulative_reserved_cost_microusd),
        "descriptor_argv": list(invocation.argv),
        "descriptor_argv_sha256": invocation.argv_sha256,
        "duration_ms": result.duration_ms,
        "broker_egress_boundary_sha256": egress_boundary.broker_egress_boundary_sha256,
        "exit_code": result.exit_code,
        "image": invocation.image,
        "ledger_evidence_sha256": ledger_evidence.evidence_sha256,
        "broker_ledger_identity_sha256": ledger_evidence.broker_ledger_identity_sha256,
        "ledger_records_sha256": ledger_evidence.records_sha256,
        "packet_sha256": invocation.packet_sha256,
        "request_id": request_id,
        "request_sha256": invocation.request_sha256,
        "reservation_record_sha256": reservation_record_sha256,
        "reserved_tokens": invocation.reserved_tokens,
        "reserved_cost_microusd": reserved_cost_microusd,
        "broker_packet_cost_limit_microusd": (ledger_evidence.broker_packet_cost_limit_microusd),
        "broker_pricing_policy_sha256": ledger_evidence.broker_pricing_policy_sha256,
        "response_sha256": response_sha256,
        "role": invocation.role,
        "runtime_executable": str(after.executable),
        "runtime_name": after.name,
        "runtime_post_security_sha256": after.security_evidence_sha256,
        "runtime_post_sha256": after.sha256,
        "runtime_pre_security_sha256": before.security_evidence_sha256,
        "runtime_pre_sha256": before.sha256,
        "runtime_rootless": after.rootless,
        "runtime_seccomp_profile": after.seccomp_profile,
        "runtime_security_sha256": after.security_evidence_sha256,
        "runtime_sha256": after.sha256,
        "runtime_user_namespace": after.user_namespace,
        "schema_version": "1.0",
        "started_unix_ns": started_unix_ns,
        "stderr_bytes": len(result.stderr),
        "stderr_sha256": result.stderr_sha256,
        "stdin_bytes": len(invocation.stdin_text.encode("utf-8")),
        "stdin_sha256": invocation.stdin_sha256,
        "stdout_bytes": len(result.stdout),
        "stdout_sha256": result.stdout_sha256,
    }
    return _sha256(_EVIDENCE_DOMAIN + _canonical_json(payload))


def execute_isolated_broker(
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
    broker_egress_boundary: EgressBoundaryEvidence,
    expected_broker_egress_boundary_sha256: str,
    expected_broker_gateway_image_digest: str,
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
    stream_runner: Callable[..., _BrokerProcessResult] = _run_bounded_broker,
    cleanup: Callable[[ContainerBackend, str, dict[str, str]], object] = _cleanup_named_container,
) -> BrokerExecutionEvidence:
    """Low-level broker primitive used by tests and the root-owned egress provisioner.

    Production orchestration must call ``execute_provisioned_isolated_broker`` so raw network
    creation, semantic inspect parsing, post-run measurement, and cleanup are also attested.
    """

    if allow_external_ai is not True or allow_isolated_broker is not True:
        raise BrokerExecutionError("isolated broker execution requires double opt-in")
    _validate_limits(
        timeout_seconds=timeout_seconds,
        max_stdin_bytes=max_stdin_bytes,
        max_stdout_bytes=max_stdout_bytes,
        max_stderr_bytes=max_stderr_bytes,
        packet_reservation_limit=broker_packet_reservation_limit,
        packet_cost_limit_microusd=broker_packet_cost_limit_microusd,
    )
    _validate_credential(credential)
    trusted_egress = validate_broker_egress_boundary_evidence(
        broker_egress_boundary,
        expected_broker_egress_boundary_sha256=expected_broker_egress_boundary_sha256,
        expected_broker_gateway_image_digest=expected_broker_gateway_image_digest,
        expected_broker_allowlist_policy_sha256=expected_broker_allowlist_policy_sha256,
    )
    trusted = _revalidate_invocation(invocation)
    try:
        trusted_pricing = validate_openai_pricing_policy(pricing_policy)
    except (PricingPolicyError, TypeError) as exc:
        raise BrokerExecutionError("broker pricing policy validation failed") from exc
    if (
        not _is_sha256(expected_broker_pricing_policy_sha256)
        or trusted_pricing.sha256 != expected_broker_pricing_policy_sha256
    ):
        raise BrokerExecutionError("broker pricing policy validation failed")
    _validate_trusted_bindings(
        trusted,
        expected_packet_sha256=expected_packet_sha256,
        expected_request_sha256=expected_request_sha256,
        expected_boundary_evidence_sha256=expected_boundary_evidence_sha256,
        expected_role=expected_role,
        expected_attempt=expected_attempt,
        approved_image_digest=approved_image_digest,
        expected_argv_sha256=expected_argv_sha256,
        expected_stdin_sha256=expected_stdin_sha256,
    )
    stdin = _validate_request_stdin(trusted)
    try:
        reserved_cost_microusd = reserve_request_cost_microusd(
            trusted_pricing,
            input_tokens=trusted.reserved_tokens - MAX_OUTPUT_TOKENS,
            output_tokens=MAX_OUTPUT_TOKENS,
        )
    except PricingPolicyError as exc:
        raise BrokerExecutionError("broker cost reservation validation failed") from exc
    if (
        len(stdin) > max_stdin_bytes
        or credential.encode("ascii") in stdin
        or any(credential in argument for argument in trusted.argv)
    ):
        raise BrokerExecutionError("broker invocation validation failed")

    before = _detect_exact_backend(
        trusted,
        candidate_uid=candidate_uid,
        which=which,
        probe=probe,
    )
    if trusted_egress.runtime_name != before.name:
        raise BrokerExecutionError("broker egress boundary validation failed")
    if trusted_egress.broker_internal_network != trusted.broker_internal_network:
        raise BrokerExecutionError("broker egress boundary validation failed")
    executed_argv = (str(before.executable), *trusted.argv[1:])
    if any(
        not value or any(character in value for character in ("\x00", "\n", "\r"))
        for value in executed_argv
    ):
        raise BrokerExecutionError("broker runtime isolation validation failed")
    executed_argv_sha256 = _sha256(_canonical_json(list(executed_argv)))
    ledger_evidence, reservation_record_sha256 = _reserve_attempt(
        ledger_path=ledger_path,
        invocation=trusted,
        packet_reservation_limit=broker_packet_reservation_limit,
        packet_cost_limit_microusd=broker_packet_cost_limit_microusd,
        pricing_policy_sha256=trusted_pricing.sha256,
        reserved_cost_microusd=reserved_cost_microusd,
        candidate_uid=candidate_uid,
        expected_ledger_identity_sha256=expected_broker_ledger_identity_sha256,
    )

    base_environment = _base_host_environment(before.name)
    process_environment = {**base_environment, BROKER_CREDENTIAL_ENV: credential}
    started_unix_ns = time.time_ns()
    process_started = time.monotonic_ns()
    process_result: object | None = None
    process_error = False
    try:
        process_result = stream_runner(
            executed_argv,
            stdin_bytes=stdin,
            environment=process_environment,
            timeout_seconds=timeout_seconds,
            max_stdin_bytes=max_stdin_bytes,
            max_stdout_bytes=max_stdout_bytes,
            max_stderr_bytes=max_stderr_bytes,
        )
    except Exception:
        # The reservation remains committed.  Never expose a subprocess exception string.
        process_error = True
    observed_process_duration_ms = max(0, (time.monotonic_ns() - process_started) // 1_000_000)

    cleanup_argv = (str(before.executable), "rm", "-f", "--", trusted.container_name)
    cleanup_started = time.monotonic_ns()
    try:
        cleanup_raw = cleanup(before, trusted.container_name, base_environment)
    except Exception:
        cleanup_raw = False
    observed_cleanup_duration_ms = max(0, (time.monotonic_ns() - cleanup_started) // 1_000_000)
    cleanup_result = _measure_cleanup_result(
        cleanup_raw,
        expected_argv=cleanup_argv,
        observed_duration_ms=observed_cleanup_duration_ms,
    )
    after: ContainerBackend | None = None
    try:
        after = _detect_exact_backend(
            trusted,
            candidate_uid=candidate_uid,
            which=which,
            probe=probe,
            enforce_invocation_mode=False,
        )
    except BrokerExecutionError:
        pass
    if cleanup_result.succeeded is not True:
        raise BrokerExecutionError("broker container cleanup could not be attested")
    if after is None or not _same_backend(before, after):
        raise BrokerExecutionError("broker runtime security changed during execution")
    if process_error or process_result is None:
        raise BrokerExecutionError("isolated broker process failed")
    measured = _measure_process_result(
        process_result,
        credential=credential,
        timeout_seconds=timeout_seconds,
        max_stdout_bytes=max_stdout_bytes,
        max_stderr_bytes=max_stderr_bytes,
        observed_duration_ms=observed_process_duration_ms,
    )
    response_sha256, request_id = _parse_canonical_envelope(
        measured.stdout,
        request_sha256=trusted.request_sha256,
    )
    evidence_sha256 = _evidence_sha256(
        invocation=trusted,
        before=before,
        after=after,
        executed_argv=executed_argv,
        executed_argv_sha256=executed_argv_sha256,
        cumulative_reserved_tokens=ledger_evidence.cumulative_reserved_tokens,
        reserved_cost_microusd=reserved_cost_microusd,
        ledger_evidence=ledger_evidence,
        reservation_record_sha256=reservation_record_sha256,
        egress_boundary=trusted_egress,
        result=measured,
        started_unix_ns=started_unix_ns,
        response_sha256=response_sha256,
        request_id=request_id,
        cleanup_result=cleanup_result,
    )
    return BrokerExecutionEvidence(
        schema_version="1.0",
        packet_sha256=trusted.packet_sha256,
        request_sha256=trusted.request_sha256,
        boundary_evidence_sha256=trusted.boundary_evidence_sha256,
        role=trusted.role,
        attempt=trusted.attempt,
        reserved_tokens=trusted.reserved_tokens,
        reserved_cost_microusd=reserved_cost_microusd,
        cumulative_reserved_tokens=ledger_evidence.cumulative_reserved_tokens,
        cumulative_reserved_cost_microusd=(ledger_evidence.cumulative_reserved_cost_microusd),
        reservation_record_sha256=reservation_record_sha256,
        broker_packet_reservation_limit=broker_packet_reservation_limit,
        broker_packet_cost_limit_microusd=broker_packet_cost_limit_microusd,
        broker_pricing_policy_sha256=trusted_pricing.sha256,
        broker_ledger_identity_sha256=ledger_evidence.broker_ledger_identity_sha256,
        broker_egress_boundary_sha256=trusted_egress.broker_egress_boundary_sha256,
        ledger=ledger_evidence,
        broker_egress_boundary=trusted_egress,
        runtime_name=after.name,
        runtime_executable=after.executable,
        runtime_sha256=after.sha256,
        runtime_security_sha256=after.security_evidence_sha256,
        runtime_pre_sha256=before.sha256,
        runtime_pre_security_sha256=before.security_evidence_sha256,
        runtime_post_sha256=after.sha256,
        runtime_post_security_sha256=after.security_evidence_sha256,
        runtime_rootless=after.rootless,
        runtime_user_namespace=after.user_namespace,
        runtime_seccomp_profile=after.seccomp_profile,
        image=trusted.image,
        approved_image_digest=trusted.approved_image_digest,
        container_name=trusted.container_name,
        descriptor_argv=trusted.argv,
        descriptor_argv_sha256=trusted.argv_sha256,
        argv=executed_argv,
        argv_sha256=executed_argv_sha256,
        stdin=stdin,
        stdin_sha256=trusted.stdin_sha256,
        exit_code=measured.exit_code,
        stdout=measured.stdout,
        stderr=measured.stderr,
        stdout_sha256=measured.stdout_sha256,
        stderr_sha256=measured.stderr_sha256,
        started_unix_ns=started_unix_ns,
        duration_ms=measured.duration_ms,
        cleanup_succeeded=True,
        cleanup_argv=cleanup_result.argv,
        cleanup_argv_sha256=_sha256(_canonical_json(list(cleanup_result.argv))),
        cleanup_exit_code=cleanup_result.exit_code,
        cleanup_duration_ms=cleanup_result.duration_ms,
        canonical_envelope=measured.stdout,
        response_sha256=response_sha256,
        request_id=request_id,
        evidence_sha256=evidence_sha256,
    )


def validate_broker_execution_evidence(
    evidence: BrokerExecutionEvidence,
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
    expected_broker_egress_boundary_sha256: str,
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
) -> BrokerExecutionEvidence:
    """Recompute every persisted binding without trusting serialized evidence fields."""

    try:
        if type(evidence) is not BrokerExecutionEvidence:
            raise BrokerExecutionError("broker execution evidence validation failed")
        _validate_limits(
            timeout_seconds=MAX_BROKER_TIMEOUT_SECONDS,
            max_stdin_bytes=MAX_BROKER_STDIN_BYTES,
            max_stdout_bytes=MAX_BROKER_STDOUT_BYTES,
            max_stderr_bytes=MAX_BROKER_STDERR_BYTES,
            packet_reservation_limit=broker_packet_reservation_limit,
            packet_cost_limit_microusd=broker_packet_cost_limit_microusd,
        )
        trusted = _revalidate_invocation(invocation)
        trusted_pricing = validate_openai_pricing_policy(pricing_policy)
        if trusted_pricing.sha256 != expected_broker_pricing_policy_sha256:
            raise BrokerExecutionError("broker execution evidence validation failed")
        reserved_cost_microusd = reserve_request_cost_microusd(
            trusted_pricing,
            input_tokens=trusted.reserved_tokens - MAX_OUTPUT_TOKENS,
            output_tokens=MAX_OUTPUT_TOKENS,
        )
        _validate_trusted_bindings(
            trusted,
            expected_packet_sha256=expected_packet_sha256,
            expected_request_sha256=expected_request_sha256,
            expected_boundary_evidence_sha256=expected_boundary_evidence_sha256,
            expected_role=expected_role,
            expected_attempt=expected_attempt,
            approved_image_digest=approved_image_digest,
            expected_argv_sha256=expected_descriptor_argv_sha256,
            expected_stdin_sha256=expected_stdin_sha256,
        )
        stdin = _validate_request_stdin(trusted)
        trusted_egress = validate_broker_egress_boundary_evidence(
            evidence.broker_egress_boundary,
            expected_broker_egress_boundary_sha256=(expected_broker_egress_boundary_sha256),
            expected_broker_gateway_image_digest=expected_broker_gateway_image_digest,
            expected_broker_allowlist_policy_sha256=(expected_broker_allowlist_policy_sha256),
        )
        current_backend = _detect_exact_backend(
            trusted,
            candidate_uid=candidate_uid,
            which=which,
            probe=probe,
        )
        if (
            evidence.schema_version != "1.0"
            or evidence.packet_sha256 != trusted.packet_sha256
            or evidence.request_sha256 != trusted.request_sha256
            or evidence.boundary_evidence_sha256 != trusted.boundary_evidence_sha256
            or evidence.role != trusted.role
            or evidence.attempt != trusted.attempt
            or evidence.reserved_tokens != trusted.reserved_tokens
            or evidence.reserved_cost_microusd != reserved_cost_microusd
            or evidence.broker_packet_reservation_limit != broker_packet_reservation_limit
            or evidence.broker_packet_cost_limit_microusd != broker_packet_cost_limit_microusd
            or evidence.broker_pricing_policy_sha256 != trusted_pricing.sha256
            or evidence.broker_ledger_identity_sha256
            != evidence.ledger.broker_ledger_identity_sha256
            or evidence.broker_egress_boundary_sha256
            != trusted_egress.broker_egress_boundary_sha256
            or evidence.image != trusted.image
            or evidence.approved_image_digest != trusted.approved_image_digest
            or evidence.container_name != trusted.container_name
            or evidence.descriptor_argv != trusted.argv
            or evidence.descriptor_argv_sha256 != trusted.argv_sha256
            or evidence.stdin != stdin
            or evidence.stdin_sha256 != trusted.stdin_sha256
        ):
            raise BrokerExecutionError("broker execution evidence validation failed")
        if (
            isinstance(evidence.cumulative_reserved_tokens, bool)
            or not isinstance(evidence.cumulative_reserved_tokens, int)
            or not trusted.reserved_tokens
            <= evidence.cumulative_reserved_tokens
            <= broker_packet_reservation_limit
            or isinstance(evidence.cumulative_reserved_cost_microusd, bool)
            or not isinstance(evidence.cumulative_reserved_cost_microusd, int)
            or not reserved_cost_microusd
            <= evidence.cumulative_reserved_cost_microusd
            <= broker_packet_cost_limit_microusd
            or not isinstance(evidence.runtime_executable, Path)
            or not evidence.runtime_executable.is_absolute()
            or evidence.runtime_name != trusted.container_runtime
            or trusted_egress.runtime_name != trusted.container_runtime
            or trusted_egress.broker_internal_network != trusted.broker_internal_network
            or type(evidence.runtime_rootless) is not bool
            or type(evidence.runtime_user_namespace) is not bool
            or evidence.runtime_rootless is not trusted.runtime_rootless
            or evidence.runtime_user_namespace is not trusted.runtime_user_namespace
            or (not evidence.runtime_rootless and not evidence.runtime_user_namespace)
            or not isinstance(evidence.runtime_seccomp_profile, str)
            or not evidence.runtime_seccomp_profile
            or "unconfined" in evidence.runtime_seccomp_profile.casefold()
        ):
            raise BrokerExecutionError("broker execution evidence validation failed")
        runtime_digests = (
            evidence.runtime_sha256,
            evidence.runtime_security_sha256,
            evidence.runtime_pre_sha256,
            evidence.runtime_pre_security_sha256,
            evidence.runtime_post_sha256,
            evidence.runtime_post_security_sha256,
        )
        if any(not _is_sha256(value) for value in runtime_digests) or not (
            evidence.runtime_sha256 == evidence.runtime_pre_sha256 == evidence.runtime_post_sha256
            and evidence.runtime_security_sha256
            == evidence.runtime_pre_security_sha256
            == evidence.runtime_post_security_sha256
        ):
            raise BrokerExecutionError("broker execution evidence validation failed")
        if (
            evidence.runtime_executable != current_backend.executable
            or evidence.runtime_sha256 != current_backend.sha256
            or evidence.runtime_security_sha256 != current_backend.security_evidence_sha256
            or evidence.runtime_rootless is not current_backend.rootless
            or evidence.runtime_user_namespace is not current_backend.user_namespace
            or evidence.runtime_seccomp_profile != current_backend.seccomp_profile
        ):
            raise BrokerExecutionError("broker execution evidence validation failed")
        executed_argv = (str(current_backend.executable), *trusted.argv[1:])
        executed_argv_sha256 = _sha256(_canonical_json(list(executed_argv)))
        cleanup_argv = (
            str(evidence.runtime_executable),
            "rm",
            "-f",
            "--",
            trusted.container_name,
        )
        cleanup_argv_sha256 = _sha256(_canonical_json(list(cleanup_argv)))
        if (
            evidence.argv != executed_argv
            or evidence.argv_sha256 != executed_argv_sha256
            or evidence.cleanup_argv != cleanup_argv
            or evidence.cleanup_argv_sha256 != cleanup_argv_sha256
            or evidence.cleanup_succeeded is not True
            or evidence.cleanup_exit_code != 0
            or isinstance(evidence.cleanup_duration_ms, bool)
            or not isinstance(evidence.cleanup_duration_ms, int)
            or not 0 <= evidence.cleanup_duration_ms <= 30_000
        ):
            raise BrokerExecutionError("broker execution evidence validation failed")
        validate_broker_ledger_evidence(
            evidence.ledger,
            ledger_path=ledger_path,
            expected_packet_sha256=expected_packet_sha256,
            broker_packet_reservation_limit=broker_packet_reservation_limit,
            expected_broker_ledger_identity_sha256=(expected_broker_ledger_identity_sha256),
            candidate_uid=candidate_uid,
            require_current_records=False,
            broker_packet_cost_limit_microusd=broker_packet_cost_limit_microusd,
            broker_pricing_policy_sha256=trusted_pricing.sha256,
        )
        ledger_records = _validated_ledger_records(
            evidence.ledger,
            expected_packet_sha256=expected_packet_sha256,
            expected_packet_reservation_limit=broker_packet_reservation_limit,
            expected_packet_cost_limit_microusd=broker_packet_cost_limit_microusd,
            expected_pricing_policy_sha256=trusted_pricing.sha256,
        )
        matching_records = [
            record
            for record in ledger_records
            if record["role"] == trusted.role and record["attempt"] == trusted.attempt
        ]
        if (
            evidence.cumulative_reserved_tokens != evidence.ledger.cumulative_reserved_tokens
            or evidence.cumulative_reserved_cost_microusd
            != evidence.ledger.cumulative_reserved_cost_microusd
            or len(matching_records) != 1
            or matching_records[0]["reserved_tokens"] != trusted.reserved_tokens
            or matching_records[0]["reserved_cost_microusd"] != reserved_cost_microusd
            or not _is_sha256(evidence.reservation_record_sha256)
            or evidence.reservation_record_sha256 != _reservation_record_sha256(matching_records[0])
        ):
            raise BrokerExecutionError("broker execution evidence validation failed")
        if (
            evidence.exit_code != 0
            or not isinstance(evidence.stdout, bytes)
            or not isinstance(evidence.stderr, bytes)
            or len(evidence.stdout) > MAX_BROKER_STDOUT_BYTES
            or len(evidence.stderr) > MAX_BROKER_STDERR_BYTES
            or evidence.stdout_sha256 != _sha256(evidence.stdout)
            or evidence.stderr_sha256 != _sha256(evidence.stderr)
            or evidence.canonical_envelope != evidence.stdout
            or isinstance(evidence.started_unix_ns, bool)
            or not isinstance(evidence.started_unix_ns, int)
            or evidence.started_unix_ns <= 0
            or isinstance(evidence.duration_ms, bool)
            or not isinstance(evidence.duration_ms, int)
            or not 0 <= evidence.duration_ms <= MAX_BROKER_TIMEOUT_SECONDS * 1_000
        ):
            raise BrokerExecutionError("broker execution evidence validation failed")
        response_sha256, request_id = _parse_canonical_envelope(
            evidence.canonical_envelope,
            request_sha256=trusted.request_sha256,
        )
        if evidence.response_sha256 != response_sha256 or evidence.request_id != request_id:
            raise BrokerExecutionError("broker execution evidence validation failed")
        before = ContainerBackend(
            name=evidence.runtime_name,
            executable=evidence.runtime_executable,
            rootless=evidence.runtime_rootless,
            user_namespace=evidence.runtime_user_namespace,
            seccomp_enabled=True,
            seccomp_profile=evidence.runtime_seccomp_profile,
            sha256=evidence.runtime_pre_sha256,
            security_evidence_sha256=evidence.runtime_pre_security_sha256,
        )
        after = ContainerBackend(
            name=evidence.runtime_name,
            executable=evidence.runtime_executable,
            rootless=evidence.runtime_rootless,
            user_namespace=evidence.runtime_user_namespace,
            seccomp_enabled=True,
            seccomp_profile=evidence.runtime_seccomp_profile,
            sha256=evidence.runtime_post_sha256,
            security_evidence_sha256=evidence.runtime_post_security_sha256,
        )
        measured = _BrokerProcessResult(
            exit_code=evidence.exit_code,
            stdout=evidence.stdout,
            stderr=evidence.stderr,
            stdout_sha256=evidence.stdout_sha256,
            stderr_sha256=evidence.stderr_sha256,
            duration_ms=evidence.duration_ms,
        )
        cleanup_result = _CleanupResult(
            argv=evidence.cleanup_argv,
            exit_code=evidence.cleanup_exit_code,
            duration_ms=evidence.cleanup_duration_ms,
            succeeded=evidence.cleanup_succeeded,
        )
        expected_evidence_sha256 = _evidence_sha256(
            invocation=trusted,
            before=before,
            after=after,
            executed_argv=executed_argv,
            executed_argv_sha256=executed_argv_sha256,
            cumulative_reserved_tokens=evidence.cumulative_reserved_tokens,
            reserved_cost_microusd=reserved_cost_microusd,
            ledger_evidence=evidence.ledger,
            reservation_record_sha256=evidence.reservation_record_sha256,
            egress_boundary=trusted_egress,
            result=measured,
            started_unix_ns=evidence.started_unix_ns,
            response_sha256=response_sha256,
            request_id=request_id,
            cleanup_result=cleanup_result,
        )
        if not _is_sha256(evidence.evidence_sha256) or not hmac.compare_digest(
            evidence.evidence_sha256,
            expected_evidence_sha256,
        ):
            raise BrokerExecutionError("broker execution evidence validation failed")
        return evidence
    except BrokerExecutionError as exc:
        if str(exc) == "broker execution evidence validation failed":
            raise
        raise BrokerExecutionError("broker execution evidence validation failed") from exc
    except (AttributeError, OSError, TypeError, ValueError) as exc:
        raise BrokerExecutionError("broker execution evidence validation failed") from exc
