from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import sqlite3
import stat
import threading
import time
from collections import Counter
from collections.abc import Mapping
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Literal
from typing import Protocol

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import BaseModel
from pydantic import Field

from tools.ai_review.models import GIT_SHA_PATTERN
from tools.ai_review.models import SHA256_PATTERN
from tools.ai_review.models import StrictModel
from tools.ai_review.nonce_ledger import NonceLedgerContractError
from tools.ai_review.nonce_ledger import NonceLedgerFileIdentity
from tools.ai_review.nonce_ledger import connect_existing_nonce_ledger_rw
from tools.ai_review.nonce_ledger import create_nonce_ledger_contract
from tools.ai_review.nonce_ledger import validate_existing_nonce_ledger
from tools.ai_review.nonce_ledger import validate_nonce_ledger_connection
from tools.ai_review.nonce_ledger import validate_nonce_ledger_directory
from tools.ai_review.nonce_ledger import validate_nonce_ledger_file_metadata
from tools.ai_review.path_safety import ensure_trusted_coordinator_directory
from tools.ai_review.path_safety import resolve_safe_input
from tools.ai_review.path_safety import resolve_safe_output
from tools.ai_review.preflight import PreflightError
from tools.ai_review.preflight import read_protected_file


_CANONICAL_INTEGER_LIMIT = 9_007_199_254_740_991
_SIGNATURE_DOMAIN = b"amazon-explorer-attestation-signature-v1\0"
_KEY_ID_DOMAIN = b"amazon-explorer-attestation-key-id-v1\0"
_ARGV_DOMAIN = b"amazon-explorer-attestation-argv-v1\0"


class AttestationError(ValueError):
    """Raised when provenance is incomplete, invalid, stale, or replayed."""


def _canonical_value(value: object) -> object:
    if isinstance(value, BaseModel):
        return _canonical_value(value.model_dump(mode="json"))
    if value is None or isinstance(value, (str, bool)):
        return value
    if isinstance(value, int):
        if abs(value) > _CANONICAL_INTEGER_LIMIT:
            raise TypeError("canonical JSON integers must fit the interoperable integer range")
        return value
    if isinstance(value, float):
        raise TypeError("canonical JSON forbids floating-point values")
    if isinstance(value, Mapping):
        if any(not isinstance(key, str) for key in value):
            raise TypeError("canonical JSON objects require string keys")
        ordered_keys = sorted(value, key=lambda key: key.encode("utf-16be"))
        return {key: _canonical_value(value[key]) for key in ordered_keys}
    if isinstance(value, (list, tuple)):
        return [_canonical_value(item) for item in value]
    raise TypeError(f"unsupported canonical JSON value: {type(value).__name__}")


def canonical_json_bytes(value: object) -> bytes:
    """Encode the harness' deliberately narrow, cross-runtime canonical JSON subset."""

    normalized = _canonical_value(value)
    try:
        return json.dumps(
            normalized,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=False,
        ).encode("utf-8")
    except UnicodeEncodeError as error:
        raise TypeError("canonical JSON strings must contain valid Unicode") from error


def canonical_sha256(value: object) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def argv_sha256(argv: Sequence[str]) -> str:
    arguments = list(argv)
    if not arguments or len(arguments) > 320:
        raise ValueError("attested argv must contain between 1 and 320 arguments")
    if any(not argument or "\x00" in argument for argument in arguments):
        raise ValueError("attested argv arguments must be non-empty and contain no NUL bytes")
    return hashlib.sha256(_ARGV_DOMAIN + canonical_json_bytes(arguments)).hexdigest()


class AttestationBinding(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    artifact_type: Literal["task", "policy", "gate", "tdd-red", "tdd-green", "review"]
    artifact_sha256: str = Field(pattern=SHA256_PATTERN)
    task_id: str = Field(pattern=r"^[A-Z][A-Z0-9_-]{0,63}$")
    task_sha256: str = Field(pattern=SHA256_PATTERN)
    base_sha: str = Field(pattern=GIT_SHA_PATTERN)
    head_sha: str = Field(pattern=GIT_SHA_PATTERN)
    candidate_sha256: str = Field(pattern=SHA256_PATTERN)
    snapshot_sha256: str = Field(pattern=SHA256_PATTERN)
    runtime_manifest_sha256: str = Field(pattern=SHA256_PATTERN)
    runner_image_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    runner_sha256: str = Field(pattern=SHA256_PATTERN)
    argv_sha256: str = Field(pattern=SHA256_PATTERN)
    log_sha256: str = Field(pattern=SHA256_PATTERN)
    role: str = Field(pattern=r"^[A-Za-z][A-Za-z0-9_.:-]{0,127}$")
    session_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
    request_sha256: str = Field(pattern=SHA256_PATTERN)
    response_sha256: str = Field(pattern=SHA256_PATTERN)


class AttestationStatement(AttestationBinding):
    nonce: str = Field(pattern=r"^[0-9a-f]{32,128}$")
    issued_at: int = Field(ge=0, le=4_102_444_800)


class AttestationExpectation(AttestationBinding):
    """Trusted values against which a signed, untrusted statement is compared."""


class SignedAttestation(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    algorithm: Literal["Ed25519"] = "Ed25519"
    key_id: str = Field(pattern=SHA256_PATTERN)
    statement: AttestationStatement
    signature: str = Field(min_length=86, max_length=86, pattern=r"^[A-Za-z0-9_-]{86}$")


def public_key_id(public_key: Ed25519PublicKey) -> str:
    raw = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return hashlib.sha256(_KEY_ID_DOMAIN + raw).hexdigest()


def _signed_bytes(statement: AttestationStatement) -> bytes:
    return _SIGNATURE_DOMAIN + canonical_json_bytes(statement)


def sign_attestation(
    statement: AttestationStatement,
    private_key: Ed25519PrivateKey,
) -> SignedAttestation:
    """Sign only from the trusted coordinator process; never pass candidate-owned keys."""

    if not isinstance(private_key, Ed25519PrivateKey):
        raise TypeError("attestation signing requires an Ed25519 private key")
    signature = private_key.sign(_signed_bytes(statement))
    encoded = base64.urlsafe_b64encode(signature).rstrip(b"=").decode("ascii")
    return SignedAttestation(
        key_id=public_key_id(private_key.public_key()),
        statement=statement,
        signature=encoded,
    )


class NonceLedger(Protocol):
    def reserve_many(self, nonces: Sequence[str]) -> bool:
        """Atomically reserve all nonces, or return False without reserving any."""


class InMemoryNonceLedger:
    """Thread-safe test/process ledger; production callers should use SqliteNonceLedger."""

    def __init__(self) -> None:
        self._nonces: set[str] = set()
        self._lock = threading.Lock()

    def reserve_many(self, nonces: Sequence[str]) -> bool:
        incoming = tuple(nonces)
        if len(incoming) != len(set(incoming)):
            return False
        with self._lock:
            if any(nonce in self._nonces for nonce in incoming):
                return False
            self._nonces.update(incoming)
        return True


class SqliteNonceLedger:
    """Persistent atomic replay ledger stored in a private coordinator directory."""

    def __init__(self, path: Path) -> None:
        parent = ensure_trusted_coordinator_directory(Path(os.path.abspath(path)).parent)
        absolute = parent / path.name
        expected_uid = os.geteuid()
        expected_gid = os.getegid()
        if absolute.exists() or absolute.is_symlink():
            safe_path = resolve_safe_input(absolute)
            try:
                identity = validate_existing_nonce_ledger(
                    safe_path,
                    expected_uid=expected_uid,
                    expected_gid=expected_gid,
                )
            except NonceLedgerContractError as exc:
                raise AttestationError(str(exc)) from None
        else:
            safe_path = resolve_safe_output(absolute)
            if any(parent.iterdir()):
                raise AttestationError(
                    "nonce ledger directory must be empty before database creation"
                )
            directory_fd = os.open(
                safe_path.parent,
                os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
            )
            try:
                ledger_fd = os.open(
                    safe_path.name,
                    os.O_RDWR
                    | os.O_CREAT
                    | os.O_EXCL
                    | getattr(os, "O_CLOEXEC", 0)
                    | getattr(os, "O_NOFOLLOW", 0),
                    0o600,
                    dir_fd=directory_fd,
                )
                try:
                    opened = os.fstat(ledger_fd)
                    created_identity = NonceLedgerFileIdentity(
                        device=opened.st_dev,
                        inode=opened.st_ino,
                        uid=opened.st_uid,
                        gid=opened.st_gid,
                    )
                    try:
                        validate_nonce_ledger_file_metadata(
                            safe_path,
                            expected_uid=expected_uid,
                            expected_gid=expected_gid,
                            expected_identity=created_identity,
                        )
                        create_nonce_ledger_contract(
                            safe_path,
                            expected_uid=expected_uid,
                            expected_gid=expected_gid,
                            expected_identity=created_identity,
                        )
                    except NonceLedgerContractError as exc:
                        raise AttestationError(str(exc)) from None
                    os.fsync(ledger_fd)
                    os.fsync(directory_fd)
                finally:
                    os.close(ledger_fd)
            finally:
                os.close(directory_fd)
            try:
                identity = validate_existing_nonce_ledger(
                    safe_path,
                    expected_uid=expected_uid,
                    expected_gid=expected_gid,
                )
            except NonceLedgerContractError as exc:
                raise AttestationError(str(exc)) from None
        self.path = safe_path
        self._identity: NonceLedgerFileIdentity = identity
        self._expected_uid = expected_uid
        self._expected_gid = expected_gid

    def _validate_closed_file(self) -> None:
        try:
            validate_nonce_ledger_file_metadata(
                self.path,
                expected_uid=self._expected_uid,
                expected_gid=self._expected_gid,
                expected_identity=self._identity,
            )
            validate_nonce_ledger_directory(self.path)
        except NonceLedgerContractError as exc:
            raise AttestationError(str(exc)) from None

    def reserve_many(self, nonces: Sequence[str]) -> bool:
        incoming = tuple(nonces)
        if any(
            type(nonce) is not str
            or not 32 <= len(nonce) <= 128
            or any(character not in "0123456789abcdef" for character in nonce)
            for nonce in incoming
        ):
            return False
        if len(incoming) != len(set(incoming)):
            return False
        try:
            connection = connect_existing_nonce_ledger_rw(
                self.path,
                expected_uid=self._expected_uid,
                expected_gid=self._expected_gid,
                expected_identity=self._identity,
            )
        except NonceLedgerContractError as exc:
            raise AttestationError(str(exc)) from None
        reserved = False
        reservation_error: AttestationError | None = None
        try:
            connection.execute("BEGIN IMMEDIATE")
            validate_nonce_ledger_connection(connection)
            reserved_at = int(time.time())
            connection.executemany(
                "INSERT INTO used_nonces(nonce, reserved_at) VALUES (?, ?)",
                [(nonce, reserved_at) for nonce in incoming],
            )
            connection.execute("COMMIT")
            reserved = True
        except sqlite3.IntegrityError:
            if connection.in_transaction:
                try:
                    connection.execute("ROLLBACK")
                except sqlite3.Error:
                    reservation_error = AttestationError("nonce ledger rollback failed")
        except NonceLedgerContractError as exc:
            if connection.in_transaction:
                try:
                    connection.execute("ROLLBACK")
                except sqlite3.Error:
                    pass
            reservation_error = AttestationError(str(exc))
        except sqlite3.Error:
            if connection.in_transaction:
                try:
                    connection.execute("ROLLBACK")
                except sqlite3.Error:
                    pass
            reservation_error = AttestationError("nonce ledger reservation failed")
        finally:
            connection.close()
        self._validate_closed_file()
        if reservation_error is not None:
            raise reservation_error from None
        return reserved


@dataclass(frozen=True)
class VerifiedAttestationSet:
    statements: tuple[AttestationStatement, ...]
    roles: tuple[str, ...]
    envelope_sha256s: tuple[str, ...]


def _decode_signature(encoded: str) -> bytes:
    try:
        decoded = base64.b64decode(encoded + "==", altchars=b"-_", validate=True)
    except (ValueError, TypeError) as error:
        raise AttestationError("attestation signature encoding is invalid") from error
    if len(decoded) != 64:
        raise AttestationError("attestation signature length is invalid")
    return decoded


def _verify_one_signature(
    envelope: SignedAttestation,
    trusted_public_keys: Mapping[str, Ed25519PublicKey],
) -> None:
    public_key = trusted_public_keys.get(envelope.key_id)
    if public_key is None:
        raise AttestationError("attestation does not reference a trusted key")
    if not isinstance(public_key, Ed25519PublicKey):
        raise AttestationError("trusted key registry contains a non-Ed25519 key")
    if not hmac.compare_digest(public_key_id(public_key), envelope.key_id):
        raise AttestationError("trusted key id does not match its Ed25519 public key")
    try:
        public_key.verify(_decode_signature(envelope.signature), _signed_bytes(envelope.statement))
    except InvalidSignature as error:
        raise AttestationError("attestation signature verification failed") from error


def _verify_binding(
    statement: AttestationStatement,
    expected: AttestationExpectation,
) -> None:
    actual_values = statement.model_dump(exclude={"issued_at", "nonce"})
    for field, expected_value in expected.model_dump().items():
        if actual_values[field] != expected_value:
            raise AttestationError(f"attestation binding mismatch: {field}")


def verify_attestation_set(
    envelopes: Sequence[SignedAttestation],
    *,
    trusted_public_keys: Mapping[str, Ed25519PublicKey],
    expectations: Mapping[str, AttestationExpectation],
    nonce_ledger: NonceLedger,
    now: int | None = None,
    max_age_seconds: int = 300,
    max_future_skew_seconds: int = 30,
) -> VerifiedAttestationSet:
    """Verify signatures/bindings as one batch, then atomically consume every nonce."""

    if not envelopes:
        raise AttestationError("at least one attestation is required")
    if max_age_seconds < 0 or max_future_skew_seconds < 0:
        raise ValueError("attestation time bounds must be non-negative")
    verification_time = int(time.time()) if now is None else now
    if isinstance(verification_time, bool) or not isinstance(verification_time, int):
        raise TypeError("attestation verification time must be an integer Unix timestamp")

    roles = [envelope.statement.role for envelope in envelopes]
    role_counts = Counter(roles)
    repeated_roles = sorted(role for role, count in role_counts.items() if count != 1)
    if repeated_roles:
        raise AttestationError(
            "attestation roles must appear exactly once: " + ", ".join(repeated_roles)
        )
    if set(roles) != set(expectations):
        missing = sorted(set(expectations) - set(roles))
        unexpected = sorted(set(roles) - set(expectations))
        detail = []
        if missing:
            detail.append("missing " + ", ".join(missing))
        if unexpected:
            detail.append("unexpected " + ", ".join(unexpected))
        raise AttestationError("attestation roles do not match expectations: " + "; ".join(detail))

    review_sessions = {
        envelope.statement.session_id
        for envelope in envelopes
        if envelope.statement.role in {"reviewer", "adversary"}
    }
    if {"reviewer", "adversary"}.issubset(roles) and len(review_sessions) != 2:
        raise AttestationError("reviewer and adversary attestations require distinct sessions")

    ordered = sorted(envelopes, key=lambda envelope: envelope.statement.role)
    for envelope in ordered:
        _verify_one_signature(envelope, trusted_public_keys)
        statement = envelope.statement
        _verify_binding(statement, expectations[statement.role])
        if statement.issued_at > verification_time + max_future_skew_seconds:
            raise AttestationError(f"attestation issued in the future: {statement.role}")
        if verification_time - statement.issued_at > max_age_seconds:
            raise AttestationError(f"attestation expired: {statement.role}")

    nonces = [envelope.statement.nonce for envelope in ordered]
    if len(nonces) != len(set(nonces)):
        raise AttestationError("attestation nonce is duplicated within the bundle")
    if not nonce_ledger.reserve_many(nonces):
        raise AttestationError("attestation replay detected")

    return VerifiedAttestationSet(
        statements=tuple(envelope.statement for envelope in ordered),
        roles=tuple(envelope.statement.role for envelope in ordered),
        envelope_sha256s=tuple(canonical_sha256(envelope) for envelope in ordered),
    )


def load_coordinator_private_key(
    path: Path,
    *,
    candidate_root: Path,
    candidate_uid: int,
    password: bytes | None = None,
) -> Ed25519PrivateKey:
    """Load a coordinator-owned key that the different-UID candidate cannot read via DAC."""

    if isinstance(candidate_uid, bool) or not isinstance(candidate_uid, int) or candidate_uid < 1:
        raise AttestationError("candidate must run as a non-root OS uid")
    safe_path = resolve_safe_input(path)
    candidate = candidate_root.resolve(strict=True)
    if not candidate.is_dir():
        raise AttestationError("candidate root must be a directory")
    if safe_path == candidate or safe_path.is_relative_to(candidate):
        raise AttestationError("coordinator private key must be outside the candidate root")

    key_stat = safe_path.stat()
    parent_stat = safe_path.parent.stat()
    if hasattr(os, "getuid"):
        coordinator_uid = os.getuid()
        if key_stat.st_uid != coordinator_uid or parent_stat.st_uid != coordinator_uid:
            raise AttestationError("coordinator private key must be owned by the coordinator user")
        if candidate_uid == coordinator_uid:
            raise AttestationError("candidate and coordinator key must use a different OS uid")
    if stat.S_IMODE(key_stat.st_mode) & 0o077:
        raise AttestationError("coordinator private key file must be private")
    if stat.S_IMODE(parent_stat.st_mode) & 0o077:
        raise AttestationError("coordinator private key directory must be private")

    try:
        private_key = serialization.load_pem_private_key(safe_path.read_bytes(), password=password)
    except (TypeError, ValueError) as error:
        raise AttestationError("coordinator private key could not be decoded") from error
    if not isinstance(private_key, Ed25519PrivateKey):
        raise AttestationError("coordinator private key must use Ed25519")
    return private_key


def load_trusted_public_key(
    path: Path,
    *,
    expected_sha256: str,
    candidate_uid: int,
) -> Ed25519PublicKey:
    """Load a candidate-immutable public key whose raw file digest is externally anchored."""

    try:
        _evidence, raw = read_protected_file(
            path,
            candidate_uid=candidate_uid,
            label="coordinator Ed25519 public key",
            expected_sha256=expected_sha256,
        )
    except PreflightError as error:
        raise AttestationError(str(error)) from error
    try:
        public_key = serialization.load_pem_public_key(raw)
    except (TypeError, ValueError) as error:
        raise AttestationError("coordinator public key could not be decoded") from error
    if not isinstance(public_key, Ed25519PublicKey):
        raise AttestationError("coordinator public key must use Ed25519")
    return public_key
