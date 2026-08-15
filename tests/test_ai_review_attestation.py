from __future__ import annotations

import base64
import concurrent.futures
import hashlib
import json
import os
import sqlite3
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import ValidationError

from tools.ai_review.attestation import AttestationError
from tools.ai_review.attestation import AttestationExpectation
from tools.ai_review.attestation import AttestationStatement
from tools.ai_review.attestation import InMemoryNonceLedger
from tools.ai_review.attestation import SqliteNonceLedger
from tools.ai_review.attestation import SignedAttestation
from tools.ai_review.attestation import argv_sha256
from tools.ai_review.attestation import canonical_json_bytes
from tools.ai_review.attestation import canonical_sha256
from tools.ai_review.attestation import load_coordinator_private_key
from tools.ai_review.attestation import load_trusted_public_key
from tools.ai_review.attestation import public_key_id
from tools.ai_review.attestation import sign_attestation
from tools.ai_review.attestation import verify_attestation_set
from tools.ai_review.models import TddEvidence


TASK_SHA = "1" * 64
BASE_SHA = "2" * 40
HEAD_SHA = "3" * 40
CANDIDATE_SHA = "4" * 64
SNAPSHOT_SHA = "5" * 64
RUNTIME_SHA = "6" * 64
RUNNER_IMAGE_DIGEST = "sha256:" + "d" * 64
RUNNER_SHA = "7" * 64
ARGV_SHA = "8" * 64
LOG_SHA = "9" * 64
REQUEST_SHA = "a" * 64
RESPONSE_SHA = "b" * 64
ARTIFACT_SHA = "c" * 64
NOW = 1_800_000_000


def statement_payload(*, role: str = "reviewer", nonce: str = "d" * 32) -> dict:
    return {
        "schema_version": "1.0",
        "artifact_type": "review",
        "artifact_sha256": ARTIFACT_SHA,
        "task_id": "TASK-TEST",
        "task_sha256": TASK_SHA,
        "base_sha": BASE_SHA,
        "head_sha": HEAD_SHA,
        "candidate_sha256": CANDIDATE_SHA,
        "snapshot_sha256": SNAPSHOT_SHA,
        "runtime_manifest_sha256": RUNTIME_SHA,
        "runner_image_digest": RUNNER_IMAGE_DIGEST,
        "runner_sha256": RUNNER_SHA,
        "argv_sha256": ARGV_SHA,
        "log_sha256": LOG_SHA,
        "nonce": nonce,
        "issued_at": NOW,
        "role": role,
        "session_id": f"session-{role}",
        "request_sha256": REQUEST_SHA,
        "response_sha256": RESPONSE_SHA,
    }


def expectation(statement: AttestationStatement) -> AttestationExpectation:
    return AttestationExpectation.model_validate(
        statement.model_dump(exclude={"issued_at", "nonce"})
    )


def test_canonical_json_is_stable_and_rejects_ambiguous_values():
    left = {"z": [True, None, "日本語"], "a": {"n": 7}}
    right = {"a": {"n": 7}, "z": [True, None, "日本語"]}

    assert canonical_json_bytes(left) == canonical_json_bytes(right)
    assert canonical_sha256(left) == canonical_sha256(right)
    assert canonical_json_bytes(left).decode() == '{"a":{"n":7},"z":[true,null,"日本語"]}'
    assert canonical_json_bytes({"\ue000": 2, "😀": 1}).decode() == '{"😀":1,"\ue000":2}'

    with pytest.raises(TypeError, match="floating-point"):
        canonical_json_bytes({"value": 1.5})
    with pytest.raises(TypeError, match="string keys"):
        canonical_json_bytes({1: "ambiguous"})


def test_argv_has_a_stable_domain_separated_digest():
    assert argv_sha256(["uv", "run", "pytest"]) == argv_sha256(("uv", "run", "pytest"))
    assert argv_sha256(["uv", "run", "pytest"]) != canonical_sha256(["uv", "run", "pytest"])


def test_signed_attestation_round_trip_binds_every_security_dimension():
    private_key = Ed25519PrivateKey.generate()
    statement = AttestationStatement.model_validate(statement_payload())
    envelope = sign_attestation(statement, private_key)
    ledger = InMemoryNonceLedger()

    verified = verify_attestation_set(
        [envelope],
        trusted_public_keys={public_key_id(private_key.public_key()): private_key.public_key()},
        expectations={"reviewer": expectation(statement)},
        nonce_ledger=ledger,
        now=NOW + 1,
    )

    assert verified.statements == (statement,)
    assert verified.roles == ("reviewer",)
    assert len(base64.urlsafe_b64decode(envelope.signature + "==")) == 64


@pytest.mark.parametrize(
    ("field", "other"),
    [
        ("artifact_sha256", "0" * 64),
        ("task_id", "TASK-OTHER"),
        ("task_sha256", "0" * 64),
        ("base_sha", "0" * 40),
        ("head_sha", "0" * 40),
        ("candidate_sha256", "0" * 64),
        ("snapshot_sha256", "0" * 64),
        ("runtime_manifest_sha256", "0" * 64),
        ("runner_image_digest", "sha256:" + "0" * 64),
        ("runner_sha256", "0" * 64),
        ("argv_sha256", "0" * 64),
        ("log_sha256", "0" * 64),
        ("role", "adversary"),
        ("session_id", "session-other"),
        ("request_sha256", "0" * 64),
        ("response_sha256", "0" * 64),
    ],
)
def test_verifier_rejects_wrong_task_candidate_snapshot_runtime_and_io_bindings(field, other):
    private_key = Ed25519PrivateKey.generate()
    statement = AttestationStatement.model_validate(statement_payload())
    envelope = sign_attestation(statement, private_key)
    expected_payload = expectation(statement).model_dump()
    expected_payload[field] = other

    with pytest.raises(AttestationError, match="binding mismatch"):
        verify_attestation_set(
            [envelope],
            trusted_public_keys={public_key_id(private_key.public_key()): private_key.public_key()},
            expectations={"reviewer": AttestationExpectation.model_validate(expected_payload)},
            nonce_ledger=InMemoryNonceLedger(),
            now=NOW,
        )


def test_tampering_wrong_key_stale_timestamp_and_replay_are_rejected():
    private_key = Ed25519PrivateKey.generate()
    wrong_key = Ed25519PrivateKey.generate()
    statement = AttestationStatement.model_validate(statement_payload())
    envelope = sign_attestation(statement, private_key)
    keys = {public_key_id(private_key.public_key()): private_key.public_key()}
    expected = {"reviewer": expectation(statement)}

    tampered = envelope.model_copy(
        update={"statement": statement.model_copy(update={"log_sha256": "0" * 64})}
    )
    with pytest.raises(AttestationError, match="signature"):
        verify_attestation_set(
            [tampered],
            trusted_public_keys=keys,
            expectations=expected,
            nonce_ledger=InMemoryNonceLedger(),
            now=NOW,
        )
    with pytest.raises(AttestationError, match="trusted key"):
        verify_attestation_set(
            [envelope],
            trusted_public_keys={public_key_id(wrong_key.public_key()): wrong_key.public_key()},
            expectations=expected,
            nonce_ledger=InMemoryNonceLedger(),
            now=NOW,
        )
    with pytest.raises(AttestationError, match="expired"):
        verify_attestation_set(
            [envelope],
            trusted_public_keys=keys,
            expectations=expected,
            nonce_ledger=InMemoryNonceLedger(),
            now=NOW + 301,
        )
    with pytest.raises(AttestationError, match="future"):
        verify_attestation_set(
            [envelope],
            trusted_public_keys=keys,
            expectations=expected,
            nonce_ledger=InMemoryNonceLedger(),
            now=NOW - 31,
        )

    ledger = InMemoryNonceLedger()
    verify_attestation_set(
        [envelope],
        trusted_public_keys=keys,
        expectations=expected,
        nonce_ledger=ledger,
        now=NOW,
    )
    with pytest.raises(AttestationError, match="replay"):
        verify_attestation_set(
            [envelope],
            trusted_public_keys=keys,
            expectations=expected,
            nonce_ledger=ledger,
            now=NOW,
        )


def test_duplicate_or_missing_roles_and_duplicate_nonce_are_rejected():
    private_key = Ed25519PrivateKey.generate()
    reviewer = AttestationStatement.model_validate(statement_payload())
    duplicate = reviewer.model_copy(update={"session_id": "session-reviewer-2"})
    keys = {public_key_id(private_key.public_key()): private_key.public_key()}

    with pytest.raises(AttestationError, match="missing adversary"):
        verify_attestation_set(
            [sign_attestation(reviewer, private_key)],
            trusted_public_keys=keys,
            expectations={
                "reviewer": expectation(reviewer),
                "adversary": expectation(
                    AttestationStatement.model_validate(
                        statement_payload(role="adversary", nonce="e" * 32)
                    )
                ),
            },
            nonce_ledger=InMemoryNonceLedger(),
            now=NOW,
        )

    with pytest.raises(AttestationError, match="exactly once"):
        verify_attestation_set(
            [sign_attestation(reviewer, private_key), sign_attestation(duplicate, private_key)],
            trusted_public_keys=keys,
            expectations={"reviewer": expectation(reviewer)},
            nonce_ledger=InMemoryNonceLedger(),
            now=NOW,
        )

    adversary = AttestationStatement.model_validate(
        statement_payload(role="adversary", nonce=reviewer.nonce)
    )
    with pytest.raises(AttestationError, match="nonce"):
        verify_attestation_set(
            [sign_attestation(reviewer, private_key), sign_attestation(adversary, private_key)],
            trusted_public_keys=keys,
            expectations={
                "reviewer": expectation(reviewer),
                "adversary": expectation(adversary),
            },
            nonce_ledger=InMemoryNonceLedger(),
            now=NOW,
        )

    same_session = adversary.model_copy(
        update={"nonce": "e" * 32, "session_id": reviewer.session_id}
    )
    with pytest.raises(AttestationError, match="distinct sessions"):
        verify_attestation_set(
            [sign_attestation(reviewer, private_key), sign_attestation(same_session, private_key)],
            trusted_public_keys=keys,
            expectations={
                "reviewer": expectation(reviewer),
                "adversary": expectation(same_session),
            },
            nonce_ledger=InMemoryNonceLedger(),
            now=NOW,
        )


def test_sqlite_nonce_ledger_rejects_replay_across_instances(tmp_path: Path):
    coordinator = tmp_path / "ledger"
    coordinator.mkdir(mode=0o700)
    path = coordinator / "nonces.sqlite3"

    assert SqliteNonceLedger(path).reserve_many(["a" * 32]) is True
    resumed = SqliteNonceLedger(path)
    assert resumed.reserve_many(["b" * 32]) is True
    assert resumed.reserve_many(["a" * 32]) is False


def test_sqlite_nonce_ledger_rolls_back_a_partially_conflicting_batch(tmp_path: Path) -> None:
    coordinator = tmp_path / "ledger"
    coordinator.mkdir(mode=0o700)
    ledger = SqliteNonceLedger(coordinator / "nonces.sqlite3")

    assert ledger.reserve_many(["a" * 32, "b" * 32]) is True
    assert ledger.reserve_many(["b" * 32, "c" * 32]) is False
    assert ledger.reserve_many(["c" * 32]) is True


def _write_unsafe_nonce_ledger(path: Path, statements: list[str]) -> None:
    connection = sqlite3.connect(path)
    try:
        for statement in statements:
            connection.execute(statement)
        connection.commit()
    finally:
        connection.close()
    path.chmod(0o600)


@pytest.mark.parametrize(
    "statements",
    [
        ["CREATE TABLE used_nonces (nonce TEXT, reserved_at INTEGER NOT NULL)"],
        [
            "CREATE TABLE used_nonces (nonce TEXT, reserved_at INTEGER NOT NULL)",
            "INSERT INTO used_nonces VALUES ('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 1)",
            "INSERT INTO used_nonces VALUES ('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 2)",
        ],
        [
            "CREATE TABLE used_nonces ("
            "nonce TEXT PRIMARY KEY CHECK(length(nonce) BETWEEN 32 AND 128), "
            "reserved_at INTEGER NOT NULL)",
            "CREATE TABLE extra_state (value TEXT)",
        ],
        [
            "CREATE TABLE used_nonces ("
            "nonce TEXT PRIMARY KEY CHECK(length(nonce) BETWEEN 32 AND 128), "
            "reserved_at INTEGER NOT NULL)",
            "CREATE TRIGGER rewrite_nonce AFTER INSERT ON used_nonces BEGIN "
            "UPDATE used_nonces SET reserved_at = 0 WHERE nonce = NEW.nonce; END",
        ],
        [
            "CREATE TABLE used_nonces ("
            "nonce TEXT PRIMARY KEY CHECK(length(nonce) BETWEEN 32 AND 128), "
            "reserved_at INTEGER NOT NULL)",
            "CREATE VIEW exposed_nonces AS SELECT * FROM used_nonces",
        ],
    ],
    ids=("missing-primary-key", "duplicate-nonce", "extra-table", "trigger", "view"),
)
def test_sqlite_nonce_ledger_rejects_noncanonical_schema(
    tmp_path: Path,
    statements: list[str],
) -> None:
    coordinator = tmp_path / "ledger"
    coordinator.mkdir(mode=0o700)
    path = coordinator / "nonces.sqlite3"
    _write_unsafe_nonce_ledger(path, statements)

    with pytest.raises(AttestationError, match="contract"):
        SqliteNonceLedger(path)


def test_sqlite_nonce_ledger_rejects_wal_mode_and_sidecars(tmp_path: Path) -> None:
    coordinator = tmp_path / "ledger"
    coordinator.mkdir(mode=0o700)
    path = coordinator / "nonces.sqlite3"
    SqliteNonceLedger(path)

    connection = sqlite3.connect(path)
    try:
        assert connection.execute("PRAGMA journal_mode=WAL").fetchone() == ("wal",)
    finally:
        connection.close()

    with pytest.raises(AttestationError, match="contract|sidecar"):
        SqliteNonceLedger(path)

    connection = sqlite3.connect(path)
    try:
        assert connection.execute("PRAGMA journal_mode=DELETE").fetchone() == ("delete",)
    finally:
        connection.close()
    (coordinator / "nonces.sqlite3-journal").write_bytes(b"untrusted journal")
    with pytest.raises(AttestationError, match="sidecar"):
        SqliteNonceLedger(path)


@pytest.mark.parametrize(
    ("pragma", "value"),
    [("application_id", 0), ("user_version", 99)],
)
def test_sqlite_nonce_ledger_rejects_wrong_persistent_pragmas(
    tmp_path: Path,
    pragma: str,
    value: int,
) -> None:
    coordinator = tmp_path / "ledger"
    coordinator.mkdir(mode=0o700)
    path = coordinator / "nonces.sqlite3"
    SqliteNonceLedger(path)
    connection = sqlite3.connect(path)
    try:
        connection.execute(f"PRAGMA {pragma}={value}")
    finally:
        connection.close()

    with pytest.raises(AttestationError, match="contract"):
        SqliteNonceLedger(path)


def test_sqlite_nonce_ledger_rejects_corrupt_database(tmp_path: Path) -> None:
    coordinator = tmp_path / "ledger"
    coordinator.mkdir(mode=0o700)
    path = coordinator / "nonces.sqlite3"
    path.write_bytes(b"not a sqlite database")
    path.chmod(0o600)

    with pytest.raises(AttestationError, match="contract"):
        SqliteNonceLedger(path)


def test_sqlite_nonce_ledger_rejects_unsafe_file_metadata(tmp_path: Path) -> None:
    coordinator = tmp_path / "ledger"
    coordinator.mkdir(mode=0o700)
    path = coordinator / "nonces.sqlite3"
    SqliteNonceLedger(path)

    path.chmod(0o640)
    with pytest.raises(AttestationError, match="mode 0600"):
        SqliteNonceLedger(path)
    path.chmod(0o600)

    hardlink = coordinator / "hardlink.sqlite3"
    os.link(path, hardlink)
    with pytest.raises((AttestationError, ValueError), match="hardlink"):
        SqliteNonceLedger(path)
    hardlink.unlink()

    target = tmp_path / "target.sqlite3"
    path.rename(target)
    path.symlink_to(target)
    with pytest.raises((AttestationError, ValueError), match="symlink"):
        SqliteNonceLedger(path)


@pytest.mark.skipif(os.geteuid() != 0, reason="changing file ownership requires root")
def test_sqlite_nonce_ledger_rejects_wrong_owner(tmp_path: Path) -> None:
    coordinator = tmp_path / "ledger"
    coordinator.mkdir(mode=0o700)
    path = coordinator / "nonces.sqlite3"
    SqliteNonceLedger(path)
    os.chown(path, 65_534, os.getegid())

    with pytest.raises(AttestationError, match="owner"):
        SqliteNonceLedger(path)


def test_sqlite_nonce_ledger_reservation_is_atomic_across_instances(tmp_path: Path) -> None:
    coordinator = tmp_path / "ledger"
    coordinator.mkdir(mode=0o700)
    path = coordinator / "nonces.sqlite3"
    first = SqliteNonceLedger(path)
    second = SqliteNonceLedger(path)

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        results = tuple(
            executor.map(lambda ledger: ledger.reserve_many(["b" * 32]), (first, second))
        )

    assert sorted(results) == [False, True]


def test_sqlite_nonce_ledger_does_not_echo_rejected_nonce(tmp_path: Path) -> None:
    coordinator = tmp_path / "ledger"
    coordinator.mkdir(mode=0o700)
    ledger = SqliteNonceLedger(coordinator / "nonces.sqlite3")
    secret_marker = "DO-NOT-ECHO-" + "c" * 32

    try:
        result = ledger.reserve_many([secret_marker])
    except Exception as exc:  # pragma: no cover - either fail-closed form is acceptable
        assert secret_marker not in str(exc)
    else:
        assert result is False


def test_coordinator_private_key_loader_enforces_external_private_different_uid_storage(
    tmp_path: Path,
):
    private_dir = tmp_path / "coordinator"
    private_dir.mkdir(mode=0o700)
    candidate = tmp_path / "candidate"
    candidate.mkdir()
    key_path = private_dir / "signing-key.pem"
    private_key = Ed25519PrivateKey.generate()
    key_path.write_bytes(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    key_path.chmod(0o600)
    candidate_uid = os.getuid() + 1

    loaded = load_coordinator_private_key(
        key_path,
        candidate_root=candidate,
        candidate_uid=candidate_uid,
    )
    assert public_key_id(loaded.public_key()) == public_key_id(private_key.public_key())

    key_path.chmod(0o640)
    with pytest.raises(AttestationError, match="private"):
        load_coordinator_private_key(
            key_path,
            candidate_root=candidate,
            candidate_uid=candidate_uid,
        )
    key_path.chmod(0o600)
    with pytest.raises(AttestationError, match="non-root|different OS uid"):
        load_coordinator_private_key(
            key_path,
            candidate_root=candidate,
            candidate_uid=os.getuid(),
        )


def test_public_key_loader_requires_candidate_immutable_expected_file_digest(tmp_path: Path):
    key_dir = tmp_path / "trusted-public-key"
    key_dir.mkdir(mode=0o700)
    key_path = key_dir / "coordinator-public.pem"
    private_key = Ed25519PrivateKey.generate()
    raw = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    key_path.write_bytes(raw)
    key_path.chmod(0o444)

    loaded = load_trusted_public_key(
        key_path,
        expected_sha256=hashlib.sha256(raw).hexdigest(),
        candidate_uid=os.getuid() + 1,
    )
    assert public_key_id(loaded) == public_key_id(private_key.public_key())

    with pytest.raises(AttestationError, match="SHA-256"):
        load_trusted_public_key(
            key_path,
            expected_sha256="0" * 64,
            candidate_uid=os.getuid() + 1,
        )


def tdd_payload() -> dict:
    test_patch = "d" * 64
    return {
        "schema_version": "2.0",
        "task_id": "TASK-TEST",
        "task_sha256": TASK_SHA,
        "base_sha": BASE_SHA,
        "head_sha": HEAD_SHA,
        "patch_sha256": CANDIDATE_SHA,
        "acceptance_test_id": "AT-1",
        "command": ["uv", "run", "pytest", "tests/test_example.py"],
        "test_paths": ["tests/test_example.py"],
        "test_manifest_sha256": "e" * 64,
        "test_patch_sha256": test_patch,
        "red_snapshot_sha256": "6" * 64,
        "green_snapshot_sha256": "7" * 64,
        "red": {
            "exit_code": 1,
            "log_sha256": "f" * 64,
            "failure_fingerprint_sha256": "0" * 64,
            "test_patch_sha256": test_patch,
        },
        "green": {
            "exit_code": 0,
            "log_sha256": "1" * 64,
            "test_patch_sha256": test_patch,
        },
    }


def test_tdd_evidence_v2_requires_distinct_measured_red_and_green_snapshots():
    evidence = TddEvidence.model_validate(tdd_payload())

    assert evidence.schema_version == "2.0"
    assert evidence.red_snapshot_sha256 == "6" * 64
    assert evidence.green_snapshot_sha256 == "7" * 64

    same_snapshot = tdd_payload()
    same_snapshot["green_snapshot_sha256"] = same_snapshot["red_snapshot_sha256"]
    with pytest.raises(ValidationError, match="distinct measured RED and GREEN"):
        TddEvidence.model_validate(same_snapshot)


def test_tdd_v1_remains_diagnostic_only_and_v2_without_bindings_fails_closed():
    version_one = tdd_payload()
    version_one["schema_version"] = "1.0"
    version_one.pop("red_snapshot_sha256")
    version_one.pop("green_snapshot_sha256")
    assert TddEvidence.model_validate(version_one).schema_version == "1.0"

    ambiguous_v1 = tdd_payload()
    ambiguous_v1["schema_version"] = "1.0"
    with pytest.raises(ValidationError, match="must not claim v2"):
        TddEvidence.model_validate(ambiguous_v1)

    missing = tdd_payload()
    missing.pop("red_snapshot_sha256")
    with pytest.raises(ValidationError, match="requires RED and GREEN"):
        TddEvidence.model_validate(missing)


def test_checked_in_attestation_schema_matches_pydantic_contract():
    root = Path(__file__).resolve().parents[1]
    checked_in = json.loads((root / "specs/schemas/attestation.schema.json").read_text())
    assert checked_in == SignedAttestation.model_json_schema()
