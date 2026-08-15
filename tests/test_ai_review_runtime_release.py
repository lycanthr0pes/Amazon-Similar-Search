from __future__ import annotations

import hashlib
import json
import os
import sys
import zipfile
from pathlib import Path

import pytest

from tools.ai_review.preflight import preflight_runtime
from tools.ai_review.runtime_release import RuntimeReleaseError
from tools.ai_review.runtime_release import build_runtime_manifest
from tools.ai_review.runtime_release import build_schema_bundle
from tools.ai_review.runtime_release import generate_coordinator_keypair
from tools.ai_review.runtime_release import load_schema_directory
from tools.ai_review.runtime_release import validate_release_task


def write_file(path: Path, data: bytes, mode: int = 0o600) -> Path:
    path.write_bytes(data)
    path.chmod(mode)
    return path


def make_zipapp(path: Path) -> Path:
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("__main__.py", "raise SystemExit(0)\n")
    path.chmod(0o600)
    return path


def task_v2_bytes(harness: Path, *, schema_version: str = "2.0") -> bytes:
    payload = {
        "schema_version": schema_version,
        "task_id": "TASK-RELEASE",
        "base_sha": "1" * 40,
        "trusted_harness_sha256": hashlib.sha256(harness.read_bytes()).hexdigest(),
        "objective": "release contractを検証する",
        "requirements": [{"id": "REQ-1", "text": "固定したテストを実行する"}],
        "review_prompts": {
            "reviewer_sha256": "2" * 64,
            "adversary_sha256": "3" * 64,
        },
        "candidate_commit": {
            "message": "TASK-RELEASE",
            "author_name": "Release Test",
            "author_email": "release@example.invalid",
            "timestamp": 946684800,
            "timezone": "+0000",
        },
        "acceptance_tests": [
            {
                "id": "AT-1",
                "kind": "test",
                "command": ["pytest", "tests/test_release.py"],
                "expected_exit_code": 0,
                "expected_red_exit_codes": [1],
                "expected_red_fingerprint_sha256": "4" * 64,
                "test_paths": ["tests/test_release.py"],
            }
        ],
        "allowed_paths": ["src/**", "tests/**"],
        "denied_paths": [".env", "cache/**"],
        "limits": {"max_changed_files": 10, "max_added_lines": 100},
        "network_policy": "deny",
    }
    return (json.dumps(payload, ensure_ascii=False, sort_keys=True) + "\n").encode()


def test_schema_bundle_is_canonical_content_addressed_and_exclusive(tmp_path: Path) -> None:
    tmp_path.chmod(0o700)
    output = tmp_path / "schemas.json"
    schemas = {
        "z.schema.json": {"type": "object", "title": "Z"},
        "a.schema.json": {"title": "A", "type": "string"},
    }

    digest = build_schema_bundle(schemas, output)
    raw = output.read_bytes()
    payload = json.loads(raw)

    assert raw.endswith(b"\n")
    assert digest == hashlib.sha256(raw).hexdigest()
    assert list(payload["schemas"]) == ["a.schema.json", "z.schema.json"]
    assert (
        payload["schema_sha256"]["a.schema.json"]
        == hashlib.sha256(b'{"title":"A","type":"string"}').hexdigest()
    )
    with pytest.raises(ValueError, match="overwrite"):
        build_schema_bundle(schemas, output)


def test_runtime_manifest_binds_every_asset_and_preflight_accepts_it(tmp_path: Path) -> None:
    tmp_path.chmod(0o700)
    python = Path(sys.executable).resolve(strict=True)
    harness = make_zipapp(tmp_path / "harness.pyz")
    task = write_file(tmp_path / "task.json", task_v2_bytes(harness))
    lock = write_file(tmp_path / "uv.lock", b"version = 1\n")
    schemas = write_file(tmp_path / "schemas.json", b'{"schema_version":"1.0"}\n')
    public_key = write_file(tmp_path / "coordinator-public.pem", b"test-public-key\n")
    egress_policy = write_file(
        tmp_path / "broker-egress-policy.json",
        (
            Path(__file__).resolve().parents[1] / "specs/policies/broker-egress-policy.json"
        ).read_bytes(),
    )
    pricing_policy = write_file(
        tmp_path / "openai-pricing-policy.json",
        (
            Path(__file__).resolve().parents[1] / "specs/policies/openai-pricing-policy.json"
        ).read_bytes(),
    )
    manifest_path = tmp_path / "runtime-manifest.json"

    digest = build_runtime_manifest(
        output=manifest_path,
        python=python,
        harness=harness,
        task=task,
        dependency_lock=lock,
        schema_bundle=schemas,
        coordinator_public_key=public_key,
        broker_egress_policy=egress_policy,
        openai_pricing_policy=pricing_policy,
        coordinator_image_digest="sha256:" + "3" * 64,
        offline_runner_image_digest="sha256:" + "1" * 64,
        broker_image_digest="sha256:" + "2" * 64,
        broker_gateway_image_digest="sha256:" + "4" * 64,
        broker_packet_reservation_limit=544_000,
        broker_packet_cost_limit_microusd=4_540_000,
    )

    payload = json.loads(manifest_path.read_bytes())
    assert digest == hashlib.sha256(manifest_path.read_bytes()).hexdigest()
    assert payload["python"]["path"] == str(python)
    assert payload["task"]["sha256"] == hashlib.sha256(task.read_bytes()).hexdigest()
    candidate_uid = 65_534 if os.geteuid() != 65_534 else 65_533
    with preflight_runtime(
        manifest_path=manifest_path,
        expected_manifest_sha256=digest,
        candidate_uid=candidate_uid,
    ) as evidence:
        assert evidence.manifest_sha256 == digest
        assert evidence.coordinator_image_digest == "sha256:" + "3" * 64
        assert evidence.offline_runner_image_digest == "sha256:" + "1" * 64
        assert evidence.broker_image_digest == "sha256:" + "2" * 64
        assert evidence.broker_gateway_image_digest == "sha256:" + "4" * 64
        assert evidence.broker_packet_reservation_limit == 544_000
        assert evidence.broker_packet_cost_limit_microusd == 4_540_000
        assert (
            evidence.openai_pricing_policy.sha256
            == hashlib.sha256(pricing_policy.read_bytes()).hexdigest()
        )


def test_runtime_manifest_rejects_mutable_contract_shapes(tmp_path: Path) -> None:
    tmp_path.chmod(0o700)
    asset = write_file(tmp_path / "asset", b"x")
    harness = make_zipapp(tmp_path / "harness.pyz")

    with pytest.raises(RuntimeReleaseError, match="distinct"):
        build_runtime_manifest(
            output=tmp_path / "runtime.json",
            python=Path(sys.executable).resolve(strict=True),
            harness=harness,
            task=asset,
            dependency_lock=asset,
            schema_bundle=asset,
            coordinator_public_key=asset,
            broker_egress_policy=asset,
            openai_pricing_policy=asset,
            coordinator_image_digest="sha256:" + "1" * 64,
            offline_runner_image_digest="sha256:" + "1" * 64,
            broker_image_digest="sha256:" + "1" * 64,
            broker_gateway_image_digest="sha256:" + "1" * 64,
            broker_packet_reservation_limit=544_000,
            broker_packet_cost_limit_microusd=4_540_000,
        )

    distinct = [f"sha256:{index:064x}" for index in range(1, 5)]
    with pytest.raises(RuntimeReleaseError, match="egress policy"):
        build_runtime_manifest(
            output=tmp_path / "forged-policy-runtime.json",
            python=Path(sys.executable).resolve(strict=True),
            harness=harness,
            task=asset,
            dependency_lock=asset,
            schema_bundle=asset,
            coordinator_public_key=asset,
            broker_egress_policy=asset,
            openai_pricing_policy=asset,
            coordinator_image_digest=distinct[0],
            offline_runner_image_digest=distinct[1],
            broker_image_digest=distinct[2],
            broker_gateway_image_digest=distinct[3],
            broker_packet_reservation_limit=544_000,
            broker_packet_cost_limit_microusd=4_540_000,
        )


@pytest.mark.parametrize(
    ("schema_version", "harness_digest", "message"),
    [
        ("1.0", None, "TaskSpec v2"),
        ("2.0", "f" * 64, "trusted harness"),
    ],
)
def test_runtime_manifest_requires_v2_task_bound_to_exact_harness(
    tmp_path: Path,
    schema_version: str,
    harness_digest: str | None,
    message: str,
) -> None:
    tmp_path.chmod(0o700)
    harness = make_zipapp(tmp_path / "harness.pyz")
    payload = json.loads(task_v2_bytes(harness))
    payload["schema_version"] = schema_version
    if harness_digest is not None:
        payload["trusted_harness_sha256"] = harness_digest
    task = write_file(
        tmp_path / "task.json",
        (json.dumps(payload, sort_keys=True) + "\n").encode(),
    )
    lock = write_file(tmp_path / "uv.lock", b"version = 1\n")
    schemas = write_file(tmp_path / "schemas.json", b'{"schema_version":"1.0"}\n')
    public_key = write_file(tmp_path / "coordinator-public.pem", b"test-public-key\n")
    egress_policy = write_file(
        tmp_path / "broker-egress-policy.json",
        (
            Path(__file__).resolve().parents[1] / "specs/policies/broker-egress-policy.json"
        ).read_bytes(),
    )
    pricing_policy = write_file(
        tmp_path / "openai-pricing-policy.json",
        (
            Path(__file__).resolve().parents[1] / "specs/policies/openai-pricing-policy.json"
        ).read_bytes(),
    )

    with pytest.raises(RuntimeReleaseError, match=message):
        build_runtime_manifest(
            output=tmp_path / "runtime-manifest.json",
            python=Path(sys.executable).resolve(strict=True),
            harness=harness,
            task=task,
            dependency_lock=lock,
            schema_bundle=schemas,
            coordinator_public_key=public_key,
            broker_egress_policy=egress_policy,
            openai_pricing_policy=pricing_policy,
            coordinator_image_digest="sha256:" + "1" * 64,
            offline_runner_image_digest="sha256:" + "2" * 64,
            broker_image_digest="sha256:" + "3" * 64,
            broker_gateway_image_digest="sha256:" + "4" * 64,
            broker_packet_reservation_limit=544_000,
            broker_packet_cost_limit_microusd=4_540_000,
        )


def test_release_task_parse_is_strict_and_rejects_duplicate_keys(tmp_path: Path) -> None:
    harness = make_zipapp(tmp_path / "harness.pyz")
    harness_sha256 = hashlib.sha256(harness.read_bytes()).hexdigest()
    payload = json.loads(task_v2_bytes(harness))
    payload["unknown"] = True

    with pytest.raises(RuntimeReleaseError, match="strict valid TaskSpec"):
        validate_release_task(
            (json.dumps(payload, sort_keys=True) + "\n").encode(),
            harness_sha256=harness_sha256,
        )
    with pytest.raises(RuntimeReleaseError, match="duplicate JSON key"):
        validate_release_task(
            b'{"schema_version":"2.0","schema_version":"2.0"}\n',
            harness_sha256=harness_sha256,
        )


def test_keypair_generation_is_exclusive_private_and_returns_only_public_identity(
    tmp_path: Path,
) -> None:
    tmp_path.chmod(0o700)
    private_key = tmp_path / "coordinator-private.pem"
    public_key = tmp_path / "coordinator-public.pem"

    result = generate_coordinator_keypair(private_key=private_key, public_key=public_key)

    assert set(result) == {"key_id", "public_key_sha256"}
    assert private_key.stat().st_mode & 0o777 == 0o600
    assert public_key.stat().st_mode & 0o777 == 0o600
    assert b"PRIVATE KEY" in private_key.read_bytes()
    assert b"PRIVATE KEY" not in public_key.read_bytes()
    with pytest.raises(ValueError, match="overwrite"):
        generate_coordinator_keypair(private_key=private_key, public_key=public_key)


def test_schema_directory_rejects_symlinked_root(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "task.schema.json").write_text('{"type":"object"}\n', encoding="utf-8")
    linked = tmp_path / "linked"
    linked.symlink_to(source, target_is_directory=True)

    with pytest.raises(RuntimeReleaseError, match="symlink-free"):
        load_schema_directory(linked)
