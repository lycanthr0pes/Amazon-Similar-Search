from __future__ import annotations

import hashlib
import json
import os
import stat
import subprocess
import sys
import zipfile
from dataclasses import replace
from pathlib import Path
from pathlib import PurePosixPath
from types import SimpleNamespace

import pytest

import tools.ai_review.external_launcher as launcher_module
import tools.ai_review.offline_runner as offline_runner_module
import tools.ai_review.preflight as preflight_module
import tools.ai_review.snapshot as snapshot_module
from tools.ai_review.external_launcher import main as launcher_main
from tools.ai_review.offline_runner import ContainerBackend
from tools.ai_review.offline_runner import ContainerUnavailableError
from tools.ai_review.offline_runner import OfflineRunnerError
from tools.ai_review.offline_runner import build_offline_container_argv
from tools.ai_review.offline_runner import detect_container_backend
from tools.ai_review.offline_runner import execute_offline
from tools.ai_review.offline_runner import validate_offline_run_evidence
from tools.ai_review.offline_runner import _run_bounded
from tools.ai_review.preflight import PreflightError
from tools.ai_review.preflight import ProtectedTreeLimits
from tools.ai_review.preflight import assert_candidate_cannot_mutate_tree
from tools.ai_review.preflight import build_isolated_zipapp_argv
from tools.ai_review.preflight import exec_verified_zipapp
from tools.ai_review.preflight import preflight_runtime
from tools.ai_review.preflight import read_verified_fd_asset
from tools.ai_review.snapshot import SnapshotError
from tools.ai_review.snapshot import build_snapshot_test_manifest
from tools.ai_review.snapshot import create_red_tdd_snapshot
from tools.ai_review.snapshot import create_tdd_overlay_snapshot
from tools.ai_review.snapshot import create_readonly_snapshot
from tools.ai_review.snapshot import measure_red_tdd_snapshot
from tools.ai_review.snapshot import verify_red_tdd_snapshot
from tools.ai_review.snapshot import verify_readonly_snapshot


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def canonical_json(payload: object) -> bytes:
    return (
        json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode()


def expected_test_manifest_sha256(paths_and_hashes: tuple[tuple[str, str], ...]) -> str:
    digest = hashlib.sha256()
    digest.update(b"amazon-explorer-ai-review-test-manifest-v1\0")
    for path, content_sha256 in sorted(paths_and_hashes):
        for value in (path, content_sha256):
            encoded = value.encode("utf-8")
            digest.update(len(encoded).to_bytes(4, "big"))
            digest.update(encoded)
    return digest.hexdigest()


def other_uid() -> int:
    current = os.geteuid()
    return 65_534 if current != 65_534 else 65_533


def protected_file(path: Path, content: bytes, mode: int = 0o444) -> Path:
    path.write_bytes(content)
    path.chmod(mode)
    return path


def make_runtime_manifest(tmp_path: Path) -> tuple[Path, str, dict[str, Path]]:
    runtime = tmp_path / "runtime"
    runtime.mkdir(mode=0o700)
    python = protected_file(runtime / "python", b"trusted-python\n", 0o555)
    harness = runtime / "ai-review.pyz"
    with zipfile.ZipFile(harness, "w") as archive:
        archive.writestr("__main__.py", "raise SystemExit(0)\n")
    harness.chmod(0o444)
    task = protected_file(runtime / "task.json", b'{"task_id":"TASK-TRUST"}\n')
    dependency_lock = protected_file(runtime / "uv.lock", b"version = 1\n")
    schema_bundle = protected_file(runtime / "schemas.json", b'{"schema_version":"1.0"}\n')
    coordinator_public_key = protected_file(runtime / "coordinator.pub", b"trusted-public-key\n")
    broker_egress_policy = protected_file(
        runtime / "broker-egress-policy.json",
        (
            Path(__file__).resolve().parents[1] / "specs/policies/broker-egress-policy.json"
        ).read_bytes(),
    )
    openai_pricing_policy = protected_file(
        runtime / "openai-pricing-policy.json",
        (
            Path(__file__).resolve().parents[1] / "specs/policies/openai-pricing-policy.json"
        ).read_bytes(),
    )
    payload = {
        "schema_version": "1.0",
        "python": {"path": str(python), "sha256": sha256_file(python)},
        "harness": {"path": str(harness), "sha256": sha256_file(harness)},
        "task": {"path": str(task), "sha256": sha256_file(task)},
        "dependency_lock": {
            "path": str(dependency_lock),
            "sha256": sha256_file(dependency_lock),
        },
        "schema_bundle": {"path": str(schema_bundle), "sha256": sha256_file(schema_bundle)},
        "coordinator_public_key": {
            "path": str(coordinator_public_key),
            "sha256": sha256_file(coordinator_public_key),
        },
        "broker_egress_policy": {
            "path": str(broker_egress_policy),
            "sha256": sha256_file(broker_egress_policy),
        },
        "openai_pricing_policy": {
            "path": str(openai_pricing_policy),
            "sha256": sha256_file(openai_pricing_policy),
        },
        "coordinator_image_digest": f"sha256:{'c' * 64}",
        "offline_runner_image_digest": f"sha256:{'a' * 64}",
        "broker_image_digest": f"sha256:{'b' * 64}",
        "broker_gateway_image_digest": f"sha256:{'d' * 64}",
        "broker_packet_reservation_limit": 544_000,
        "broker_packet_cost_limit_microusd": 4_540_000,
    }
    manifest = runtime / "runtime-manifest.json"
    manifest.write_bytes(canonical_json(payload))
    digest = sha256_file(manifest)
    manifest.chmod(0o444)
    return (
        manifest,
        digest,
        {
            "python": python,
            "harness": harness,
            "task": task,
            "dependency_lock": dependency_lock,
            "schema_bundle": schema_bundle,
            "coordinator_public_key": coordinator_public_key,
            "broker_egress_policy": broker_egress_policy,
            "openai_pricing_policy": openai_pricing_policy,
        },
    )


def run_git(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
        shell=False,
    )
    return result.stdout.strip()


def make_bare_repository(
    tmp_path: Path,
    *,
    symlink: bool = False,
    env_example: bytes | None = None,
) -> tuple[Path, str]:
    tmp_path.mkdir(parents=True, exist_ok=True)
    work = tmp_path / "source-work"
    work.mkdir()
    run_git(work, "init", "-q")
    run_git(work, "config", "user.name", "Harness Test")
    run_git(work, "config", "user.email", "test@example.com")
    (work / "src").mkdir()
    (work / "src" / "example.py").write_text("VALUE = 1\n", encoding="utf-8")
    (work / "run.sh").write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    (work / "run.sh").chmod(0o755)
    if symlink:
        (work / "escape").symlink_to("/etc/passwd")
    if env_example is not None:
        (work / ".env.example").write_bytes(env_example)
    run_git(work, "add", "-A")
    run_git(work, "commit", "-qm", "snapshot")
    commit = run_git(work, "rev-parse", "HEAD")
    bare = tmp_path / "source.git"
    subprocess.run(
        ["git", "clone", "-q", "--bare", "--no-hardlinks", str(work), str(bare)],
        check=True,
        capture_output=True,
        shell=False,
    )
    return bare, commit


def make_tdd_repository(tmp_path: Path) -> tuple[Path, str, str]:
    """Create a base and candidate where production and one executable test both change."""

    tmp_path.mkdir(parents=True, exist_ok=True)
    work = tmp_path / "tdd-work"
    work.mkdir()
    run_git(work, "init", "-q")
    run_git(work, "config", "user.name", "Harness Test")
    run_git(work, "config", "user.email", "test@example.com")
    (work / "src").mkdir()
    (work / "src" / "example.py").write_text("VALUE = 1\n", encoding="utf-8")
    run_git(work, "add", "-A")
    run_git(work, "commit", "-qm", "base")
    base_commit = run_git(work, "rev-parse", "HEAD")

    (work / "src" / "example.py").write_text("VALUE = 2\n", encoding="utf-8")
    (work / "tests").mkdir()
    candidate_test = work / "tests" / "test_example.py"
    candidate_test.write_text("def test_example(): assert True\n", encoding="utf-8")
    candidate_test.chmod(0o755)
    run_git(work, "add", "-A")
    run_git(work, "commit", "-qm", "candidate")
    candidate_commit = run_git(work, "rev-parse", "HEAD")

    bare = tmp_path / "tdd-source.git"
    subprocess.run(
        ["git", "clone", "-q", "--bare", "--no-hardlinks", str(work), str(bare)],
        check=True,
        capture_output=True,
        shell=False,
    )
    return bare, base_commit, candidate_commit


def test_preflight_verifies_raw_runtime_before_building_import_argv(tmp_path):
    manifest, manifest_sha, assets = make_runtime_manifest(tmp_path)

    evidence = preflight_runtime(
        manifest_path=manifest,
        expected_manifest_sha256=manifest_sha,
        candidate_uid=other_uid(),
    )

    assert evidence.manifest_sha256 == manifest_sha
    assert evidence.harness.sha256 == sha256_file(assets["harness"])
    assert evidence.dependency_lock.sha256 == sha256_file(assets["dependency_lock"])
    assert evidence.schema_bundle.sha256 == sha256_file(assets["schema_bundle"])
    assert evidence.coordinator_public_key.sha256 == sha256_file(assets["coordinator_public_key"])
    assert evidence.coordinator_image_digest == f"sha256:{'c' * 64}"
    assert evidence.offline_runner_image_digest == f"sha256:{'a' * 64}"
    assert evidence.broker_image_digest == f"sha256:{'b' * 64}"
    for name in (
        "manifest",
        "python",
        "harness",
        "task",
        "dependency_lock",
        "schema_bundle",
        "coordinator_public_key",
    ):
        descriptor = int(evidence.fd_path(name).rsplit("/", 1)[1])
        assert os.lseek(descriptor, 0, os.SEEK_CUR) == 0
    argv = build_isolated_zipapp_argv(evidence, ("policy", "--task", evidence.fd_path("task")))
    assert argv == (
        evidence.fd_path("python"),
        "-I",
        evidence.fd_path("harness"),
        "policy",
        "--task",
        evidence.fd_path("task"),
    )
    evidence.close()


def test_verified_exec_uses_only_hash_stable_file_descriptors(tmp_path):
    manifest, manifest_sha, _assets = make_runtime_manifest(tmp_path)
    evidence = preflight_runtime(
        manifest_path=manifest,
        expected_manifest_sha256=manifest_sha,
        candidate_uid=other_uid(),
    )
    observed: dict[str, object] = {}

    def fake_execve(executable, argv, environment):
        observed.update(executable=executable, argv=argv, environment=environment)
        raise OSError("sentinel")

    with pytest.raises(PreflightError, match="diagnostic-only"):
        exec_verified_zipapp(evidence, ("policy",), execve=fake_execve)
    with pytest.raises(PreflightError, match="exec verified runtime"):
        exec_verified_zipapp(
            evidence,
            ("policy",),
            diagnostic_host_exec=True,
            execve=fake_execve,
        )

    assert observed["executable"] == evidence.fd_path("python")
    assert observed["argv"][:3] == (
        evidence.fd_path("python"),
        "-I",
        evidence.fd_path("harness"),
    )
    assert "PYTHONPATH" not in observed["environment"]
    evidence.close()


def test_verified_fd_reader_requires_exact_binding_and_preserves_offset(tmp_path):
    manifest, manifest_sha, assets = make_runtime_manifest(tmp_path)
    evidence = preflight_runtime(
        manifest_path=manifest,
        expected_manifest_sha256=manifest_sha,
        candidate_uid=other_uid(),
    )
    task_fd_path = evidence.fd_path("task")
    descriptor = int(task_fd_path.rsplit("/", 1)[1])
    end_offset = os.lseek(descriptor, 0, os.SEEK_END)

    measured, raw = read_verified_fd_asset(
        task_fd_path,
        expected_sha256=evidence.task.sha256,
        label="task",
        max_bytes=2 * 1024 * 1024,
    )

    assert raw == assets["task"].read_bytes()
    assert measured.inode == evidence.task.inode
    assert os.lseek(descriptor, 0, os.SEEK_CUR) == end_offset
    with pytest.raises(PreflightError, match="trusted binding"):
        read_verified_fd_asset(
            task_fd_path,
            expected_sha256="0" * 64,
            label="task",
        )
    with pytest.raises(PreflightError, match="exact /proc/self/fd"):
        read_verified_fd_asset(
            assets["task"],
            expected_sha256=evidence.task.sha256,
            label="task",
        )
    evidence.close()


def test_real_python_exec_reads_verified_zipapp_and_task_fd_from_offset_zero(tmp_path):
    manifest, _manifest_sha, assets = make_runtime_manifest(tmp_path)
    real_python = Path(sys.executable).resolve(strict=True)
    assets["harness"].chmod(0o644)
    with zipfile.ZipFile(assets["harness"], "w") as archive:
        archive.writestr(
            "__main__.py",
            "import hashlib, sys\n"
            "raw = open(sys.argv[1], 'rb').read()\n"
            "print(hashlib.sha256(raw).hexdigest())\n",
        )
    assets["harness"].chmod(0o444)
    payload = json.loads(manifest.read_text(encoding="utf-8"))
    payload["python"] = {"path": str(real_python), "sha256": sha256_file(real_python)}
    payload["harness"]["sha256"] = sha256_file(assets["harness"])
    manifest.chmod(0o644)
    manifest.write_bytes(canonical_json(payload))
    manifest.chmod(0o444)
    manifest_sha = sha256_file(manifest)
    source_root = Path(__file__).resolve().parents[1]
    bootstrap = (
        "import sys\n"
        "from pathlib import Path\n"
        "from tools.ai_review.preflight import exec_verified_zipapp, preflight_runtime\n"
        "evidence = preflight_runtime(manifest_path=Path(sys.argv[1]), "
        "expected_manifest_sha256=sys.argv[2], candidate_uid=int(sys.argv[3]))\n"
        "exec_verified_zipapp(evidence, (evidence.fd_path('task'),), "
        "diagnostic_host_exec=True)\n"
    )

    result = subprocess.run(
        [
            sys.executable,
            "-c",
            bootstrap,
            str(manifest),
            manifest_sha,
            str(other_uid()),
        ],
        cwd=source_root,
        check=False,
        capture_output=True,
        env={"PATH": os.defpath, "LC_ALL": "C", "PYTHONPATH": str(source_root)},
        shell=False,
        text=True,
        timeout=30,
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == sha256_file(assets["task"])


def test_external_launcher_source_checkout_is_diagnostic_only(tmp_path, capsys):
    manifest, manifest_sha, _assets = make_runtime_manifest(tmp_path)

    exit_code = launcher_main(
        [
            "--manifest",
            str(manifest),
            "--expected-manifest-sha256",
            manifest_sha,
            "--candidate-uid",
            str(other_uid()),
            "--diagnostic-source",
            "--",
            "policy",
            "--task",
            "@task-fd",
            "--schema",
            "@schema-bundle-fd",
            "--coordinator-image-digest",
            "@coordinator-image-digest",
            "--runner-image-digest",
            "@offline-runner-image-digest",
            "--runtime-sha256",
            "@runtime-manifest-sha256",
        ]
    )

    captured = capsys.readouterr()
    assert exit_code == 0
    payload = json.loads(captured.out)
    assert payload["diagnostic_only"] is True
    assert payload["argv"][1] == "-I"
    assert payload["argv"][5].startswith("/proc/self/fd/")
    assert payload["argv"][7].startswith("/proc/self/fd/")
    assert payload["argv"][9] == f"sha256:{'c' * 64}"
    assert payload["argv"][11] == f"sha256:{'a' * 64}"
    assert payload["argv"][13] == manifest_sha


def test_external_launcher_runs_as_isolated_standalone_script(tmp_path):
    manifest, manifest_sha, _assets = make_runtime_manifest(tmp_path)
    launcher = Path(__file__).parents[1] / "tools" / "ai_review" / "external_launcher.py"

    result = subprocess.run(
        [
            sys.executable,
            "-I",
            str(launcher),
            "--manifest",
            str(manifest),
            "--expected-manifest-sha256",
            manifest_sha,
            "--candidate-uid",
            str(other_uid()),
            "--diagnostic-source",
            "--",
            "policy",
            "--task",
            "@task-fd",
        ],
        cwd=tmp_path,
        check=False,
        capture_output=True,
        env={"PATH": os.defpath, "LC_ALL": "C"},
        shell=False,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["diagnostic_only"] is True


def test_external_launcher_imports_coordinator_only_from_verified_zipapp_fd(tmp_path):
    launcher = Path(__file__).parents[1] / "tools" / "ai_review" / "external_launcher.py"
    archive = tmp_path / "trusted-harness.pyz"
    with zipfile.ZipFile(archive, "w") as bundle:
        bundle.writestr("tools/__init__.py", "")
        bundle.writestr("tools/ai_review/__init__.py", "")
        bundle.writestr("tools/ai_review/coordinator_launcher.py", "VALUE = 'verified'\n")
    descriptor = os.open(archive, os.O_RDONLY)
    os.set_inheritable(descriptor, True)
    script = (
        "import importlib.util,sys;"
        f"spec=importlib.util.spec_from_file_location('approved_launcher',{str(launcher)!r});"
        "module=importlib.util.module_from_spec(spec);"
        "sys.modules[spec.name]=module;spec.loader.exec_module(module);"
        f"evidence=type('E',(),{{'fd_path':lambda self,name:'/proc/self/fd/{descriptor}'}})();"
        "loaded=module._load_verified_harness_module("
        "evidence,'tools.ai_review.coordinator_launcher');"
        "print(loaded.VALUE);print(loaded.__file__)"
    )
    try:
        result = subprocess.run(
            [sys.executable, "-I", "-c", script],
            check=False,
            capture_output=True,
            env={"PATH": os.defpath, "LC_ALL": "C"},
            pass_fds=(descriptor,),
            shell=False,
            text=True,
            timeout=30,
        )
    finally:
        os.close(descriptor)

    assert result.returncode == 0, result.stderr
    lines = result.stdout.splitlines()
    assert lines[0] == "verified"
    assert lines[1].startswith(f"/proc/self/fd/{descriptor}/")


def test_external_launcher_refuses_production_exec_from_source_checkout(tmp_path, capsys):
    manifest, manifest_sha, _assets = make_runtime_manifest(tmp_path)

    exit_code = launcher_main(
        [
            "--manifest",
            str(manifest),
            "--expected-manifest-sha256",
            manifest_sha,
            "--candidate-uid",
            str(other_uid()),
            "--",
            "policy",
        ]
    )

    captured = capsys.readouterr()
    assert exit_code == 2
    assert "isolated Python (-I)" in captured.err or "outside a Git checkout" in captured.err


def test_external_launcher_checks_bootstrap_before_loading_preflight(tmp_path, monkeypatch, capsys):
    manifest, manifest_sha, _assets = make_runtime_manifest(tmp_path)
    loaded = False

    def forbidden_load(_path):
        nonlocal loaded
        loaded = True
        raise AssertionError("untrusted preflight must not load before bootstrap validation")

    monkeypatch.setattr(launcher_module, "_load_sibling_preflight", forbidden_load)
    exit_code = launcher_main(
        [
            "--manifest",
            str(manifest),
            "--expected-manifest-sha256",
            manifest_sha,
            "--candidate-uid",
            str(other_uid()),
            "--",
            "policy",
        ]
    )

    assert exit_code == 2
    assert loaded is False
    assert "launcher error" in capsys.readouterr().err


def test_preflight_rejects_tampered_archive_without_importing_it(tmp_path):
    manifest, manifest_sha, assets = make_runtime_manifest(tmp_path)
    sentinel = tmp_path / "IMPORTED"
    assets["harness"].chmod(0o644)
    with zipfile.ZipFile(assets["harness"], "w") as archive:
        archive.writestr(
            "__main__.py", f"from pathlib import Path\nPath({str(sentinel)!r}).touch()\n"
        )
    assets["harness"].chmod(0o444)

    with pytest.raises(PreflightError, match="harness SHA-256"):
        preflight_runtime(
            manifest_path=manifest,
            expected_manifest_sha256=manifest_sha,
            candidate_uid=other_uid(),
        )

    assert not sentinel.exists()


@pytest.mark.parametrize("attack", ["final-symlink", "parent-symlink", "hardlink"])
def test_preflight_rejects_link_and_path_swap_attacks(tmp_path, attack):
    manifest, manifest_sha, assets = make_runtime_manifest(tmp_path)
    harness = assets["harness"]
    runtime = harness.parent
    if attack == "final-symlink":
        trusted = runtime / "trusted.pyz"
        harness.rename(trusted)
        harness.symlink_to(trusted.name)
    elif attack == "parent-symlink":
        moved = tmp_path / "moved-runtime"
        runtime.rename(moved)
        runtime.symlink_to(moved.name, target_is_directory=True)
    else:
        linked = runtime / "linked.pyz"
        os.link(harness, linked)

    with pytest.raises(PreflightError, match="symlink|hardlink"):
        preflight_runtime(
            manifest_path=manifest,
            expected_manifest_sha256=manifest_sha,
            candidate_uid=other_uid(),
        )


def test_preflight_rejects_same_uid_as_candidate(tmp_path):
    manifest, manifest_sha, _assets = make_runtime_manifest(tmp_path)

    with pytest.raises(PreflightError, match="different OS UID"):
        preflight_runtime(
            manifest_path=manifest,
            expected_manifest_sha256=manifest_sha,
            candidate_uid=os.geteuid(),
        )


def test_recursive_worktree_protection_includes_standalone_git_metadata(tmp_path):
    _bare, _commit = make_bare_repository(tmp_path)
    worktree = tmp_path / "source-work"

    evidence = assert_candidate_cannot_mutate_tree(
        worktree,
        candidate_uid=other_uid(),
        limits=ProtectedTreeLimits(
            max_entries=10_000,
            max_total_bytes=32 * 1024 * 1024,
            max_file_bytes=8 * 1024 * 1024,
        ),
        same_device=True,
    )

    assert evidence.root == worktree
    assert evidence.entry_count > 0
    assert (worktree / ".git" / "config").is_file()


def test_recursive_worktree_protection_rejects_mutable_git_child(tmp_path):
    _bare, _commit = make_bare_repository(tmp_path)
    worktree = tmp_path / "source-work"
    config = worktree / ".git" / "config"
    config.chmod(0o666)

    with pytest.raises(PreflightError, match="can modify a protected tree entry"):
        assert_candidate_cannot_mutate_tree(worktree, candidate_uid=other_uid())


def test_recursive_worktree_protection_rejects_hardlink_and_nested_device(tmp_path, monkeypatch):
    _bare, _commit = make_bare_repository(tmp_path)
    worktree = tmp_path / "source-work"
    source = worktree / "src" / "example.py"
    linked = worktree / "src" / "linked.py"
    os.link(source, linked)
    with pytest.raises(PreflightError, match="hardlinks"):
        assert_candidate_cannot_mutate_tree(worktree, candidate_uid=other_uid())
    linked.unlink()

    nested = worktree / ".git" / "objects"
    original_lstat = preflight_module.os.lstat

    class DifferentDevice:
        def __init__(self, metadata):
            self._metadata = metadata
            self.st_dev = metadata.st_dev + 1

        def __getattr__(self, name):
            return getattr(self._metadata, name)

    def mounted_lstat(path, *args, **kwargs):
        metadata = original_lstat(path, *args, **kwargs)
        return DifferentDevice(metadata) if Path(path) == nested else metadata

    monkeypatch.setattr(preflight_module.os, "lstat", mounted_lstat)
    with pytest.raises(PreflightError, match="nested filesystem mount"):
        assert_candidate_cannot_mutate_tree(worktree, candidate_uid=other_uid())


def test_preflight_rejects_manifest_substitution_and_duplicate_keys(tmp_path):
    manifest, manifest_sha, _assets = make_runtime_manifest(tmp_path)
    manifest.chmod(0o644)
    manifest.write_text('{"schema_version":"1.0","schema_version":"2.0"}\n', encoding="utf-8")
    manifest.chmod(0o444)

    with pytest.raises(PreflightError, match="manifest SHA-256"):
        preflight_runtime(
            manifest_path=manifest,
            expected_manifest_sha256=manifest_sha,
            candidate_uid=other_uid(),
        )

    substituted_sha = sha256_file(manifest)
    with pytest.raises(PreflightError, match="duplicate JSON key"):
        preflight_runtime(
            manifest_path=manifest,
            expected_manifest_sha256=substituted_sha,
            candidate_uid=other_uid(),
        )


def test_snapshot_is_standalone_content_addressed_and_read_only(tmp_path):
    bare, commit = make_bare_repository(tmp_path)
    destination = tmp_path / "snapshots"
    destination.mkdir(mode=0o700)

    evidence = create_readonly_snapshot(
        source_repo=bare,
        commit_sha=commit,
        destination_root=destination,
        candidate_uid=other_uid(),
    )
    verified = verify_readonly_snapshot(evidence.root, candidate_uid=other_uid())

    assert verified == evidence
    assert evidence.root.name == evidence.snapshot_sha256
    assert evidence.commit_tree_sha == run_git(bare, "rev-parse", f"{commit}^{{tree}}")
    assert not (evidence.root / ".git").exists()
    assert (evidence.tree / "src" / "example.py").read_text(encoding="utf-8") == "VALUE = 1\n"
    assert stat.S_IMODE((evidence.tree / "run.sh").stat().st_mode) == 0o555
    assert stat.S_IMODE((evidence.tree / "src" / "example.py").stat().st_mode) == 0o444
    assert all(path.stat().st_nlink == 1 for path in evidence.tree.rglob("*") if path.is_file())

    second_root = tmp_path / "second-snapshots"
    second_root.mkdir(mode=0o700)
    second = create_readonly_snapshot(
        source_repo=bare,
        commit_sha=commit,
        destination_root=second_root,
        candidate_uid=other_uid(),
    )
    assert second.snapshot_sha256 == evidence.snapshot_sha256
    assert second.manifest_path.read_bytes() == evidence.manifest_path.read_bytes()


def test_snapshot_clone_argv_has_one_source_and_one_destination(tmp_path, monkeypatch):
    bare, commit = make_bare_repository(tmp_path)
    destination = tmp_path / "snapshots"
    destination.mkdir(mode=0o700)
    observed: list[tuple[str, ...]] = []
    original = snapshot_module._run_git

    def recording_run_git(git, arguments, **kwargs):
        if "clone" in arguments:
            observed.append(arguments)
        return original(git, arguments, **kwargs)

    monkeypatch.setattr(snapshot_module, "_run_git", recording_run_git)
    create_readonly_snapshot(
        source_repo=bare,
        commit_sha=commit,
        destination_root=destination,
        candidate_uid=other_uid(),
    )

    assert len(observed) == 1
    clone_argv = observed[0]
    assert clone_argv.count(str(bare)) == 1
    assert clone_argv[-2] == str(bare)
    assert Path(clone_argv[-1]).name == "clone.git"


def test_snapshot_rejects_candidate_symlinks_and_same_uid(tmp_path):
    bare, commit = make_bare_repository(tmp_path, symlink=True)
    destination = tmp_path / "snapshots"
    destination.mkdir(mode=0o700)

    with pytest.raises(SnapshotError, match="symlink"):
        create_readonly_snapshot(
            source_repo=bare,
            commit_sha=commit,
            destination_root=destination,
            candidate_uid=other_uid(),
        )


@pytest.mark.parametrize(
    "sensitive_path",
    [".env", ".ENV.production", ".streamlit/SECRETS.toml", "cache/result.json"],
)
def test_snapshot_rejects_sensitive_paths_before_reading_blob(
    tmp_path, monkeypatch, sensitive_path
):
    source_root = tmp_path / "sensitive"
    bare, commit = make_bare_repository(source_root)
    work = source_root / "source-work"
    target = work.joinpath(*PurePosixPath(sensitive_path).parts)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("NEVER_READ\n", encoding="utf-8")
    run_git(work, "add", "-f", "--", sensitive_path)
    run_git(work, "commit", "-qm", "sensitive")
    commit = run_git(work, "rev-parse", "HEAD")
    run_git(work, "push", "-q", str(bare), f"{commit}:refs/heads/main")
    blob_reads: list[tuple[str, ...]] = []
    real_run_git = snapshot_module._run_git

    def monitored_run_git(git, arguments, **kwargs):
        if "cat-file" in arguments and "blob" in arguments:
            blob_reads.append(arguments)
        return real_run_git(git, arguments, **kwargs)

    monkeypatch.setattr(snapshot_module, "_run_git", monitored_run_git)
    destination = tmp_path / "sensitive-snapshots"
    destination.mkdir(mode=0o700)

    with pytest.raises(SnapshotError, match="sensitive|Git metadata"):
        create_readonly_snapshot(
            source_repo=bare,
            commit_sha=commit,
            destination_root=destination,
            candidate_uid=other_uid(),
        )

    assert blob_reads == []


def test_snapshot_verifier_rejects_protected_manifest_path_before_blob_read(tmp_path, monkeypatch):
    secret = b"AWS_SECRET_ACCESS_KEY=never-read\n"
    entry = {
        "mode": "100644",
        "path": ".ENV.production",
        "sha256": sha256_bytes(secret),
        "size": len(secret),
    }
    digest_payload = {
        "schema_version": "1.0",
        "commit_sha": "a" * 40,
        "commit_tree_sha": "b" * 40,
        "excluded_paths": [],
        "files": [entry],
    }
    snapshot_sha256 = sha256_bytes(canonical_json(digest_payload))
    root = tmp_path / snapshot_sha256
    tree = root / "tree"
    tree.mkdir(parents=True)
    protected_file(tree / ".ENV.production", secret)
    protected_file(
        root / "manifest.json",
        canonical_json({**digest_payload, "snapshot_sha256": snapshot_sha256}),
    )
    tree.chmod(0o555)
    root.chmod(0o555)
    labels: list[str] = []
    original_read = snapshot_module.read_protected_file

    def monitored_read(path, **kwargs):
        labels.append(kwargs["label"])
        return original_read(path, **kwargs)

    monkeypatch.setattr(snapshot_module, "read_protected_file", monitored_read)
    with pytest.raises(SnapshotError, match="sensitive environment path"):
        verify_readonly_snapshot(root, candidate_uid=other_uid())

    assert labels == ["snapshot manifest"]


def test_snapshot_enforces_blob_size_before_reading_content(tmp_path, monkeypatch):
    bare, commit = make_bare_repository(tmp_path)
    destination = tmp_path / "snapshots"
    destination.mkdir(mode=0o700)
    blob_reads: list[tuple[str, ...]] = []
    original = snapshot_module._run_git

    def monitored_run_git(git, arguments, **kwargs):
        if "cat-file" in arguments and "blob" in arguments:
            blob_reads.append(arguments)
        return original(git, arguments, **kwargs)

    monkeypatch.setattr(snapshot_module, "_run_git", monitored_run_git)
    monkeypatch.setattr(snapshot_module, "MAX_FILE_BYTES", 1)

    with pytest.raises(SnapshotError, match="file exceeds"):
        create_readonly_snapshot(
            source_repo=bare,
            commit_sha=commit,
            destination_root=destination,
            candidate_uid=other_uid(),
        )

    assert blob_reads == []


def test_snapshot_bounds_git_metadata_before_clone(tmp_path, monkeypatch):
    bare, commit = make_bare_repository(tmp_path)
    destination = tmp_path / "snapshots"
    destination.mkdir(mode=0o700)
    monkeypatch.setattr(snapshot_module, "MAX_GIT_METADATA_ENTRIES", 1)

    with pytest.raises(SnapshotError, match="metadata exceeds the entry limit"):
        create_readonly_snapshot(
            source_repo=bare,
            commit_sha=commit,
            destination_root=destination,
            candidate_uid=other_uid(),
        )


def test_snapshot_rejects_nested_filesystem_in_git_metadata(tmp_path, monkeypatch):
    bare, commit = make_bare_repository(tmp_path)
    destination = tmp_path / "snapshots"
    destination.mkdir(mode=0o700)
    nested = bare / "objects"
    original_lstat = snapshot_module.os.lstat

    class DifferentDevice:
        def __init__(self, metadata):
            self._metadata = metadata
            self.st_dev = metadata.st_dev + 1

        def __getattr__(self, name):
            return getattr(self._metadata, name)

    def mounted_lstat(path, *args, **kwargs):
        metadata = original_lstat(path, *args, **kwargs)
        return DifferentDevice(metadata) if Path(path) == nested else metadata

    monkeypatch.setattr(snapshot_module.os, "lstat", mounted_lstat)
    with pytest.raises(SnapshotError, match="nested filesystem mount"):
        create_readonly_snapshot(
            source_repo=bare,
            commit_sha=commit,
            destination_root=destination,
            candidate_uid=other_uid(),
        )


def test_snapshot_classifies_exact_git_metadata_component_only():
    assert snapshot_module._sensitive_tree_reason(".git/config") == "Git metadata"
    assert snapshot_module._sensitive_tree_reason("src/.GIT/index") == "Git metadata"
    assert snapshot_module._sensitive_tree_reason(".github/workflows/test.yml") is None
    assert snapshot_module._sensitive_tree_reason(".gitignore") is None


def test_snapshot_validates_then_excludes_root_empty_env_example(tmp_path):
    template = Path(__file__).resolve().parents[1].joinpath(".env.example").read_bytes()
    bare, commit = make_bare_repository(tmp_path / "source", env_example=template)
    destination = tmp_path / "snapshots"
    destination.mkdir(mode=0o700)

    evidence = create_readonly_snapshot(
        source_repo=bare,
        commit_sha=commit,
        destination_root=destination,
        candidate_uid=other_uid(),
    )

    assert evidence.excluded_paths == (".env.example",)
    assert not (evidence.tree / ".env.example").exists()
    assert verify_readonly_snapshot(evidence.root, candidate_uid=other_uid()) == evidence


def test_snapshot_rejects_configured_env_example_without_echoing_value(tmp_path):
    bare, commit = make_bare_repository(
        tmp_path / "source",
        env_example=b"OUTSCRAPER_API_KEY=live-value-must-not-appear\n",
    )
    destination = tmp_path / "snapshots"
    destination.mkdir(mode=0o700)

    with pytest.raises(SnapshotError, match="not a safe empty template") as captured:
        create_readonly_snapshot(
            source_repo=bare,
            commit_sha=commit,
            destination_root=destination,
            candidate_uid=other_uid(),
        )

    assert "live-value" not in str(captured.value)


@pytest.mark.parametrize(
    ("path", "reason"),
    [
        (".envrc", "sensitive environment path"),
        (".netrc", "credential path"),
        (".pypirc", "credential path"),
        (".npmrc", "credential path"),
        ("nested/.cache/http/body", "sensitive cache path"),
        ("nested/credentials", "credential path"),
        ("nested/secrets.toml", "credential path"),
        ("nested/.aws/credentials", "credential path"),
        ("nested/.docker/config.json", "credential path"),
        ("nested/.ssh/id_ed25519", "credential path"),
        ("nested/.kube/config", "credential path"),
    ],
)
def test_snapshot_classifies_credential_paths_without_reading_content(path, reason):
    assert snapshot_module._sensitive_tree_reason(path) == reason


@pytest.mark.parametrize("attack", ["alternates", "replace-ref", "config", "hardlink"])
def test_snapshot_rejects_untrusted_git_metadata_before_materializing(tmp_path, attack):
    bare, commit = make_bare_repository(tmp_path)
    if attack == "alternates":
        info = bare / "objects" / "info"
        info.mkdir(exist_ok=True)
        (info / "alternates").write_text("/untrusted/objects\n", encoding="utf-8")
    elif attack == "replace-ref":
        replacement = bare / "refs" / "replace" / commit
        replacement.parent.mkdir(parents=True)
        replacement.write_text(f"{commit}\n", encoding="ascii")
    elif attack == "config":
        with (bare / "config").open("a", encoding="utf-8") as handle:
            handle.write("[include]\n\tpath = /untrusted/config\n")
    else:
        os.link(bare / "config", bare / "config-hardlink")
    destination = tmp_path / "metadata-snapshots"
    destination.mkdir(mode=0o700)

    with pytest.raises(SnapshotError, match="alternates|replace|config|hardlink"):
        create_readonly_snapshot(
            source_repo=bare,
            commit_sha=commit,
            destination_root=destination,
            candidate_uid=other_uid(),
        )


def test_snapshot_rejects_same_uid(tmp_path):
    safe_bare, safe_commit = make_bare_repository(tmp_path)
    destination = tmp_path / "snapshots"
    destination.mkdir(mode=0o700)
    with pytest.raises(SnapshotError, match="different OS UID"):
        create_readonly_snapshot(
            source_repo=safe_bare,
            commit_sha=safe_commit,
            destination_root=destination,
            candidate_uid=os.geteuid(),
        )


def test_snapshot_verification_rejects_content_and_path_swaps(tmp_path):
    bare, commit = make_bare_repository(tmp_path)
    destination = tmp_path / "snapshots"
    destination.mkdir(mode=0o700)
    evidence = create_readonly_snapshot(
        source_repo=bare,
        commit_sha=commit,
        destination_root=destination,
        candidate_uid=other_uid(),
    )
    source = evidence.tree / "src" / "example.py"
    replacement = tmp_path / "replacement.py"
    replacement.write_text("VALUE = 999\n", encoding="utf-8")
    (evidence.tree / "src").chmod(0o755)
    source.unlink()
    source.symlink_to(replacement)

    with pytest.raises(SnapshotError, match="symlink"):
        verify_readonly_snapshot(evidence.root, candidate_uid=other_uid())


def test_snapshot_verification_rejects_nested_filesystem(tmp_path, monkeypatch):
    bare, commit = make_bare_repository(tmp_path)
    destination = tmp_path / "snapshots"
    destination.mkdir(mode=0o700)
    evidence = create_readonly_snapshot(
        source_repo=bare,
        commit_sha=commit,
        destination_root=destination,
        candidate_uid=other_uid(),
    )
    nested = evidence.tree / "src"
    original_lstat = snapshot_module.os.lstat

    class DifferentDevice:
        def __init__(self, metadata):
            self._metadata = metadata
            self.st_dev = metadata.st_dev + 1

        def __getattr__(self, name):
            return getattr(self._metadata, name)

    def mounted_lstat(path, *args, **kwargs):
        metadata = original_lstat(path, *args, **kwargs)
        return DifferentDevice(metadata) if Path(path) == nested else metadata

    monkeypatch.setattr(snapshot_module.os, "lstat", mounted_lstat)
    with pytest.raises(SnapshotError, match="nested filesystem mount"):
        verify_readonly_snapshot(evidence.root, candidate_uid=other_uid())


def test_container_detection_fails_closed_without_supported_backend():
    with pytest.raises(ContainerUnavailableError, match="Podman or Docker"):
        detect_container_backend(which=lambda _name: None)


def test_container_detection_rejects_runtime_without_seccomp(tmp_path):
    binary = protected_file(tmp_path / "podman", b"runtime\n", 0o555)

    def probe(argv, **_kwargs):
        return subprocess.CompletedProcess(
            argv,
            0,
            stdout=(
                '{"host":{"security":{"rootless":true,"seccompEnabled":false,'
                '"seccompProfilePath":"unconfined"}}}'
            ),
            stderr="",
        )

    with pytest.raises(ContainerUnavailableError, match="seccomp"):
        detect_container_backend(
            candidate_uid=other_uid(),
            which=lambda name: str(binary) if name == "podman" else None,
            probe=probe,
        )


def test_container_detection_uses_bounded_streaming_probe_by_default(tmp_path, monkeypatch):
    binary = protected_file(tmp_path / "podman", b"runtime\n", 0o555)
    observed: dict[str, object] = {}
    stdout = (
        b'{"host":{"security":{"rootless":true,"seccompEnabled":true,'
        b'"seccompProfilePath":"/usr/share/containers/seccomp.json"}}}'
    )

    def bounded_probe(argv, **kwargs):
        observed.update(argv=argv, kwargs=kwargs)
        return SimpleNamespace(exit_code=0, stdout=stdout, stderr=b"", duration_ms=1)

    monkeypatch.setattr(offline_runner_module, "_run_bounded", bounded_probe)
    backend = detect_container_backend(
        candidate_uid=other_uid(),
        which=lambda name: str(binary) if name == "podman" else None,
    )

    assert backend.name == "podman"
    assert observed["kwargs"]["max_output_bytes"] == 64_000
    assert observed["kwargs"]["timeout_seconds"] == 10


def test_offline_container_argv_has_required_isolation_and_no_secret_mounts(tmp_path):
    bare, commit = make_bare_repository(tmp_path)
    destination = tmp_path / "snapshots"
    destination.mkdir(mode=0o700)
    snapshot = create_readonly_snapshot(
        source_repo=bare,
        commit_sha=commit,
        destination_root=destination,
        candidate_uid=other_uid(),
    )
    backend_binary = protected_file(tmp_path / "podman", b"container-runtime\n", 0o555)
    backend = ContainerBackend(
        name="podman",
        executable=backend_binary,
        rootless=True,
        user_namespace=True,
        seccomp_enabled=True,
        seccomp_profile="/usr/share/containers/seccomp.json",
    )
    image = f"registry.invalid/ai-review@sha256:{'a' * 64}"

    argv = build_offline_container_argv(
        backend=backend,
        snapshot=snapshot,
        image=image,
        approved_image_digest=f"sha256:{'a' * 64}",
        command=(sys.executable, "-m", "pytest", "-p", "no:cacheprovider"),
        candidate_uid=other_uid(),
    )

    joined = "\n".join(argv)
    assert argv[0] == str(backend_binary)
    assert "--network=none" in argv
    assert "--read-only" in argv
    assert "--cap-drop=ALL" in argv
    assert "--security-opt=no-new-privileges" in argv
    assert "seccomp=unconfined" not in joined
    assert "--pull=never" in argv
    assert f"src={snapshot.tree}" in joined
    assert "dst=/workspace" in joined
    assert "readonly" in joined
    assert sum(argument.startswith("type=bind,") for argument in argv) == 1
    assert "/var/run/docker.sock" not in joined
    assert ".env" not in joined
    assert "secrets.toml" not in joined
    assert image in argv


@pytest.mark.parametrize(
    "image",
    ["python:3.13", "python@sha256:nope", "", f"--privileged@sha256:{'a' * 64}"],
)
def test_offline_runner_rejects_unpinned_images(tmp_path, image):
    backend_binary = protected_file(tmp_path / "docker", b"container-runtime\n", 0o555)
    backend = ContainerBackend(
        name="docker",
        executable=backend_binary,
        rootless=True,
        user_namespace=True,
        seccomp_enabled=True,
        seccomp_profile="builtin",
    )
    bare, commit = make_bare_repository(tmp_path)
    destination = tmp_path / "snapshots"
    destination.mkdir(mode=0o700)
    snapshot = create_readonly_snapshot(
        source_repo=bare,
        commit_sha=commit,
        destination_root=destination,
        candidate_uid=other_uid(),
    )

    with pytest.raises(OfflineRunnerError, match="digest"):
        build_offline_container_argv(
            backend=backend,
            snapshot=snapshot,
            image=image,
            approved_image_digest=f"sha256:{'a' * 64}",
            command=("python", "-m", "pytest"),
            candidate_uid=other_uid(),
        )


def test_execute_offline_never_runs_when_backend_is_unavailable(tmp_path):
    called = False

    def forbidden_run(*_args, **_kwargs):
        nonlocal called
        called = True
        raise AssertionError("runner must not be called")

    with pytest.raises(ContainerUnavailableError):
        execute_offline(
            snapshot_root=tmp_path / "missing",
            image=f"example.invalid/runner@sha256:{'b' * 64}",
            approved_image_digest=f"sha256:{'b' * 64}",
            command=("python", "-m", "pytest"),
            phase="red",
            acceptance_test_id="AT-TEST",
            session_id="ai-review-" + "1" * 24,
            task_sha256="c" * 64,
            candidate_sha256="a" * 64,
            source_snapshot_sha256="e" * 64,
            test_patch_sha256="d" * 64,
            test_manifest_sha256="e" * 64,
            candidate_snapshot_sha256="f" * 64,
            candidate_uid=other_uid(),
            which=lambda _name: None,
            stream_runner=forbidden_run,
        )

    assert not called


@pytest.mark.parametrize(
    ("name", "rootless", "user_namespace", "expected_userns"),
    [
        ("podman", True, True, "--userns=keep-id:uid=65534,gid=65534"),
        ("podman", False, True, "--userns=auto"),
        ("docker", True, True, None),
        ("docker", False, True, None),
    ],
)
def test_offline_runner_validates_rootless_and_rootful_user_namespaces(
    tmp_path, name, rootless, user_namespace, expected_userns
):
    bare, commit = make_bare_repository(tmp_path)
    destination = tmp_path / "snapshots"
    destination.mkdir(mode=0o700)
    snapshot = create_readonly_snapshot(
        source_repo=bare,
        commit_sha=commit,
        destination_root=destination,
        candidate_uid=other_uid(),
    )
    binary = protected_file(tmp_path / name, b"runtime\n", 0o555)
    backend = ContainerBackend(
        name=name,
        executable=binary,
        rootless=rootless,
        user_namespace=user_namespace,
        seccomp_enabled=True,
        seccomp_profile=("/usr/share/containers/seccomp.json" if name == "podman" else "builtin"),
    )
    argv = build_offline_container_argv(
        backend=backend,
        snapshot=snapshot,
        image=f"example.invalid/runner@sha256:{'e' * 64}",
        approved_image_digest=f"sha256:{'e' * 64}",
        command=("python", "-m", "pytest"),
        candidate_uid=other_uid(),
    )

    assert "--user=65534:65534" in argv
    if expected_userns is None:
        assert not any(argument.startswith("--userns=") for argument in argv)
    else:
        assert expected_userns in argv


def test_offline_runner_rejects_rootful_backend_without_user_namespace(tmp_path):
    binary = protected_file(tmp_path / "docker", b"runtime\n", 0o555)
    backend = ContainerBackend(
        name="docker",
        executable=binary,
        rootless=False,
        user_namespace=False,
        seccomp_enabled=True,
        seccomp_profile="builtin",
    )
    with pytest.raises(OfflineRunnerError, match="user namespace"):
        # Backend rejection occurs before snapshot access.
        build_offline_container_argv(
            backend=backend,
            snapshot=object(),
            image=f"example.invalid/runner@sha256:{'e' * 64}",
            approved_image_digest=f"sha256:{'e' * 64}",
            command=("python",),
            candidate_uid=other_uid(),
        )


def test_offline_runner_rejects_green_candidate_substitution_and_gate_tdd_claims(tmp_path):
    bare, commit = make_bare_repository(tmp_path)
    destination = tmp_path / "snapshots"
    destination.mkdir(mode=0o700)
    snapshot = create_readonly_snapshot(
        source_repo=bare,
        commit_sha=commit,
        destination_root=destination,
        candidate_uid=other_uid(),
    )
    binary = protected_file(tmp_path / "podman", b"runtime\n", 0o555)

    def probe(argv, **_kwargs):
        return subprocess.CompletedProcess(
            argv,
            0,
            stdout=(
                '{"host":{"security":{"rootless":true,"seccompEnabled":true,'
                '"seccompProfilePath":"/usr/share/containers/seccomp.json"}}}'
            ),
            stderr="",
        )

    common = {
        "snapshot_root": snapshot.root,
        "image": f"example.invalid/runner@sha256:{'f' * 64}",
        "approved_image_digest": f"sha256:{'f' * 64}",
        "command": ("python", "-m", "pytest"),
        "acceptance_test_id": "AT-TEST",
        "session_id": "ai-review-" + "1" * 24,
        "task_sha256": "1" * 64,
        "candidate_sha256": "2" * 64,
        "source_snapshot_sha256": snapshot.snapshot_sha256,
        "candidate_uid": other_uid(),
        "which": lambda name: str(binary) if name == "podman" else None,
        "probe": probe,
    }
    with pytest.raises(OfflineRunnerError, match="GREEN must execute the candidate snapshot"):
        execute_offline(
            **common,
            phase="green",
            test_patch_sha256="2" * 64,
            test_manifest_sha256="3" * 64,
            candidate_snapshot_sha256="4" * 64,
        )
    with pytest.raises(OfflineRunnerError, match="gate runs must not claim TDD"):
        execute_offline(
            **common,
            phase="gate",
            test_patch_sha256="2" * 64,
            test_manifest_sha256="3" * 64,
        )


@pytest.mark.parametrize("phase", ["gate", "red", "green"])
def test_execute_offline_returns_bounded_digest_bound_evidence(tmp_path, phase):
    bare, commit = make_bare_repository(tmp_path)
    destination = tmp_path / "snapshots"
    destination.mkdir(mode=0o700)
    snapshot = create_readonly_snapshot(
        source_repo=bare,
        commit_sha=commit,
        destination_root=destination,
        candidate_uid=other_uid(),
    )
    binary = protected_file(tmp_path / "podman", b"runtime\n", 0o555)
    observed: dict[str, object] = {}

    def probe(argv, **_kwargs):
        return subprocess.CompletedProcess(
            argv,
            0,
            stdout=(
                '{"host":{"security":{"rootless":true,"seccompEnabled":true,'
                '"seccompProfilePath":"/usr/share/containers/seccomp.json"}}}'
            ),
            stderr="",
        )

    def runner(argv, **kwargs):
        observed.update(argv=argv, kwargs=kwargs)
        cidfile_argument = next(value for value in argv if value.startswith("--cidfile="))
        Path(cidfile_argument.split("=", 1)[1]).write_text("a" * 64 + "\n", encoding="ascii")
        stdout = b"A" * 400
        stderr = b"B" * 400
        return SimpleNamespace(
            exit_code=7,
            stdout=stdout,
            stderr=stderr,
            stdout_sha256=sha256_bytes(stdout),
            stderr_sha256=sha256_bytes(stderr),
            duration_ms=12,
        )

    evidence = execute_offline(
        snapshot_root=snapshot.root,
        image=f"example.invalid/runner@sha256:{'f' * 64}",
        approved_image_digest=f"sha256:{'f' * 64}",
        command=("python", "-m", "pytest", "tests/test_example.py"),
        phase=phase,
        acceptance_test_id="AT-TEST",
        session_id="ai-review-" + "1" * 24,
        task_sha256="1" * 64,
        candidate_sha256="4" * 64,
        source_snapshot_sha256=("5" * 64 if phase == "red" else snapshot.snapshot_sha256),
        test_patch_sha256=None if phase == "gate" else "2" * 64,
        test_manifest_sha256=None if phase == "gate" else "3" * 64,
        candidate_snapshot_sha256=("6" * 64 if phase == "red" else snapshot.snapshot_sha256),
        candidate_uid=other_uid(),
        max_log_bytes=1_024,
        which=lambda name: str(binary) if name == "podman" else None,
        probe=probe,
        stream_runner=runner,
        cleanup=lambda _backend, _name, _environment: True,
    )

    assert evidence.request.phase == phase
    assert evidence.request.source_commit_sha == commit
    assert evidence.request.source_commit_tree_sha == snapshot.commit_tree_sha
    assert evidence.request.candidate_snapshot_sha256 == (
        "6" * 64 if phase == "red" else snapshot.snapshot_sha256
    )
    assert evidence.request.source_snapshot_sha256 == (
        "5" * 64 if phase == "red" else snapshot.snapshot_sha256
    )
    assert evidence.request.execution_snapshot_sha256 == snapshot.snapshot_sha256
    assert evidence.request.test_patch_sha256 == (None if phase == "gate" else "2" * 64)
    assert evidence.request.test_manifest_sha256 == (None if phase == "gate" else "3" * 64)
    assert evidence.runtime_name == "podman"
    assert evidence.runtime_sha256 == sha256_file(binary)
    assert evidence.runtime_security_sha256 == evidence.runtime_security_sha256.lower()
    assert len(evidence.runtime_security_sha256) == 64
    assert evidence.runtime_seccomp_profile == "/usr/share/containers/seccomp.json"
    assert evidence.snapshot_sha256 == snapshot.snapshot_sha256
    assert evidence.exit_code == 7
    assert evidence.log_truncated is False
    assert len(evidence.log) <= 1_024
    expected_log_binding = canonical_json(
        {
            "stderr_bytes": 400,
            "stderr_sha256": sha256_bytes(b"B" * 400),
            "stdout_bytes": 400,
            "stdout_sha256": sha256_bytes(b"A" * 400),
        }
    )
    assert evidence.log_sha256 == sha256_bytes(expected_log_binding)
    assert evidence.request_sha256 == evidence.request.sha256()
    assert evidence.argv_sha256 == sha256_bytes(canonical_json(list(observed["argv"])))
    assert set(observed["kwargs"]["environment"]) == {"PATH", "LC_ALL"}
    assert (
        validate_offline_run_evidence(
            evidence,
            execution_snapshot=snapshot,
            image=f"example.invalid/runner@sha256:{'f' * 64}",
            approved_image_digest=f"sha256:{'f' * 64}",
            candidate_uid=other_uid(),
        )
        == evidence
    )
    for changed in (
        replace(evidence, stdout=evidence.stdout + b"tampered"),
        replace(evidence, response_sha256="0" * 64),
        replace(evidence, cleanup_succeeded=False),
        replace(evidence, argv_sha256="0" * 64),
    ):
        with pytest.raises(OfflineRunnerError):
            validate_offline_run_evidence(
                changed,
                execution_snapshot=snapshot,
                image=f"example.invalid/runner@sha256:{'f' * 64}",
                approved_image_digest=f"sha256:{'f' * 64}",
                candidate_uid=other_uid(),
            )


def test_bounded_stream_runner_kills_output_flood():
    with pytest.raises(OfflineRunnerError, match="output exceeded"):
        _run_bounded(
            (sys.executable, "-c", "import os; os.write(1, b'x' * 4096)"),
            environment={"PATH": os.defpath, "LC_ALL": "C"},
            timeout_seconds=5,
            max_output_bytes=1_024,
        )


def test_execute_offline_fails_closed_when_named_container_cleanup_fails(tmp_path):
    bare, commit = make_bare_repository(tmp_path)
    destination = tmp_path / "snapshots"
    destination.mkdir(mode=0o700)
    snapshot = create_readonly_snapshot(
        source_repo=bare,
        commit_sha=commit,
        destination_root=destination,
        candidate_uid=other_uid(),
    )
    binary = protected_file(tmp_path / "podman", b"runtime\n", 0o555)

    def probe(argv, **_kwargs):
        return subprocess.CompletedProcess(
            argv,
            0,
            stdout=(
                '{"host":{"security":{"rootless":false,"seccompEnabled":true,'
                '"seccompProfilePath":"/usr/share/containers/seccomp.json"}}}'
            ),
            stderr="",
        )

    def timed_out(_argv, **_kwargs):
        raise OfflineRunnerError("isolated candidate execution timed out")

    with pytest.raises(OfflineRunnerError, match="cleanup could not be attested"):
        execute_offline(
            snapshot_root=snapshot.root,
            image=f"example.invalid/runner@sha256:{'f' * 64}",
            approved_image_digest=f"sha256:{'f' * 64}",
            command=("python", "-m", "pytest"),
            phase="green",
            acceptance_test_id="AT-TEST",
            session_id="ai-review-" + "1" * 24,
            task_sha256="3" * 64,
            candidate_sha256="6" * 64,
            source_snapshot_sha256=snapshot.snapshot_sha256,
            test_patch_sha256="4" * 64,
            test_manifest_sha256="5" * 64,
            candidate_uid=other_uid(),
            which=lambda name: str(binary) if name == "podman" else None,
            probe=probe,
            stream_runner=timed_out,
            cleanup=lambda _backend, _name, _environment: False,
        )


def test_tdd_overlay_applies_only_exact_coordinator_owned_test_patch(tmp_path):
    bare, commit = make_bare_repository(tmp_path)
    destination = tmp_path / "snapshots"
    destination.mkdir(mode=0o700)
    source = create_readonly_snapshot(
        source_repo=bare,
        commit_sha=commit,
        destination_root=destination,
        candidate_uid=other_uid(),
    )
    patch = protected_file(
        tmp_path / "test.patch",
        b"diff --git a/tests/test_example.py b/tests/test_example.py\n"
        b"new file mode 100644\n"
        b"--- /dev/null\n"
        b"+++ b/tests/test_example.py\n"
        b"@@ -0,0 +1 @@\n"
        b"+def test_example(): assert True\n",
    )
    overlay_root = tmp_path / "overlays"
    overlay_root.mkdir(mode=0o700)

    overlay = create_tdd_overlay_snapshot(
        phase="red",
        source_snapshot=source,
        test_patch_path=patch,
        expected_test_patch_sha256=sha256_file(patch),
        test_paths=("tests/test_example.py",),
        destination_root=overlay_root,
        candidate_uid=other_uid(),
    )

    assert overlay.phase == "red"
    assert overlay.source_snapshot_sha256 == source.snapshot_sha256
    assert overlay.test_patch_sha256 == sha256_file(patch)
    assert (overlay.snapshot.tree / "tests" / "test_example.py").is_file()
    assert not (source.tree / "tests" / "test_example.py").exists()
    assert (
        verify_readonly_snapshot(overlay.snapshot.root, candidate_uid=other_uid())
        == overlay.snapshot
    )


def test_red_tdd_snapshot_uses_base_production_and_exact_candidate_test_entries(tmp_path):
    bare, base_commit, candidate_commit = make_tdd_repository(tmp_path)
    snapshots = tmp_path / "snapshots"
    snapshots.mkdir(mode=0o700)
    base = create_readonly_snapshot(
        source_repo=bare,
        commit_sha=base_commit,
        destination_root=snapshots,
        candidate_uid=other_uid(),
    )
    candidate = create_readonly_snapshot(
        source_repo=bare,
        commit_sha=candidate_commit,
        destination_root=snapshots,
        candidate_uid=other_uid(),
    )
    overlays = tmp_path / "overlays"
    overlays.mkdir(mode=0o700)

    red = create_red_tdd_snapshot(
        base_snapshot=base,
        candidate_snapshot=candidate,
        test_paths=("tests/test_example.py",),
        destination_root=overlays,
        candidate_uid=other_uid(),
    )

    expected_delta = canonical_json(
        {
            "files": [
                {
                    "after": {
                        "mode": "100755",
                        "sha256": sha256_bytes(b"def test_example(): assert True\n"),
                        "size": 32,
                    },
                    "before": None,
                    "path": "tests/test_example.py",
                }
            ],
            "schema_version": "1.0",
        }
    )
    assert red.phase == "red"
    assert red.source_snapshot_sha256 == base.snapshot_sha256
    assert red.candidate_snapshot_sha256 == candidate.snapshot_sha256
    assert red.test_patch_sha256 == sha256_bytes(expected_delta)
    expected_test_manifest = expected_test_manifest_sha256(
        (("tests/test_example.py", sha256_bytes(b"def test_example(): assert True\n")),)
    )
    assert red.test_manifest_sha256 == expected_test_manifest
    assert (
        build_snapshot_test_manifest(
            snapshot=candidate,
            test_paths=("tests/test_example.py",),
            candidate_uid=other_uid(),
        ).test_manifest_sha256
        == expected_test_manifest
    )
    assert (red.snapshot.tree / "src" / "example.py").read_text() == "VALUE = 1\n"
    assert (red.snapshot.tree / "tests" / "test_example.py").read_bytes() == (
        candidate.tree / "tests" / "test_example.py"
    ).read_bytes()
    assert stat.S_IMODE((red.snapshot.tree / "tests" / "test_example.py").stat().st_mode) == 0o555
    assert (
        verify_red_tdd_snapshot(
            red,
            base_snapshot=base,
            candidate_snapshot=candidate,
            candidate_uid=other_uid(),
        )
        == red
    )
    assert (
        measure_red_tdd_snapshot(
            red_root=red.snapshot.root,
            base_snapshot=base,
            candidate_snapshot=candidate,
            test_paths=("tests/test_example.py",),
            candidate_uid=other_uid(),
        )
        == red
    )


def test_red_tdd_snapshot_rejects_missing_deleted_unchanged_and_non_test_paths(tmp_path):
    bare, base_commit, candidate_commit = make_tdd_repository(tmp_path)
    snapshots = tmp_path / "snapshots"
    snapshots.mkdir(mode=0o700)
    base = create_readonly_snapshot(
        source_repo=bare,
        commit_sha=base_commit,
        destination_root=snapshots,
        candidate_uid=other_uid(),
    )
    candidate = create_readonly_snapshot(
        source_repo=bare,
        commit_sha=candidate_commit,
        destination_root=snapshots,
        candidate_uid=other_uid(),
    )

    for test_paths, message in (
        (("tests/missing.py",), "candidate test path is missing"),
        (("src/example.py",), "below tests"),
    ):
        destination = tmp_path / ("overlay-" + sha256_bytes(repr(test_paths).encode())[:8])
        destination.mkdir(mode=0o700)
        with pytest.raises(SnapshotError, match=message):
            create_red_tdd_snapshot(
                base_snapshot=base,
                candidate_snapshot=candidate,
                test_paths=test_paths,
                destination_root=destination,
                candidate_uid=other_uid(),
            )

    unchanged_destination = tmp_path / "unchanged-overlay"
    unchanged_destination.mkdir(mode=0o700)
    with pytest.raises(SnapshotError, match="must change every exact test path"):
        create_red_tdd_snapshot(
            base_snapshot=candidate,
            candidate_snapshot=candidate,
            test_paths=("tests/test_example.py",),
            destination_root=unchanged_destination,
            candidate_uid=other_uid(),
        )


def test_red_tdd_verifier_rejects_candidate_snapshot_substitution(tmp_path):
    bare, base_commit, candidate_commit = make_tdd_repository(tmp_path)
    snapshots = tmp_path / "snapshots"
    snapshots.mkdir(mode=0o700)
    base = create_readonly_snapshot(
        source_repo=bare,
        commit_sha=base_commit,
        destination_root=snapshots,
        candidate_uid=other_uid(),
    )
    candidate = create_readonly_snapshot(
        source_repo=bare,
        commit_sha=candidate_commit,
        destination_root=snapshots,
        candidate_uid=other_uid(),
    )
    overlays = tmp_path / "overlays"
    overlays.mkdir(mode=0o700)
    red = create_red_tdd_snapshot(
        base_snapshot=base,
        candidate_snapshot=candidate,
        test_paths=("tests/test_example.py",),
        destination_root=overlays,
        candidate_uid=other_uid(),
    )

    with pytest.raises(SnapshotError, match="candidate snapshot binding"):
        verify_red_tdd_snapshot(
            red,
            base_snapshot=base,
            candidate_snapshot=base,
            candidate_uid=other_uid(),
        )


def test_tdd_overlay_rejects_production_path_patch(tmp_path):
    bare, commit = make_bare_repository(tmp_path)
    destination = tmp_path / "snapshots"
    destination.mkdir(mode=0o700)
    source = create_readonly_snapshot(
        source_repo=bare,
        commit_sha=commit,
        destination_root=destination,
        candidate_uid=other_uid(),
    )
    patch = protected_file(
        tmp_path / "production.patch",
        b"diff --git a/src/example.py b/src/example.py\n"
        b"--- a/src/example.py\n"
        b"+++ b/src/example.py\n"
        b"@@ -1 +1 @@\n"
        b"-VALUE = 1\n"
        b"+VALUE = 2\n",
    )
    overlay_root = tmp_path / "overlays"
    overlay_root.mkdir(mode=0o700)

    with pytest.raises(SnapshotError, match="RED-only"):
        create_tdd_overlay_snapshot(
            phase="green",
            source_snapshot=source,
            test_patch_path=patch,
            expected_test_patch_sha256=sha256_file(patch),
            test_paths=("tests/test_example.py",),
            destination_root=overlay_root,
            candidate_uid=other_uid(),
        )
