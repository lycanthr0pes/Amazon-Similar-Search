from __future__ import annotations

import ast
import hashlib
import json
import os
import stat
from pathlib import Path
from types import SimpleNamespace

import pytest

from tools.ai_review import deployment_check
from tools.ai_review.deployment_check import DeploymentCheckError
from tools.ai_review.external_launcher import LauncherTrustError
from tools.ai_review.external_launcher import _run_deployment_check
from tools.ai_review.external_launcher import _validate_phase_request_stdlib


_DIGESTS = {
    "coordinator": "sha256:" + "1" * 64,
    "offline-runner": "sha256:" + "2" * 64,
    "broker": "sha256:" + "3" * 64,
    "broker-gateway": "sha256:" + "4" * 64,
}
_IMAGES = {
    role: f"registry.invalid/amazon-explorer/{role}@{digest}" for role, digest in _DIGESTS.items()
}

_PODMAN_6_GRAPH_OPTIONS = {
    "overlay.mount_program": {
        "Executable": "/usr/bin/fuse-overlayfs",
        "Package": "fuse-overlayfs 1.15-1",
        "Version": "fusermount3 version: 3.17.4\nfuse-overlayfs: version 1.15",
    },
    "overlay.mountopt": "nodev",
}
_BASE_ENV = [
    "GPG_KEY=7169605F62C751356D054A26A821E680E5FA6305",
    "PYTHON_SHA256=5462f9099dfd30e238def83c71d91897d8caa5ff6ebc7a50f14d4802cdaaa79a",
    "PYTHON_VERSION=3.13.7",
]
_CONFIG = {
    "coordinator": {
        "user": "65532:65532",
        "entrypoint": [
            "/opt/ai-review-runtime/.venv/bin/python",
            "-I",
            "/opt/ai-review-app/tools/ai_review/coordinator_main.py",
        ],
        "cmd": None,
        "env": [
            *_BASE_ENV,
            "HOME=/nonexistent",
            "PATH=/opt/ai-review-runtime/.venv/bin:/usr/local/bin:/usr/bin:/bin",
            "PYTHONDONTWRITEBYTECODE=1",
            "PYTHONNOUSERSITE=1",
            "PYTHONHASHSEED=0",
            "VIRTUAL_ENV=/opt/ai-review-runtime/.venv",
        ],
    },
    "offline-runner": {
        "user": "65534:65534",
        "entrypoint": None,
        "cmd": ["python", "--version"],
        "env": [
            *_BASE_ENV,
            "HOME=/nonexistent",
            "PATH=/opt/ai-review-runtime/.venv/bin:/usr/local/bin:/usr/bin:/bin",
            "PYTHONDONTWRITEBYTECODE=1",
            "PYTHONPYCACHEPREFIX=/tmp/pycache",
            "PYTEST_ADDOPTS=-p no:cacheprovider",
            "RUFF_CACHE_DIR=/tmp/ruff-cache",
            "UV_CACHE_DIR=/tmp/uv-cache",
            "UV_FROZEN=1",
            "UV_NO_CACHE=1",
            "UV_OFFLINE=1",
            "UV_PROJECT_ENVIRONMENT=/opt/ai-review-runtime/.venv",
        ],
    },
    "broker": {
        "user": "65532:65532",
        "entrypoint": ["/opt/ai-review/bin/responses-broker"],
        "cmd": None,
        "env": [
            *_BASE_ENV,
            "HOME=/nonexistent",
            "PATH=/usr/local/bin:/usr/bin:/bin",
            "PYTHONDONTWRITEBYTECODE=1",
            "PYTHONNOUSERSITE=1",
            "PYTHONHASHSEED=0",
        ],
    },
    "broker-gateway": {
        "user": "65531:65531",
        "entrypoint": ["/opt/ai-review/bin/egress-gateway"],
        "cmd": None,
        "env": [
            *_BASE_ENV,
            "AI_REVIEW_EGRESS_GATEWAY=1",
            "HOME=/nonexistent",
            "PATH=/usr/local/bin:/usr/bin:/bin",
            "PYTHONDONTWRITEBYTECODE=1",
            "PYTHONNOUSERSITE=1",
            "PYTHONHASHSEED=0",
        ],
    },
}


def _result(exit_code: int, stdout: bytes = b"", stderr: bytes = b"") -> SimpleNamespace:
    return SimpleNamespace(
        exit_code=exit_code,
        stdout=stdout,
        stderr=stderr,
        stdout_sha256=hashlib.sha256(stdout).hexdigest(),
        stderr_sha256=hashlib.sha256(stderr).hexdigest(),
        duration_ms=1,
    )


def test_deployment_module_has_no_python311_only_tomllib_dependency() -> None:
    source = Path(deployment_check.__file__).read_text(encoding="utf-8")
    assert "import tomllib" not in source
    ast.parse(source, filename="deployment_check.py", feature_version=(3, 10))


@pytest.mark.parametrize(
    "config",
    [
        b'[storage]\n"imagestore" = "/candidate-store"\n',
        b'[storage]\nstorage.imagestore = "/candidate-store"\n',
        b'[storage.options]\nadditionalimagestores = ["/candidate-store"]\n',
        b'[storage]\nimagestore = """/candidate-store"""\n',
    ],
)
def test_storage_config_parser_rejects_external_store_and_ambiguous_keys(
    config: bytes,
) -> None:
    with pytest.raises(DeploymentCheckError, match="storage config|external image store"):
        deployment_check.validate_storage_config(
            config,
            graph_driver_name="overlay",
            graph_root=Path("/home/ai/.local/share/containers/storage"),
            run_root=Path("/run/user/1000/containers"),
            transient_store=False,
        )


def test_storage_config_parser_accepts_comments_empty_stores_and_bound_values() -> None:
    deployment_check.validate_storage_config(
        b"""# imagestore = "/comment-only"
[storage]
driver = "overlay"
graphroot = "/home/ai/.local/share/containers/storage"
runroot = "/run/user/1000/containers"
transient_store = false
imagestore = ""
[storage.options]
additionalimagestores = []
[storage.options.overlay]
mount_program = "/usr/bin/fuse-overlayfs" # inline comment
""",
        graph_driver_name="overlay",
        graph_root=Path("/home/ai/.local/share/containers/storage"),
        run_root=Path("/run/user/1000/containers"),
        transient_store=False,
    )


def test_graph_options_accepts_bounded_podman_6_mapping_and_preserves_values() -> None:
    assert (
        deployment_check._validated_graph_options(_PODMAN_6_GRAPH_OPTIONS)
        == _PODMAN_6_GRAPH_OPTIONS
    )


@pytest.mark.parametrize(
    "graph_options",
    [
        {"overlay.imagestore": "/candidate-store"},
        {"overlay.mountopt": "imagestore=/candidate-store"},
        {
            "overlay.mount_program": {
                "Executable": "/usr/bin/fuse-overlayfs",
                "Package": "imagestore-helper",
            }
        },
        {"overlay.mount_program": {"Executable": ["/usr/bin/fuse-overlayfs"]}},
        {"overlay.mountopt": "nodev", 1: "invalid-key"},
        {"overlay.mountopt": "x" * 16_385},
        {"overlay.mountopt": 1},
    ],
)
def test_graph_options_rejects_external_store_or_noncanonical_mapping(
    graph_options: object,
) -> None:
    with pytest.raises(DeploymentCheckError, match="graph options|external image store"):
        deployment_check._validated_graph_options(graph_options)


def _inspect(role: str) -> bytes:
    config = _CONFIG[role]
    return json.dumps(
        [
            {
                "Digest": _DIGESTS[role],
                "RepoDigests": [_IMAGES[role]],
                "Config": {
                    "User": config["user"],
                    "Entrypoint": config["entrypoint"],
                    "Cmd": config["cmd"],
                    "Env": config["env"],
                },
            }
        ]
    ).encode("utf-8")


class FakeRunner:
    def __init__(self) -> None:
        self.calls: list[tuple[str, ...]] = []
        self.limits: list[tuple[tuple[str, ...], int, int]] = []

    def __call__(
        self,
        argv: tuple[str, ...],
        *,
        environment: dict[str, str],
        timeout_seconds: int,
        max_output_bytes: int,
    ) -> SimpleNamespace:
        self.calls.append(argv)
        self.limits.append((argv, timeout_seconds, max_output_bytes))
        assert environment == _host_environment()
        if argv[1:3] == ("image", "inspect"):
            role = next(role for role, image in _IMAGES.items() if image == argv[3])
            return _result(0, _inspect(role))
        if argv[1:3] == ("container", "exists"):
            return _result(1)
        if argv[1] == "run":
            role = next(role for role, image in _IMAGES.items() if image in argv)
            if role == "coordinator":
                return _result(0, b"usage: ai-review [-h] {snapshot,attested-judge}\n")
            if role == "offline-runner":
                return _result(0, b"Python 3.13.7\n")
            if role == "broker":
                return _result(
                    2,
                    stderr=b"ai-review-broker: request is empty or exceeds the byte limit\n",
                )
            return _result(
                2,
                stderr=b"egress gateway error: egress gateway accepts no arguments\n",
            )
        raise AssertionError(f"unexpected container runtime command: {argv!r}")


def _backend() -> SimpleNamespace:
    return SimpleNamespace(
        name="podman",
        executable=Path("/usr/bin/podman"),
        rootless=True,
        user_namespace=True,
        seccomp_enabled=True,
        seccomp_profile="/usr/share/containers/seccomp.json",
        sha256="5" * 64,
        security_evidence_sha256="6" * 64,
        deployment_environment_sha256="7" * 64,
        config_path_sha256="c" * 64,
        graph_root_path_sha256="8" * 64,
        run_root_path_sha256="9" * 64,
        seccomp_path_sha256="a" * 64,
        podman_info_sha256="b" * 64,
        environment=tuple(sorted(_host_environment().items())),
    )


def _host_environment() -> dict[str, str]:
    return {
        "CONTAINERS_STORAGE_CONF": "/home/ai-review/.config/containers/storage.conf",
        "HOME": "/home/ai-review",
        "LC_ALL": "C",
        "PATH": os.defpath,
        "XDG_CONFIG_HOME": "/home/ai-review/.config",
        "XDG_DATA_HOME": "/home/ai-review/.local/share",
        "XDG_RUNTIME_DIR": "/run/user/1000",
    }


def _expected_smoke_call(role: str) -> tuple[str, ...]:
    user = _CONFIG[role]["user"]
    assert isinstance(user, str)
    uid = user.split(":", 1)[0]
    tails = {
        "broker": (),
        "broker-gateway": ("smoke",),
        "coordinator": ("--help",),
        "offline-runner": (),
    }
    return (
        "/usr/bin/podman",
        "run",
        "--rm",
        "--pull=never",
        f"--name=ai-review-deploy-{role}-aaaaaaaaaaaaaaaa",
        "--network=none",
        "--read-only",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "--ipc=none",
        f"--userns=keep-id:uid={uid},gid={uid}",
        f"--user={user}",
        "--workdir=/",
        "--pids-limit=16",
        "--memory=128m",
        "--cpus=0.5",
        "--tmpfs=/tmp:rw,noexec,nosuid,nodev,size=4m,mode=1777",
        _IMAGES[role],
        *tails[role],
    )


def test_deployment_check_inspects_and_smokes_all_images_without_external_boundary() -> None:
    runner = FakeRunner()
    raw = deployment_check.run_deployment_check(
        manifest_sha256="7" * 64,
        backend=_backend(),
        images=_IMAGES,
        approved_digests=_DIGESTS,
        runner=runner,
        token_hex=lambda _size: "a" * 16,
    )

    value = json.loads(raw)
    assert raw == deployment_check.canonical_deployment_check_bytes(value)
    assert value["status"] == "nonlive_ready"
    assert value["production_e2e_complete"] is False
    assert value["credentials_read"] is False
    assert value["external_api_called"] is False
    assert value["external_network_created"] is False
    assert value["manifest_sha256"] == "7" * 64
    assert value["backend_evidence_sha256"] == (
        deployment_check.canonical_backend_evidence_sha256(_backend())
    )
    assert [item["role"] for item in value["images"]] == sorted(_IMAGES)
    assert all(item["inspect_sha256"] for item in value["images"])
    assert all(item["smoke_argv_sha256"] for item in value["images"])
    assert {item["smoke_exit_code"] for item in value["images"]} == {0, 2}
    assert all(item["smoke_stderr_sha256"] for item in value["images"])

    smoke_calls = [call for call in runner.calls if call[1] == "run"]
    assert len(smoke_calls) == 4
    for role in sorted(_IMAGES):
        call = next(call for call in smoke_calls if _IMAGES[role] in call)
        assert call == _expected_smoke_call(role)
        assert not any("OPENAI" in value or "credential" in value.casefold() for value in call)
    assert [timeout for argv, timeout, _maximum in runner.limits if argv[1] == "run"] == [
        60,
        60,
        60,
        60,
    ]
    assert not any(call[1:3] == ("network", "create") for call in runner.calls)


@pytest.mark.parametrize(
    ("role", "field", "replacement"),
    [
        ("broker", "Digest", "sha256:" + "f" * 64),
        ("coordinator", "User", "0:0"),
        ("broker-gateway", "Entrypoint", ["/bin/sh"]),
        ("offline-runner", "Entrypoint", []),
        ("offline-runner", "Cmd", ["sh"]),
        ("coordinator", "Cmd", []),
        ("broker", "Env", [*_CONFIG["broker"]["env"], "OPENAI_API_KEY=forbidden"]),
        ("coordinator", "Env", [*_CONFIG["coordinator"]["env"], "HTTP_PROXY=x"]),
        (
            "broker-gateway",
            "Env",
            [
                *[
                    item
                    for item in _CONFIG["broker-gateway"]["env"]
                    if not item.startswith("GPG_KEY=")
                ],
                "GPG_KEY=0123456789ABCDEF0123456789ABCDEF01234567",
            ],
        ),
    ],
)
def test_deployment_check_rejects_untrusted_local_image_metadata(
    role: str,
    field: str,
    replacement: object,
) -> None:
    class BadInspectRunner(FakeRunner):
        def __call__(self, argv: tuple[str, ...], **kwargs: object) -> SimpleNamespace:
            if argv[1:3] == ("image", "inspect") and argv[3] == _IMAGES[role]:
                payload = json.loads(_inspect(role))
                if field in {"User", "Entrypoint", "Cmd", "Env"}:
                    payload[0]["Config"][field] = replacement
                else:
                    payload[0][field] = replacement
                self.calls.append(argv)
                return _result(0, json.dumps(payload).encode("utf-8"))
            return super().__call__(argv, **kwargs)

    with pytest.raises(DeploymentCheckError, match="image inspection"):
        deployment_check.run_deployment_check(
            manifest_sha256="7" * 64,
            backend=_backend(),
            images=_IMAGES,
            approved_digests=_DIGESTS,
            runner=BadInspectRunner(),
            token_hex=lambda _size: "a" * 16,
        )


@pytest.mark.parametrize(
    "image",
    [
        "https://registry.invalid/repo@sha256:" + "1" * 64,
        "registry.invalid//repo@sha256:" + "1" * 64,
        "registry.invalid/org/../repo@sha256:" + "1" * 64,
        "registry.invalid/repo:latest@sha256:" + "1" * 64,
        "registry.invalid\\repo@sha256:" + "1" * 64,
        "registry.invalid/repo\n@sha256:" + "1" * 64,
        "repo@sha256:" + "1" * 64,
        "registry.invalid:99999/repo@sha256:" + "1" * 64,
    ],
)
def test_deployment_check_rejects_noncanonical_image_references(image: str) -> None:
    images = {**_IMAGES, "coordinator": image}
    runner = FakeRunner()
    with pytest.raises(DeploymentCheckError, match="canonical registry reference"):
        deployment_check.run_deployment_check(
            manifest_sha256="7" * 64,
            backend=_backend(),
            images=images,
            approved_digests=_DIGESTS,
            runner=runner,
        )
    assert runner.calls == []


@pytest.mark.parametrize(
    ("role", "bad_result"),
    [
        ("coordinator", _result(0, b"usage: ai-review snapshot\n")),
        ("offline-runner", _result(0, b"Python 3.13\n")),
        ("offline-runner", _result(0, b"Python 3.13.8\n")),
        (
            "broker",
            _result(2, stderr=b"ai-review-broker: some other failure\n"),
        ),
        (
            "broker-gateway",
            _result(2, stderr=b"egress gateway error: DNS was attempted\n"),
        ),
    ],
)
def test_deployment_check_requires_role_specific_safe_smoke_result(
    role: str,
    bad_result: SimpleNamespace,
) -> None:
    class BadSmokeRunner(FakeRunner):
        def __call__(self, argv: tuple[str, ...], **kwargs: object) -> SimpleNamespace:
            if argv[1] == "run" and _IMAGES[role] in argv:
                self.calls.append(argv)
                return bad_result
            return super().__call__(argv, **kwargs)

    with pytest.raises(DeploymentCheckError, match="smoke result is invalid"):
        deployment_check.run_deployment_check(
            manifest_sha256="7" * 64,
            backend=_backend(),
            images=_IMAGES,
            approved_digests=_DIGESTS,
            runner=BadSmokeRunner(),
            token_hex=lambda _size: "a" * 16,
        )


def _launcher_args() -> SimpleNamespace:
    return SimpleNamespace(
        workflow=False,
        diagnostic_source=False,
        deployment_check=True,
        coordinator_image=_IMAGES["coordinator"],
        offline_image=_IMAGES["offline-runner"],
        broker_image=_IMAGES["broker"],
        broker_gateway_image=_IMAGES["broker-gateway"],
        artifact_root=None,
        candidate_repo=None,
        phase_request=None,
        expected_phase_request_file_sha256=None,
        phase_output_root=None,
        signing_key=None,
        broker_ledger=None,
        attestation_nonce_ledger_root=None,
        reviewer_credential_fd=None,
        adversary_credential_fd=None,
        timeout_seconds=300,
    )


def test_external_deployment_entry_never_loads_credentials_or_broker_outer(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    import socket

    import tools.ai_review.external_launcher as launcher

    backend = _backend()
    loaded: list[str] = []
    detected: list[int] = []
    expected = deployment_check.run_deployment_check(
        manifest_sha256="7" * 64,
        backend=backend,
        images=_IMAGES,
        approved_digests=_DIGESTS,
        runner=FakeRunner(),
        token_hex=lambda _size: "a" * 16,
    )

    def detect(*, candidate_uid: int) -> object:
        detected.append(candidate_uid)
        return backend

    coordinator = SimpleNamespace(
        detect_container_backend=detect,
        _validate_backend=lambda value, *, candidate_uid: value,
        _run_bounded=lambda *_args, **_kwargs: pytest.fail("runner belongs to fake check"),
    )
    workflow = SimpleNamespace(
        PHASE_ORDER=(
            "snapshot",
            "red-snapshot",
            "offline",
            "review-packet",
            "broker",
            "sign",
            "attested-judge",
        ),
        IMPLEMENTED_COORDINATOR_WORKFLOW_PHASES=(
            "snapshot",
            "red-snapshot",
            "offline",
            "review-packet",
            "broker",
            "sign",
            "attested-judge",
        ),
    )
    check = SimpleNamespace(
        run_deployment_check=lambda **kwargs: (
            assert_check_kwargs(kwargs, backend=backend) or expected
        ),
        canonical_backend_evidence_sha256=(deployment_check.canonical_backend_evidence_sha256),
        validate_deployment_check_bytes=deployment_check.validate_deployment_check_bytes,
        validate_launcher_environment=lambda **kwargs: (
            assert_launcher_environment_kwargs(kwargs) or SimpleNamespace()
        ),
        detect_deployment_backend=lambda **kwargs: (
            assert_deployment_backend_kwargs(kwargs, backend=backend) or backend
        ),
    )
    modules = {
        "tools.ai_review.coordinator_launcher": coordinator,
        "tools.ai_review.outer_workflow_runtime": workflow,
        "tools.ai_review.deployment_check": check,
    }

    def load(_evidence: object, name: str) -> object:
        loaded.append(name)
        if "broker" in name or "offline_outer" in name:
            pytest.fail("deployment check must not load an external executor")
        return modules[name]

    monkeypatch.setattr(launcher, "_load_verified_harness_module", load)
    monkeypatch.setattr(launcher, "_assert_deployment_assets_root_owned", lambda _value: None)
    monkeypatch.setattr(launcher, "_assert_deployment_task_v2", lambda _value: None)
    monkeypatch.setattr(launcher.os, "geteuid", lambda: 1000)
    monkeypatch.setattr(
        launcher,
        "_read_credential_fd",
        lambda *_args, **_kwargs: pytest.fail("deployment check read a credential"),
    )
    monkeypatch.setattr(
        socket,
        "create_connection",
        lambda *_args, **_kwargs: pytest.fail("deployment check reached a network socket"),
    )
    evidence = SimpleNamespace(
        candidate_uid=2000,
        manifest_sha256="7" * 64,
        coordinator_image_digest=_DIGESTS["coordinator"],
        offline_runner_image_digest=_DIGESTS["offline-runner"],
        broker_image_digest=_DIGESTS["broker"],
        broker_gateway_image_digest=_DIGESTS["broker-gateway"],
    )

    assert _run_deployment_check(_launcher_args(), evidence) == 0
    assert capsys.readouterr().out.encode("utf-8") == expected
    assert loaded == [
        "tools.ai_review.coordinator_launcher",
        "tools.ai_review.outer_workflow_runtime",
        "tools.ai_review.deployment_check",
    ]
    assert detected == []


def assert_check_kwargs(kwargs: dict[str, object], *, backend: object) -> bool:
    assert kwargs["backend"] is backend
    assert kwargs["images"] == _IMAGES
    assert kwargs["approved_digests"] == _DIGESTS
    assert kwargs["manifest_sha256"] == "7" * 64
    return False


def assert_launcher_environment_kwargs(kwargs: dict[str, object]) -> bool:
    assert kwargs == {"candidate_uid": 2000, "launcher_uid": 1000}
    return False


def assert_deployment_backend_kwargs(kwargs: dict[str, object], *, backend: object) -> bool:
    assert kwargs["candidate_uid"] == 2000
    assert kwargs["launcher_uid"] == 1000
    assert kwargs["host"] == SimpleNamespace()
    assert kwargs["coordinator_module"].detect_container_backend is not None
    assert kwargs["runner"] is kwargs["coordinator_module"]._run_bounded
    return False


def test_external_deployment_entry_rehashes_runtime_after_smoke(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import tools.ai_review.external_launcher as launcher

    backend = _backend()
    changed_backend = SimpleNamespace(**{**vars(backend), "sha256": "9" * 64})
    detected = iter((backend, changed_backend))
    expected = deployment_check.run_deployment_check(
        manifest_sha256="7" * 64,
        backend=backend,
        images=_IMAGES,
        approved_digests=_DIGESTS,
        runner=FakeRunner(),
        token_hex=lambda _size: "a" * 16,
    )
    coordinator = SimpleNamespace(
        detect_container_backend=lambda *, candidate_uid: next(detected),
        _validate_backend=lambda value, *, candidate_uid: value,
        _run_bounded=lambda *_args, **_kwargs: None,
    )
    phases = (
        "snapshot",
        "red-snapshot",
        "offline",
        "review-packet",
        "broker",
        "sign",
        "attested-judge",
    )
    workflow = SimpleNamespace(
        PHASE_ORDER=phases,
        IMPLEMENTED_COORDINATOR_WORKFLOW_PHASES=phases,
    )
    check = SimpleNamespace(
        run_deployment_check=lambda **_kwargs: expected,
        canonical_backend_evidence_sha256=(deployment_check.canonical_backend_evidence_sha256),
        validate_deployment_check_bytes=lambda *_args, **_kwargs: pytest.fail(
            "changed runtime must fail before evidence validation"
        ),
        validate_launcher_environment=lambda **_kwargs: SimpleNamespace(),
        detect_deployment_backend=lambda **_kwargs: next(detected),
    )
    modules = {
        "tools.ai_review.coordinator_launcher": coordinator,
        "tools.ai_review.outer_workflow_runtime": workflow,
        "tools.ai_review.deployment_check": check,
    }
    monkeypatch.setattr(
        launcher,
        "_load_verified_harness_module",
        lambda _evidence, name: modules[name],
    )
    monkeypatch.setattr(launcher, "_assert_deployment_assets_root_owned", lambda _value: None)
    monkeypatch.setattr(launcher, "_assert_deployment_task_v2", lambda _value: None)
    monkeypatch.setattr(launcher.os, "geteuid", lambda: 1000)
    evidence = SimpleNamespace(
        candidate_uid=2000,
        manifest_sha256="7" * 64,
        coordinator_image_digest=_DIGESTS["coordinator"],
        offline_runner_image_digest=_DIGESTS["offline-runner"],
        broker_image_digest=_DIGESTS["broker"],
        broker_gateway_image_digest=_DIGESTS["broker-gateway"],
    )
    with pytest.raises(LauncherTrustError, match="runtime changed"):
        _run_deployment_check(_launcher_args(), evidence)


def _private_directory(path: Path, *, uid: int) -> None:
    path.mkdir(parents=True, exist_ok=True)
    os.chown(path, uid, -1)
    path.chmod(0o700)


def _anchor_tmp_trust(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    original = deployment_check._path_components

    def components(path: Path) -> tuple[Path, ...]:
        values = original(path)
        return values[values.index(tmp_path) :]

    monkeypatch.setattr(deployment_check, "_path_components", components)


def test_graph_root_evidence_tolerates_only_runtime_managed_leaf_ctime_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _anchor_tmp_trust(monkeypatch, tmp_path)
    launcher_uid = 1000
    candidate_uid = 2000
    graph_root = tmp_path / "home" / ".local" / "share" / "containers" / "storage"
    _private_directory(graph_root, uid=launcher_uid)

    before_metadata = graph_root.stat()
    before = deployment_check._measure_private_directory(
        graph_root,
        owner_uid=launcher_uid,
        candidate_uid=candidate_uid,
        volatile_leaf_ctime=True,
    )
    strict_before = deployment_check._measure_private_directory(
        graph_root,
        owner_uid=launcher_uid,
        candidate_uid=candidate_uid,
    )
    os.utime(
        graph_root,
        ns=(before_metadata.st_atime_ns, before_metadata.st_mtime_ns + 1_000_000_000),
    )
    after_metadata = graph_root.stat()
    after = deployment_check._measure_private_directory(
        graph_root,
        owner_uid=launcher_uid,
        candidate_uid=candidate_uid,
        volatile_leaf_ctime=True,
    )
    strict_after = deployment_check._measure_private_directory(
        graph_root,
        owner_uid=launcher_uid,
        candidate_uid=candidate_uid,
    )

    assert after_metadata.st_ctime_ns != before_metadata.st_ctime_ns
    assert (
        after_metadata.st_dev,
        after_metadata.st_ino,
        stat.S_IMODE(after_metadata.st_mode),
        after_metadata.st_uid,
        after_metadata.st_gid,
    ) == (
        before_metadata.st_dev,
        before_metadata.st_ino,
        stat.S_IMODE(before_metadata.st_mode),
        before_metadata.st_uid,
        before_metadata.st_gid,
    )
    assert deployment_check._path_evidence_sha256(after) == (
        deployment_check._path_evidence_sha256(before)
    )
    assert deployment_check._path_evidence_sha256(strict_after) != (
        deployment_check._path_evidence_sha256(strict_before)
    )
    assert before["components"][-1]["volatile_metadata"] == ["ctime_ns"]
    assert all("ctime_ns" in component for component in before["components"][:-1])


@pytest.mark.parametrize("drift", ["mode", "owner", "inode", "path"])
def test_graph_root_evidence_rejects_or_binds_real_identity_drift(
    drift: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _anchor_tmp_trust(monkeypatch, tmp_path)
    launcher_uid = 1000
    candidate_uid = 2000
    graph_root = tmp_path / "home" / ".local" / "share" / "containers" / "storage"
    alternate_root = graph_root.parent / "alternate-storage"
    _private_directory(graph_root, uid=launcher_uid)
    _private_directory(alternate_root, uid=launcher_uid)
    before_inode = graph_root.stat().st_ino
    before = deployment_check._measure_private_directory(
        graph_root,
        owner_uid=launcher_uid,
        candidate_uid=candidate_uid,
        volatile_leaf_ctime=True,
    )

    measured_path = graph_root
    if drift == "mode":
        graph_root.chmod(0o500)
    elif drift == "owner":
        os.chown(graph_root, candidate_uid, -1)
        with pytest.raises(DeploymentCheckError, match="untrusted owner"):
            deployment_check._measure_private_directory(
                graph_root,
                owner_uid=launcher_uid,
                candidate_uid=candidate_uid,
                volatile_leaf_ctime=True,
            )
        return
    elif drift == "inode":
        graph_root.rename(graph_root.parent / "held-original-storage")
        _private_directory(graph_root, uid=launcher_uid)
        assert graph_root.stat().st_ino != before_inode
    else:
        measured_path = alternate_root

    after = deployment_check._measure_private_directory(
        measured_path,
        owner_uid=launcher_uid,
        candidate_uid=candidate_uid,
        volatile_leaf_ctime=True,
    )
    assert deployment_check._path_evidence_sha256(after) != (
        deployment_check._path_evidence_sha256(before)
    )


def test_launcher_environment_comes_only_from_passwd_and_canonical_xdg_paths(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _anchor_tmp_trust(monkeypatch, tmp_path)
    launcher_uid = 1000
    candidate_uid = 2000
    home = tmp_path / "home" / "ai-review"
    runtime_base = tmp_path / "run" / "user"
    for path in (
        home,
        home / ".config",
        home / ".local",
        home / ".local" / "share",
        runtime_base / str(launcher_uid),
    ):
        _private_directory(path, uid=launcher_uid)
    host = deployment_check.validate_launcher_environment(
        launcher_uid=launcher_uid,
        candidate_uid=candidate_uid,
        environ={
            "HOME": "/attacker",
            "XDG_CONFIG_HOME": "/attacker/config",
            "XDG_DATA_HOME": "/attacker/data",
            "XDG_RUNTIME_DIR": "/attacker/run",
        },
        passwd_lookup=lambda uid: SimpleNamespace(pw_uid=uid, pw_dir=str(home)),
        runtime_base=runtime_base,
    )

    assert dict(host.environment) == {
        "CONTAINERS_STORAGE_CONF": str(home / ".config" / "containers" / "storage.conf"),
        "HOME": str(home),
        "LC_ALL": "C",
        "PATH": os.defpath,
        "XDG_CONFIG_HOME": str(home / ".config"),
        "XDG_DATA_HOME": str(home / ".local" / "share"),
        "XDG_RUNTIME_DIR": str(runtime_base / str(launcher_uid)),
    }
    assert len(host.evidence_sha256) == 64


def test_launcher_environment_rejects_candidate_accessible_or_symlinked_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _anchor_tmp_trust(monkeypatch, tmp_path)
    launcher_uid = 1000
    home = tmp_path / "home"
    runtime_base = tmp_path / "run" / "user"
    for path in (
        home,
        home / ".config",
        home / ".local",
        home / ".local" / "share",
        runtime_base / str(launcher_uid),
    ):
        _private_directory(path, uid=launcher_uid)
    home.chmod(0o755)
    with pytest.raises(DeploymentCheckError, match="candidate-inaccessible"):
        deployment_check.validate_launcher_environment(
            launcher_uid=launcher_uid,
            candidate_uid=2000,
            passwd_lookup=lambda uid: SimpleNamespace(pw_uid=uid, pw_dir=str(home)),
            runtime_base=runtime_base,
        )

    home.chmod(0o700)
    (home / ".config").rmdir()
    (home / ".config").symlink_to(home / ".local")
    with pytest.raises(DeploymentCheckError, match="symlink"):
        deployment_check.validate_launcher_environment(
            launcher_uid=launcher_uid,
            candidate_uid=2000,
            passwd_lookup=lambda uid: SimpleNamespace(pw_uid=uid, pw_dir=str(home)),
            runtime_base=runtime_base,
        )


def test_launcher_environment_rejects_posix_acl(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _anchor_tmp_trust(monkeypatch, tmp_path)
    launcher_uid = 1000
    home = tmp_path / "home"
    runtime_base = tmp_path / "run" / "user"
    for path in (
        home,
        home / ".config",
        home / ".local",
        home / ".local" / "share",
        runtime_base / str(launcher_uid),
    ):
        _private_directory(path, uid=launcher_uid)
    original = deployment_check.os.listxattr

    def listxattr(path: object, **kwargs: object) -> list[str]:
        if Path(path) == home:
            return ["system.posix_acl_access"]
        return list(original(path, **kwargs))

    monkeypatch.setattr(deployment_check.os, "listxattr", listxattr)
    with pytest.raises(DeploymentCheckError, match="POSIX ACL"):
        deployment_check.validate_launcher_environment(
            launcher_uid=launcher_uid,
            candidate_uid=2000,
            passwd_lookup=lambda uid: SimpleNamespace(pw_uid=uid, pw_dir=str(home)),
            runtime_base=runtime_base,
        )


def test_launcher_environment_rejects_writable_or_candidate_owned_ancestor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _anchor_tmp_trust(monkeypatch, tmp_path)
    launcher_uid = 1000
    candidate_uid = 2000
    boundary = tmp_path / "boundary"
    home = boundary / "home"
    runtime_base = tmp_path / "run" / "user"
    for path in (
        home,
        home / ".config",
        home / ".local",
        home / ".local" / "share",
        runtime_base / str(launcher_uid),
    ):
        _private_directory(path, uid=launcher_uid)
    boundary.chmod(0o777)
    with pytest.raises(DeploymentCheckError, match="writable ancestor"):
        deployment_check.validate_launcher_environment(
            launcher_uid=launcher_uid,
            candidate_uid=candidate_uid,
            passwd_lookup=lambda uid: SimpleNamespace(pw_uid=uid, pw_dir=str(home)),
            runtime_base=runtime_base,
        )

    boundary.chmod(0o700)
    os.chown(boundary, candidate_uid, -1)
    with pytest.raises(DeploymentCheckError, match="untrusted owner"):
        deployment_check.validate_launcher_environment(
            launcher_uid=launcher_uid,
            candidate_uid=candidate_uid,
            passwd_lookup=lambda uid: SimpleNamespace(pw_uid=uid, pw_dir=str(home)),
            runtime_base=runtime_base,
        )


def test_backend_evidence_binds_podman_storage_runtime_and_seccomp_paths() -> None:
    backend = _backend()
    baseline = deployment_check.canonical_backend_evidence_sha256(backend)
    changed = SimpleNamespace(**{**vars(backend), "graph_root_path_sha256": "c" * 64})
    assert deployment_check.canonical_backend_evidence_sha256(changed) != baseline


def test_backend_probe_and_info_use_only_validated_home_xdg_environment(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _anchor_tmp_trust(monkeypatch, tmp_path)
    launcher_uid = 1000
    environment = {
        "CONTAINERS_STORAGE_CONF": str(
            tmp_path / "home" / ".config" / "containers" / "storage.conf"
        ),
        "HOME": str(tmp_path / "home"),
        "LC_ALL": "C",
        "PATH": os.defpath,
        "XDG_CONFIG_HOME": str(tmp_path / "home" / ".config"),
        "XDG_DATA_HOME": str(tmp_path / "home" / ".local" / "share"),
        "XDG_RUNTIME_DIR": str(tmp_path / "run" / "user" / "1000"),
    }
    graph_root = Path(environment["XDG_DATA_HOME"]) / "containers" / "storage"
    run_root = Path(environment["XDG_RUNTIME_DIR"]) / "containers"
    config = Path(environment["XDG_CONFIG_HOME"]) / "containers" / "storage.conf"
    for path in (graph_root, run_root):
        _private_directory(path, uid=launcher_uid)
    config.parent.mkdir(parents=True, exist_ok=True)
    config.write_text(
        '[storage]\n[storage.options.overlay]\nmount_program = "/usr/bin/fuse-overlayfs"\n',
        encoding="utf-8",
    )
    os.chown(config, launcher_uid, -1)
    config.chmod(0o600)
    seccomp_root = tmp_path / "protected" / "containers"
    seccomp_root.mkdir(parents=True)
    seccomp_root.chmod(0o755)
    seccomp = seccomp_root / "seccomp.json"
    seccomp.write_text("{}\n", encoding="utf-8")
    seccomp.chmod(0o444)
    podman = tmp_path / "podman"
    podman.write_bytes(b"runtime")
    podman.chmod(0o755)
    monkeypatch.setattr(deployment_check.shutil, "which", lambda *_args, **_kwargs: str(podman))
    info = {
        "host": {
            "security": {
                "rootless": True,
                "seccompEnabled": True,
                "seccompProfilePath": str(seccomp),
            },
            "uptime": "1s",
        },
        "store": {
            "graphDriverName": "overlay",
            "graphOptions": _PODMAN_6_GRAPH_OPTIONS,
            "graphRoot": str(graph_root),
            "graphRootUsed": 100,
            "runRoot": str(run_root),
            "transientStore": False,
        },
    }
    raw_info = json.dumps(info).encode("utf-8")
    calls: list[tuple[tuple[str, ...], dict[str, str]]] = []

    def runner(argv: tuple[str, ...], **kwargs: object) -> SimpleNamespace:
        calls.append((argv, kwargs["environment"]))
        return _result(0, raw_info)

    base = SimpleNamespace(
        name="podman",
        executable=podman.resolve(),
        rootless=True,
        user_namespace=True,
        seccomp_enabled=True,
        seccomp_profile=str(seccomp),
        sha256="1" * 64,
        security_evidence_sha256="2" * 64,
    )

    def detect(**kwargs: object) -> object:
        assert kwargs["candidate_uid"] == 2000
        assert kwargs["which"]("podman") == str(podman.resolve())
        completed = kwargs["probe"](
            (str(podman.resolve()), "info", "--format", "json"),
            env={"HOME": "/attacker"},
        )
        assert completed.returncode == 0
        return base

    host = deployment_check.LauncherEnvironmentEvidence(
        environment=tuple(sorted(environment.items())),
        evidence_sha256="3" * 64,
    )
    measured = deployment_check.detect_deployment_backend(
        coordinator_module=SimpleNamespace(
            detect_container_backend=detect,
            _validate_backend=lambda backend, *, candidate_uid: backend,
        ),
        candidate_uid=2000,
        launcher_uid=launcher_uid,
        host=host,
        runner=runner,
    )

    info["host"]["uptime"] = "2s"
    info["store"]["configFile"] = None
    info["store"]["graphRootUsed"] = 200
    raw_info = json.dumps(info).encode("utf-8")
    remeasured = deployment_check.detect_deployment_backend(
        coordinator_module=SimpleNamespace(
            detect_container_backend=detect,
            _validate_backend=lambda backend, *, candidate_uid: backend,
        ),
        candidate_uid=2000,
        launcher_uid=launcher_uid,
        host=host,
        runner=runner,
    )

    assert calls == [
        ((str(podman.resolve()), "info", "--format", "json"), environment),
        ((str(podman.resolve()), "info", "--format", "json"), environment),
    ]
    assert measured.deployment_environment_sha256 == "3" * 64
    assert len(measured.podman_info_sha256) == 64
    assert remeasured == measured
    assert all(
        len(value) == 64
        for value in (
            measured.graph_root_path_sha256,
            measured.run_root_path_sha256,
            measured.seccomp_path_sha256,
        )
    )

    changed_options = json.loads(json.dumps(_PODMAN_6_GRAPH_OPTIONS))
    changed_options["overlay.mount_program"]["Package"] = "fuse-overlayfs 1.15-2"
    info["store"]["graphOptions"] = changed_options
    raw_info = json.dumps(info).encode("utf-8")
    changed = deployment_check.detect_deployment_backend(
        coordinator_module=SimpleNamespace(
            detect_container_backend=detect,
            _validate_backend=lambda backend, *, candidate_uid: backend,
        ),
        candidate_uid=2000,
        launcher_uid=launcher_uid,
        host=host,
        runner=runner,
    )
    assert changed.podman_info_sha256 != measured.podman_info_sha256
    info["store"]["graphOptions"] = _PODMAN_6_GRAPH_OPTIONS
    raw_info = json.dumps(info).encode("utf-8")

    host_without_explicit_config = deployment_check.LauncherEnvironmentEvidence(
        environment=tuple(
            sorted(
                (name, value)
                for name, value in environment.items()
                if name != "CONTAINERS_STORAGE_CONF"
            )
        ),
        evidence_sha256="3" * 64,
    )
    with pytest.raises(DeploymentCheckError, match="CONTAINERS_STORAGE_CONF"):
        deployment_check.detect_deployment_backend(
            coordinator_module=SimpleNamespace(
                detect_container_backend=detect,
                _validate_backend=lambda backend, *, candidate_uid: backend,
            ),
            candidate_uid=2000,
            launcher_uid=launcher_uid,
            host=host_without_explicit_config,
            runner=runner,
        )

    info["store"]["configFile"] = str(config.parent / "other.conf")
    raw_info = json.dumps(info).encode("utf-8")
    with pytest.raises(DeploymentCheckError, match="configFile.*disagrees"):
        deployment_check.detect_deployment_backend(
            coordinator_module=SimpleNamespace(
                detect_container_backend=detect,
                _validate_backend=lambda backend, *, candidate_uid: backend,
            ),
            candidate_uid=2000,
            launcher_uid=launcher_uid,
            host=host,
            runner=runner,
        )
    info["store"].pop("configFile")

    info["host"]["security"]["rootless"] = False
    raw_info = json.dumps(info).encode("utf-8")
    with pytest.raises(DeploymentCheckError, match="security subset"):
        deployment_check.detect_deployment_backend(
            coordinator_module=SimpleNamespace(
                detect_container_backend=detect,
                _validate_backend=lambda backend, *, candidate_uid: backend,
            ),
            candidate_uid=2000,
            launcher_uid=launcher_uid,
            host=host,
            runner=runner,
        )

    info["host"]["security"]["rootless"] = True
    config.write_text(
        "# imagestore = '/comment-is-allowed'\n[storage]\nimagestore = '/candidate-store'\n",
        encoding="utf-8",
    )
    os.chown(config, launcher_uid, -1)
    config.chmod(0o600)
    raw_info = json.dumps(info).encode("utf-8")
    with pytest.raises(DeploymentCheckError, match="external image store"):
        deployment_check.detect_deployment_backend(
            coordinator_module=SimpleNamespace(
                detect_container_backend=detect,
                _validate_backend=lambda backend, *, candidate_uid: backend,
            ),
            candidate_uid=2000,
            launcher_uid=launcher_uid,
            host=host,
            runner=runner,
        )

    config.write_text(
        '[storage]\n[storage.options.overlay]\nmount_program = "/usr/bin/other-overlay"\n',
        encoding="utf-8",
    )
    os.chown(config, launcher_uid, -1)
    config.chmod(0o600)
    info["store"]["graphOptions"] = _PODMAN_6_GRAPH_OPTIONS
    raw_info = json.dumps(info).encode("utf-8")
    with pytest.raises(DeploymentCheckError, match="mount_program.*disagrees"):
        deployment_check.detect_deployment_backend(
            coordinator_module=SimpleNamespace(
                detect_container_backend=detect,
                _validate_backend=lambda backend, *, candidate_uid: backend,
            ),
            candidate_uid=2000,
            launcher_uid=launcher_uid,
            host=host,
            runner=runner,
        )

    config.write_text("[storage]\n", encoding="utf-8")
    os.chown(config, launcher_uid, -1)
    config.chmod(0o600)
    info["store"]["graphOptions"] = ["overlay.imagestore=/candidate-store"]
    raw_info = json.dumps(info).encode("utf-8")
    with pytest.raises(DeploymentCheckError, match="external image store"):
        deployment_check.detect_deployment_backend(
            coordinator_module=SimpleNamespace(
                detect_container_backend=detect,
                _validate_backend=lambda backend, *, candidate_uid: backend,
            ),
            candidate_uid=2000,
            launcher_uid=launcher_uid,
            host=host,
            runner=runner,
        )


def test_external_deployment_entry_rejects_root_launcher_before_import(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import tools.ai_review.external_launcher as launcher

    monkeypatch.setattr(launcher.os, "geteuid", lambda: 0)
    monkeypatch.setattr(
        launcher,
        "_load_verified_harness_module",
        lambda *_args: pytest.fail("root launcher must fail before harness import"),
    )
    with pytest.raises(LauncherTrustError, match="non-root launcher"):
        _run_deployment_check(
            _launcher_args(),
            SimpleNamespace(candidate_uid=2000),
        )


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("artifact_root", Path("/forbidden/artifacts")),
        ("candidate_repo", Path("/forbidden/candidate")),
        ("phase_request", Path("/forbidden/request.json")),
        ("expected_phase_request_file_sha256", "9" * 64),
        ("phase_output_root", Path("/forbidden/output")),
        ("signing_key", Path("/forbidden/key")),
        ("broker_ledger", Path("/forbidden/ledger")),
        ("attestation_nonce_ledger_root", Path("/forbidden/nonces")),
        ("reviewer_credential_fd", 7),
        ("adversary_credential_fd", 8),
    ],
)
def test_external_deployment_entry_rejects_sensitive_workflow_inputs(
    name: str,
    value: object,
) -> None:
    args = _launcher_args()
    setattr(args, name, value)
    with pytest.raises(LauncherTrustError, match="forbids workflow inputs"):
        _run_deployment_check(args, SimpleNamespace())


@pytest.mark.parametrize(
    "conflict",
    [
        ["--workflow"],
        ["--diagnostic-source"],
        ["--", "snapshot"],
    ],
)
def test_deployment_mode_is_exclusive_before_preflight(
    conflict: list[str],
    capsys: pytest.CaptureFixture[str],
) -> None:
    import tools.ai_review.external_launcher as launcher

    result = launcher.main(
        [
            "--manifest",
            "/must-not-be-read.json",
            "--expected-manifest-sha256",
            "a" * 64,
            "--candidate-uid",
            "2000",
            "--deployment-check",
            *conflict,
        ]
    )
    assert result == 2
    assert "deployment-check mode is exclusive" in capsys.readouterr().err


def _held_task_evidence(
    tmp_path: Path,
    raw: bytes,
    *,
    harness_sha256: str = "a" * 64,
) -> tuple[SimpleNamespace, int]:
    task_path = tmp_path / "task.json"
    task_path.write_bytes(raw)
    descriptor = os.open(task_path, os.O_RDONLY)
    evidence = SimpleNamespace(
        task=SimpleNamespace(
            path=task_path,
            sha256=hashlib.sha256(raw).hexdigest(),
        ),
        harness=SimpleNamespace(
            path=tmp_path / "harness.pyz",
            sha256=harness_sha256,
        ),
        fd_path=lambda name: (
            f"/proc/self/fd/{descriptor}"
            if name == "task"
            else pytest.fail("only the held task FD may be read")
        ),
    )
    return evidence, descriptor


def test_deployment_task_v2_is_rechecked_from_held_descriptor(tmp_path: Path) -> None:
    import tools.ai_review.external_launcher as launcher

    raw = json.dumps(
        {
            "schema_version": "2.0",
            "trusted_harness_sha256": "a" * 64,
        }
    ).encode("utf-8")
    evidence, descriptor = _held_task_evidence(tmp_path, raw)
    try:
        launcher._assert_deployment_task_v2(evidence)
    finally:
        os.close(descriptor)


def test_deployment_entry_rejects_v1_task_before_loading_harness(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import tools.ai_review.external_launcher as launcher

    raw = json.dumps(
        {
            "schema_version": "1.0",
            "trusted_harness_sha256": "a" * 64,
        }
    ).encode("utf-8")
    evidence, descriptor = _held_task_evidence(tmp_path, raw)
    evidence.candidate_uid = 2000
    monkeypatch.setattr(launcher.os, "geteuid", lambda: 1000)
    monkeypatch.setattr(launcher, "_assert_deployment_assets_root_owned", lambda _value: None)
    monkeypatch.setattr(
        launcher,
        "_load_verified_harness_module",
        lambda *_args: pytest.fail("TaskSpec v1 must fail before harness import"),
    )
    try:
        with pytest.raises(LauncherTrustError, match="TaskSpec v2"):
            _run_deployment_check(_launcher_args(), evidence)
    finally:
        os.close(descriptor)


def test_deployment_task_v2_rejects_duplicate_or_wrong_harness_binding(
    tmp_path: Path,
) -> None:
    import tools.ai_review.external_launcher as launcher

    duplicate = (
        b'{"schema_version":"2.0","schema_version":"2.0",'
        b'"trusted_harness_sha256":"' + b"a" * 64 + b'"}'
    )
    evidence, descriptor = _held_task_evidence(tmp_path, duplicate)
    try:
        with pytest.raises(LauncherTrustError, match="duplicate key"):
            launcher._assert_deployment_task_v2(evidence)
    finally:
        os.close(descriptor)

    wrong_path = tmp_path / "wrong"
    wrong_path.mkdir()
    wrong = json.dumps(
        {
            "schema_version": "2.0",
            "trusted_harness_sha256": "b" * 64,
        }
    ).encode("utf-8")
    evidence, descriptor = _held_task_evidence(wrong_path, wrong)
    try:
        with pytest.raises(LauncherTrustError, match="bind the verified harness"):
            launcher._assert_deployment_task_v2(evidence)
    finally:
        os.close(descriptor)


def test_deployment_assets_require_root_owned_non_checkout_files(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import tools.ai_review.external_launcher as launcher

    paths = [Path(f"/release/asset-{index}") for index in range(9)]
    evidence = SimpleNamespace(
        manifest_path=paths[0],
        python=SimpleNamespace(path=paths[1]),
        harness=SimpleNamespace(path=paths[2]),
        task=SimpleNamespace(path=paths[3]),
        dependency_lock=SimpleNamespace(path=paths[4]),
        schema_bundle=SimpleNamespace(path=paths[5]),
        coordinator_public_key=SimpleNamespace(path=paths[6]),
        broker_egress_policy=SimpleNamespace(path=paths[7]),
        openai_pricing_policy=SimpleNamespace(path=paths[8]),
    )
    inspected: list[Path] = []

    def inspect(path: Path, *, label: str) -> Path:
        assert label.startswith("deployment ")
        inspected.append(path)
        return path

    monkeypatch.setattr(launcher, "_assert_root_owned_path", inspect)
    monkeypatch.setattr(launcher, "_inside_git_checkout", lambda _path: False)
    launcher._assert_deployment_assets_root_owned(evidence)
    assert inspected == paths

    monkeypatch.setattr(launcher, "_inside_git_checkout", lambda _path: True)
    with pytest.raises(LauncherTrustError, match="outside a Git checkout"):
        launcher._assert_deployment_assets_root_owned(evidence)


def test_stdlib_initial_request_requires_canonical_empty_artifact_digest() -> None:
    from tools.ai_review.phase_protocol import PhaseRequest
    from tools.ai_review.phase_protocol import canonical_json_bytes

    values = {
        "workflow_id": "a" * 64,
        "phase": "snapshot",
        "sequence": 1,
        "previous_phase_sha256": None,
        "task_sha256": "b" * 64,
        "runtime_manifest_sha256": "c" * 64,
        "coordinator_key_id": "d" * 64,
        "coordinator_public_key_sha256": "e" * 64,
        "candidate_sha256": "f" * 64,
        "candidate_snapshot_sha256": None,
        "review_packet_sha256": None,
    }
    valid = PhaseRequest.create(
        **values,
        input_artifacts_sha256=deployment_check.EMPTY_ARTIFACT_SET_SHA256,
    )
    assert _validate_phase_request_stdlib(canonical_json_bytes(valid)) == valid.model_dump(
        mode="json"
    )

    invalid = valid.model_dump(mode="json")
    invalid["input_artifacts_sha256"] = "0" * 64
    unsigned = {key: value for key, value in invalid.items() if key != "request_sha256"}
    invalid["request_sha256"] = hashlib.sha256(
        b"amazon-explorer-phase-request-v1\0" + canonical_json_bytes(unsigned)
    ).hexdigest()
    with pytest.raises(LauncherTrustError, match="empty artifact set"):
        _validate_phase_request_stdlib(canonical_json_bytes(invalid))
