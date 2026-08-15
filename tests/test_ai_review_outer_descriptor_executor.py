from __future__ import annotations

import hashlib
import json
import os
import subprocess
from pathlib import Path

import pytest

from tools.ai_review.outer_descriptor_executor import OuterDescriptorError
from tools.ai_review.outer_descriptor_executor import OuterExecutionDescriptor
from tools.ai_review.outer_descriptor_executor import execute_outer_descriptor


def _runtime(tmp_path: Path) -> Path:
    runtime = tmp_path / "podman"
    runtime.write_text(
        "#!/usr/bin/python3\n"
        "import sys\n"
        "if sys.argv[1:2] == ['rm']: raise SystemExit(0)\n"
        "raw = sys.stdin.buffer.read()\n"
        "sys.stdout.buffer.write(raw)\n",
        encoding="utf-8",
    )
    runtime.chmod(0o555)
    return runtime


def _descriptor(tmp_path: Path, kind: str) -> bytes:
    runtime = _runtime(tmp_path)
    runtime_sha256 = hashlib.sha256(runtime.read_bytes()).hexdigest()
    image_digest = "sha256:" + ("1" if kind == "offline" else "2") * 64
    image = f"registry.invalid/{kind}@{image_digest}"
    name = f"ai-review-{kind}-" + "a" * 24
    profile = [
        str(runtime),
        "run",
        "--rm",
        "--pull=never",
        f"--name={name}",
        "--read-only",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "--ipc=none",
        "--userns=keep-id:uid=65532,gid=65532",
        "--user=65532:65532",
        "--pids-limit=128",
        "--memory=1g",
        "--cpus=1",
        "--tmpfs=/tmp:rw,noexec,nosuid,nodev,size=32m,mode=1777",
        "--env=PYTHONDONTWRITEBYTECODE=1",
        "--env=PYTHONNOUSERSITE=1",
    ]
    if kind == "offline":
        snapshot = tmp_path / "snapshot"
        snapshot.mkdir(mode=0o555)
        profile.extend(
            (
                "--network=none",
                "--mount",
                f"type=bind,src={snapshot},dst=/workspace,readonly,bind-propagation=rprivate",
            )
        )
    else:
        profile.append("--network=ai-review-broker-" + "b" * 24)
    profile.extend((image, "worker"))
    return OuterExecutionDescriptor.create(
        kind=kind,
        request_sha256="3" * 64,
        candidate_uid=65_534 if os.geteuid() != 65_534 else 65_533,
        runtime_path=runtime,
        runtime_sha256=runtime_sha256,
        image=image,
        approved_image_digest=image_digest,
        container_name=name,
        argv=tuple(profile),
        stdin=b'{"packet":true}\n',
    )


def _replace_argv(raw: bytes, argv: list[str]) -> bytes:
    payload = json.loads(raw)
    payload["argv"] = argv
    unsigned = {key: value for key, value in payload.items() if key != "descriptor_sha256"}
    module = __import__(
        "tools.ai_review.outer_descriptor_executor",
        fromlist=["_domain_sha256"],
    )
    payload["descriptor_sha256"] = module._domain_sha256(unsigned)
    return (json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n").encode()


@pytest.mark.parametrize("kind", ["offline", "broker"])
def test_stdlib_outer_descriptor_executes_bounded_subprocess_and_cleanup(
    tmp_path: Path,
    kind: str,
) -> None:
    raw = _descriptor(tmp_path, kind)
    evidence = json.loads(
        execute_outer_descriptor(
            raw,
            credential="test-credential-not-recorded" if kind == "broker" else None,
        )
    )
    assert evidence["kind"] == kind
    assert evidence["cleanup_succeeded"] is True
    assert evidence["stdout_sha256"] == hashlib.sha256(b'{"packet":true}\n').hexdigest()
    assert "credential" not in json.dumps(evidence)


@pytest.mark.parametrize(
    "forged",
    [
        "--privileged",
        "--network=host",
        "type=bind,src=/run/podman/podman.sock,dst=/run/podman/podman.sock",
    ],
)
def test_outer_descriptor_rejects_privilege_host_network_and_runtime_socket(
    tmp_path: Path,
    forged: str,
) -> None:
    payload = json.loads(_descriptor(tmp_path, "offline"))
    payload["argv"].append(forged)
    unsigned = {key: value for key, value in payload.items() if key != "descriptor_sha256"}
    module = __import__(
        "tools.ai_review.outer_descriptor_executor",
        fromlist=["_domain_sha256"],
    )
    payload["descriptor_sha256"] = module._domain_sha256(unsigned)
    raw = (json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n").encode()
    with pytest.raises(OuterDescriptorError):
        OuterExecutionDescriptor.parse(raw)


@pytest.mark.parametrize(
    "extra",
    [
        ("--privileged=true",),
        ("--security-opt=seccomp=unconfined",),
        ("--security-opt", "seccomp=unconfined"),
        ("--mount=type=bind,src=/,dst=/host,readonly",),
        ("--volume=/:/host:ro",),
        ("--network", "host"),
        ("--cap-add=SYS_ADMIN",),
        ("--unknown-option=value",),
    ],
)
def test_outer_descriptor_rejects_assigned_split_and_unknown_runtime_options(
    tmp_path: Path,
    extra: tuple[str, ...],
) -> None:
    payload = json.loads(_descriptor(tmp_path, "offline"))
    forged = _replace_argv(
        (json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n").encode(),
        [*payload["argv"], *extra],
    )
    with pytest.raises(OuterDescriptorError, match="canonical container profile"):
        OuterExecutionDescriptor.parse(forged)


@pytest.mark.parametrize("source", ["/", "/etc", "/proc", "/candidate"])
def test_offline_descriptor_rejects_broad_or_candidate_mount_sources(
    tmp_path: Path,
    source: str,
) -> None:
    raw = _descriptor(tmp_path, "offline")
    payload = json.loads(raw)
    mount_index = payload["argv"].index("--mount") + 1
    payload["argv"][mount_index] = (
        f"type=bind,src={source},dst=/workspace,readonly,bind-propagation=rprivate"
    )
    with pytest.raises(OuterDescriptorError, match="mount source"):
        OuterExecutionDescriptor.parse(_replace_argv(raw, payload["argv"]))


def test_outer_descriptor_rejects_noncanonical_option_order(tmp_path: Path) -> None:
    raw = _descriptor(tmp_path, "broker")
    payload = json.loads(raw)
    memory_index = payload["argv"].index("--memory=1g")
    cpu_index = payload["argv"].index("--cpus=1")
    payload["argv"][memory_index], payload["argv"][cpu_index] = (
        payload["argv"][cpu_index],
        payload["argv"][memory_index],
    )
    with pytest.raises(OuterDescriptorError, match="canonical container profile"):
        OuterExecutionDescriptor.parse(_replace_argv(raw, payload["argv"]))


def test_broker_descriptor_rejects_candidate_path_or_mount(tmp_path: Path) -> None:
    payload = json.loads(_descriptor(tmp_path, "broker"))
    payload["argv"].extend(("--mount", "type=bind,src=/candidate,dst=/candidate,readonly"))
    unsigned = {key: value for key, value in payload.items() if key != "descriptor_sha256"}
    module = __import__(
        "tools.ai_review.outer_descriptor_executor",
        fromlist=["_domain_sha256"],
    )
    payload["descriptor_sha256"] = module._domain_sha256(unsigned)
    raw = (json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n").encode()
    with pytest.raises(OuterDescriptorError, match="packet stdin"):
        OuterExecutionDescriptor.parse(raw)


def test_outer_descriptor_module_imports_under_i_s_without_site_packages(tmp_path: Path) -> None:
    module = (
        Path(__file__).resolve().parents[1] / "tools" / "ai_review" / "outer_descriptor_executor.py"
    )
    script = (
        "import importlib.util,sys;"
        "spec=importlib.util.spec_from_file_location('outer_executor',sys.argv[1]);"
        "value=importlib.util.module_from_spec(spec);sys.modules[spec.name]=value;"
        "spec.loader.exec_module(value);"
        "assert 'pydantic' not in sys.modules;assert 'cryptography' not in sys.modules"
    )
    result = subprocess.run(
        ["/usr/bin/python3", "-I", "-S", "-c", script, str(module)],
        cwd=tmp_path,
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
        env={"PATH": os.defpath, "LC_ALL": "C"},
    )
    assert result.returncode == 0, result.stderr
