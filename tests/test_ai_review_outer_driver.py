from __future__ import annotations

import hashlib
import json
import os
import subprocess
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from tools.ai_review.attestation import AttestationStatement
from tools.ai_review.attestation import canonical_sha256
from tools.ai_review.attestation import public_key_id
from tools.ai_review.models import AcceptanceTest
from tools.ai_review.models import CandidateCommitPolicy
from tools.ai_review.models import DiffLimits
from tools.ai_review.models import Requirement
from tools.ai_review.models import ReviewPromptDigests
from tools.ai_review.models import TaskSpec
from tools.ai_review.outer_driver import OuterWorkflowDriver
from tools.ai_review.outer_driver import _freeze_output_tree
from tools.ai_review.phase_adapters import PhaseAdapters
from tools.ai_review.phase_protocol import PHASE_ORDER
from tools.ai_review.phase_protocol import CoordinatorPhaseOutput
from tools.ai_review.phase_protocol import EMPTY_INITIAL_ARTIFACTS_SHA256
from tools.ai_review.phase_protocol import PhaseAction
from tools.ai_review.phase_protocol import PhaseOutputArtifact
from tools.ai_review.phase_protocol import PhaseRequest
from tools.ai_review.phase_protocol import PhaseProtocolError
from tools.ai_review.phase_protocol import SqlitePhaseLedger
from tools.ai_review.phase_protocol import canonical_json_bytes
from tools.ai_review.policy import inspect_git_diff


def _other_uid() -> int:
    return 65_534 if os.geteuid() != 65_534 else 65_533


def _git(repo: Path, *arguments: str, env: dict[str, str] | None = None) -> str:
    result = subprocess.run(
        ["git", *arguments],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
        env={**os.environ, **(env or {})},
    )
    return result.stdout.strip()


def _freeze_tree(root: Path) -> None:
    for directory, directories, files in os.walk(root, topdown=False):
        directory_path = Path(directory)
        for name in files:
            path = directory_path / name
            path.chmod(0o555 if path.stat().st_mode & 0o111 else 0o444)
        for name in directories:
            (directory_path / name).chmod(0o555)
        directory_path.chmod(0o555)


def _artifact(name: str, raw: bytes) -> PhaseOutputArtifact:
    return PhaseOutputArtifact.create(name, raw)


def _review_packet_bytes(value: str = "packet") -> bytes:
    body = {"value": value}
    digest = hashlib.sha256(
        json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return (
        json.dumps(
            {**body, "packet_sha256": digest},
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode()


@pytest.mark.parametrize("entry_kind", ["symlink", "hardlink"])
def test_freeze_output_rejects_links_before_changing_external_inode(
    tmp_path: Path,
    entry_kind: str,
) -> None:
    output = tmp_path / "output"
    output.mkdir(mode=0o700)
    victim = tmp_path / "victim"
    victim.write_bytes(b"secret\n")
    victim.chmod(0o600)
    if entry_kind == "symlink":
        output.joinpath("escape").symlink_to(victim)
    else:
        os.link(victim, output / "escape")
    with pytest.raises(PhaseProtocolError, match="symlinks, hardlinks"):
        _freeze_output_tree(output)
    assert victim.stat().st_mode & 0o777 == 0o600


def test_outer_driver_reaches_real_snapshots_signing_and_final_judge_adapter(
    tmp_path: Path,
) -> None:
    source = tmp_path / "candidate-source"
    worktree = source / "worktree"
    source.mkdir(mode=0o700)
    worktree.mkdir(mode=0o700)
    _git(worktree, "init", "-q")
    _git(worktree, "config", "user.name", "AI Harness")
    _git(worktree, "config", "user.email", "harness@example.invalid")
    (worktree / "tests").mkdir()
    (worktree / "app.py").write_text("VALUE = 1\n", encoding="utf-8")
    (worktree / "tests" / "test_feature.py").write_text(
        "def test_value():\n    assert 1 == 1\n",
        encoding="utf-8",
    )
    _git(worktree, "add", ".")
    commit_env = {
        "GIT_AUTHOR_DATE": "2000-01-01T00:00:00+00:00",
        "GIT_COMMITTER_DATE": "2000-01-01T00:00:00+00:00",
    }
    _git(worktree, "commit", "-q", "-m", "base", env=commit_env)
    base_sha = _git(worktree, "rev-parse", "HEAD")
    (worktree / "app.py").write_text("VALUE = 2\n", encoding="utf-8")
    (worktree / "tests" / "test_feature.py").write_text(
        "def test_value():\n    assert 2 == 2\n",
        encoding="utf-8",
    )
    _git(worktree, "add", ".")
    _git(worktree, "commit", "-q", "-m", "candidate", env=commit_env)
    candidate_sha = _git(worktree, "rev-parse", "HEAD")
    bare = source / "candidate.git"
    _git(source, "clone", "-q", "--bare", "--no-hardlinks", str(worktree), str(bare))

    task_sha = "1" * 64
    task = TaskSpec(
        schema_version="2.0",
        task_id="TASK-OUTER",
        base_sha=base_sha,
        trusted_harness_sha256="2" * 64,
        objective="exercise the complete phase driver",
        requirements=[Requirement(id="REQ-1", text="preserve bindings")],
        review_prompts=ReviewPromptDigests(
            reviewer_sha256="3" * 64,
            adversary_sha256="4" * 64,
        ),
        candidate_commit=CandidateCommitPolicy(
            message="candidate",
            author_name="AI Harness",
            author_email="harness@example.invalid",
            timestamp=946684800,
            timezone="+0000",
        ),
        acceptance_tests=[
            AcceptanceTest(
                id="AT-TEST",
                kind="test",
                command=["python", "-m", "pytest", "-q"],
                expected_red_exit_codes=[1],
                expected_red_fingerprint_sha256="5" * 64,
                test_paths=["tests/test_feature.py"],
            )
        ],
        allowed_paths=["app.py", "tests/**"],
        denied_paths=[".env*", "cache/**"],
        limits=DiffLimits(max_changed_files=10, max_added_lines=100),
        network_policy="deny",
    )
    policy = inspect_git_diff(worktree, task, task_sha256=task_sha, head="HEAD")
    assert policy.passed and policy.patch_sha256 is not None
    _freeze_tree(source)

    private_key = Ed25519PrivateKey.generate()
    private_path = tmp_path / "coordinator-private.pem"
    private_path.write_bytes(
        private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    private_path.chmod(0o400)
    public_pem = private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    initial_input = tmp_path / "initial-input"
    initial_input.mkdir(mode=0o555)
    ledger_root = tmp_path / "ledger"
    ledger_root.mkdir(mode=0o700)
    output_root = tmp_path / "phase-outputs"
    output_root.mkdir(mode=0o700)
    ledger = SqlitePhaseLedger(ledger_root / "phases.sqlite3", candidate_uid=_other_uid())
    driver = OuterWorkflowDriver(
        ledger=ledger,
        output_root=output_root,
        candidate_uid=_other_uid(),
    )
    public_adapters = PhaseAdapters.from_public_apis()

    state: dict[str, object] = {"policy": policy}
    previous = None
    artifact_input = initial_input
    reached_judge = False

    def make_request(phase: str) -> PhaseRequest:
        index = PHASE_ORDER.index(phase)
        return PhaseRequest.create(
            workflow_id="a" * 64,
            phase=phase,
            sequence=index + 1,
            previous_phase_sha256=None if previous is None else previous.phase_sha256,
            task_sha256=task_sha,
            runtime_manifest_sha256="6" * 64,
            coordinator_key_id=public_key_id(private_key.public_key()),
            coordinator_public_key_sha256=hashlib.sha256(public_pem).hexdigest(),
            candidate_sha256=policy.patch_sha256,
            candidate_snapshot_sha256=(
                None if previous is None else previous.candidate_snapshot_sha256
            ),
            review_packet_sha256=(
                previous.review_packet_sha256 if index >= PHASE_ORDER.index("broker") else None
            ),
            input_artifacts_sha256=(
                EMPTY_INITIAL_ARTIFACTS_SHA256
                if previous is None
                else previous.output_artifacts_sha256
            ),
        )

    def coordinator_prepare(
        request: PhaseRequest,
        *,
        artifact_input_root: Path,
        phase_output_root: Path,
        candidate_repo: Path | None,
        signing_key: Path | None,
    ):
        nonlocal reached_judge
        del artifact_input_root
        phase = request.phase
        state["current_request"] = request
        if phase == "snapshot":
            assert candidate_repo == source and signing_key is None
            measured_policy = inspect_git_diff(
                candidate_repo / "worktree",
                task,
                task_sha256=task_sha,
                head="HEAD",
                expected_patch_sha256=policy.patch_sha256,
            )
            assert measured_policy == policy
            base = public_adapters.invoke_coordinator(
                "snapshot",
                source_repo=candidate_repo / "candidate.git",
                commit_sha=base_sha,
                destination_root=phase_output_root,
                candidate_uid=_other_uid(),
            )
            candidate = public_adapters.invoke_coordinator(
                "snapshot",
                source_repo=candidate_repo / "candidate.git",
                commit_sha=candidate_sha,
                destination_root=phase_output_root,
                candidate_uid=_other_uid(),
            )
            state.update(base=base, candidate=candidate)
            payload = json.dumps(
                {"base": base.snapshot_sha256, "candidate": candidate.snapshot_sha256},
                sort_keys=True,
            ).encode()
        elif phase == "red-snapshot":
            assert candidate_repo is None and signing_key is None
            red = public_adapters.invoke_coordinator(
                "red-snapshot",
                base_snapshot=state["base"],
                candidate_snapshot=state["candidate"],
                test_paths=("tests/test_feature.py",),
                destination_root=phase_output_root,
                candidate_uid=_other_uid(),
            )
            state["red"] = red
            payload = red.snapshot.snapshot_sha256.encode()
        elif phase == "sign":
            assert candidate_repo is None and signing_key == private_path
            loaded = serialization.load_pem_private_key(signing_key.read_bytes(), password=None)
            assert isinstance(loaded, Ed25519PrivateKey)
            signed = []
            sign_sources = tuple(
                _artifact(name, name.encode())
                for name in (
                    "task",
                    "policy",
                    "gate:AT-TEST",
                    "tdd-red:AT-TEST",
                    "tdd-green:AT-TEST",
                    "reviewer",
                    "adversary",
                )
            )
            for artifact in sign_sources:
                artifact_type = (
                    "task"
                    if artifact.name == "task"
                    else "policy"
                    if artifact.name == "policy"
                    else "gate"
                    if artifact.name.startswith("gate:")
                    else "tdd-red"
                    if artifact.name.startswith("tdd-red:")
                    else "tdd-green"
                    if artifact.name.startswith("tdd-green:")
                    else "review"
                )
                statement = AttestationStatement(
                    artifact_type=artifact_type,
                    artifact_sha256=artifact.semantic_sha256(),
                    task_id=task.task_id,
                    task_sha256=task_sha,
                    base_sha=base_sha,
                    head_sha=candidate_sha,
                    candidate_sha256=policy.patch_sha256,
                    snapshot_sha256=state["candidate"].snapshot_sha256,
                    runtime_manifest_sha256=request.runtime_manifest_sha256,
                    runner_image_digest="sha256:" + "7" * 64,
                    runner_sha256="8" * 64,
                    argv_sha256="9" * 64,
                    log_sha256="b" * 64,
                    role=artifact.name,
                    session_id="session-" + hashlib.sha256(artifact.name.encode()).hexdigest()[:12],
                    request_sha256="c" * 64,
                    response_sha256="d" * 64,
                    nonce=hashlib.sha256(("nonce:" + artifact.name).encode()).hexdigest(),
                    issued_at=946684800,
                )
                signed.append(
                    public_adapters.invoke_coordinator(
                        "sign",
                        statement=statement,
                        private_key=loaded,
                    )
                )
            state["signed"] = signed
            payload = json.dumps(
                [item.model_dump(mode="json") for item in signed],
                sort_keys=True,
            ).encode()
        elif phase == "attested-judge":
            assert candidate_repo is None and signing_key is None
            adapters = PhaseAdapters(
                snapshot=lambda **_kwargs: None,
                red_snapshot=lambda **_kwargs: None,
                offline=lambda **_kwargs: None,
                review_packet=lambda **_kwargs: None,
                broker=lambda **_kwargs: None,
                sign=lambda **_kwargs: None,
                attested_judge=lambda **_kwargs: {"status": "human_review"},
            )
            verdict = adapters.invoke_coordinator("attested-judge")
            reached_judge = True
            payload = json.dumps(verdict, sort_keys=True).encode()
        else:
            assert candidate_repo is None and signing_key is None
            payload = json.dumps({"phase": phase}, sort_keys=True).encode()
        kind = "offline" if phase == "offline" else "broker" if phase == "broker" else "none"
        return (
            PhaseAction.create(
                request=request,
                external_kind=kind,
                payload_sha256=hashlib.sha256(payload).hexdigest(),
            ),
            payload,
        )

    def coordinator_finalize(action: PhaseAction, evidence: bytes, **kwargs) -> bytes:
        assert kwargs["candidate_repo"] is None or action.phase == "snapshot"
        assert kwargs["signing_key"] is None or action.phase == "sign"
        del evidence
        request = state["current_request"]
        assert isinstance(request, PhaseRequest)
        return canonical_json_bytes(
            CoordinatorPhaseOutput.create(
                request=request,
                artifacts=_phase_artifacts(request.phase, state),
            )
        )

    def _phase_artifacts(
        phase: str,
        values: dict[str, object],
    ) -> tuple[PhaseOutputArtifact, ...]:
        if phase == "snapshot":
            entries = (
                _artifact("policy", canonical_sha256(values["policy"]).encode()),
                _artifact("base-snapshot", values["base"].snapshot_sha256.encode()),
                _artifact("candidate-snapshot", values["candidate"].snapshot_sha256.encode()),
            )
        elif phase == "red-snapshot":
            entries = (
                _artifact("red-snapshot:AT-TEST", values["red"].snapshot.snapshot_sha256.encode()),
            )
        elif phase == "offline":
            entries = tuple(
                _artifact(name, name.encode())
                for name in ("gate:AT-TEST", "tdd-red:AT-TEST", "tdd-green:AT-TEST")
            )
        elif phase == "review-packet":
            entries = (_artifact("review-packet", _review_packet_bytes()),)
        elif phase == "broker":
            entries = (_artifact("reviewer", b"reviewer"), _artifact("adversary", b"adversary"))
        elif phase == "sign":
            entries = tuple(
                _artifact(item.statement.role, canonical_json_bytes(item))
                for item in values["signed"]
            )
        else:
            entries = (_artifact("verdict", b"human_review"),)
        return tuple(sorted(entries, key=lambda item: item.name))

    for phase in PHASE_ORDER:
        request = make_request(phase)
        result, phase_output = driver.run_phase(
            request,
            artifact_input_root=artifact_input,
            coordinator_prepare=coordinator_prepare,
            coordinator_finalize=coordinator_finalize,
            offline_execute=lambda _action, payload: b"offline-evidence:" + payload,
            broker_execute=lambda _action, payload: b"broker-evidence:" + payload,
            candidate_repo=source if phase == "snapshot" else None,
            signing_key=private_path if phase == "sign" else None,
        )
        previous = result
        artifact_input = phase_output

    assert reached_judge is True
    assert previous is not None and previous.request.phase == "attested-judge"
    assert state["red"].snapshot.snapshot_sha256 not in {
        state["base"].snapshot_sha256,
        state["candidate"].snapshot_sha256,
    }
    assert len(state["signed"]) == 7
    assert all(not path.stat().st_mode & 0o222 for path in output_root.rglob("*"))
    final_tree = output_root / "07-attested-judge"
    assert len(list(final_tree.rglob("phase-result.json"))) == len(PHASE_ORDER)
    assert any(
        path.parent.name == state["candidate"].snapshot_sha256
        for path in final_tree.rglob("manifest.json")
    )


def test_outer_driver_reaches_actual_attested_judge_with_raw_offline_and_broker_evidence(
    tmp_path: Path,
) -> None:
    from test_ai_review_attested_judge import NOW
    from test_ai_review_attested_judge import TASK_SHA
    from test_ai_review_attested_judge import make_strict_bundle
    from test_ai_review_attested_judge import sign_strict_bundle
    from tools.ai_review.attestation import InMemoryNonceLedger
    from tools.ai_review.review_packet import canonical_packet_bytes

    fixture_root = tmp_path / "strict-fixture"
    fixture_root.mkdir(mode=0o700)
    strict = make_strict_bundle(fixture_root)
    bundle = strict.bundle
    adapters = PhaseAdapters.from_public_apis()
    private_key = Ed25519PrivateKey.generate()
    private_path = tmp_path / "strict-private.pem"
    private_path.write_bytes(
        private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    private_path.chmod(0o400)
    public_pem = private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    initial = tmp_path / "strict-initial"
    initial.mkdir(mode=0o555)
    ledger_root = tmp_path / "strict-ledger"
    ledger_root.mkdir(mode=0o700)
    output_root = tmp_path / "strict-output"
    output_root.mkdir(mode=0o700)
    driver = OuterWorkflowDriver(
        ledger=SqlitePhaseLedger(
            ledger_root / "phases.sqlite3",
            candidate_uid=strict.candidate_uid,
        ),
        output_root=output_root,
        candidate_uid=strict.candidate_uid,
    )
    state: dict[str, object] = {}
    previous = None
    artifact_input = initial

    def request_for_phase(phase: str) -> PhaseRequest:
        index = PHASE_ORDER.index(phase)
        return PhaseRequest.create(
            workflow_id="f" * 64,
            phase=phase,
            sequence=index + 1,
            previous_phase_sha256=None if previous is None else previous.phase_sha256,
            task_sha256=TASK_SHA,
            runtime_manifest_sha256=bundle.context.runtime_manifest_sha256,
            coordinator_key_id=public_key_id(private_key.public_key()),
            coordinator_public_key_sha256=hashlib.sha256(public_pem).hexdigest(),
            candidate_sha256=bundle.policy.patch_sha256,
            candidate_snapshot_sha256=(
                None if previous is None else previous.candidate_snapshot_sha256
            ),
            review_packet_sha256=(
                previous.review_packet_sha256 if index >= PHASE_ORDER.index("broker") else None
            ),
            input_artifacts_sha256=(
                EMPTY_INITIAL_ARTIFACTS_SHA256
                if previous is None
                else previous.output_artifacts_sha256
            ),
        )

    def offline_summary(run: object) -> dict[str, object]:
        return {
            "acceptance_test_id": run.request.acceptance_test_id,
            "log_sha256": run.log_sha256,
            "phase": run.request.phase,
            "request_sha256": run.request_sha256,
            "response_sha256": run.response_sha256,
            "runtime_security_sha256": run.runtime_security_sha256,
        }

    def broker_summary(run: object) -> dict[str, object]:
        execution = run.execution
        return {
            "attempt": execution.attempt,
            "evidence_sha256": run.evidence_sha256,
            "ledger_identity_sha256": execution.broker_ledger_identity_sha256,
            "request_sha256": execution.request_sha256,
            "response_sha256": execution.response_sha256,
            "role": execution.role,
        }

    def phase_artifacts(phase: str) -> tuple[PhaseOutputArtifact, ...]:
        if phase == "snapshot":
            values = (
                _artifact("base-snapshot", strict.base_snapshot.snapshot_sha256.encode()),
                _artifact(
                    "candidate-snapshot",
                    strict.candidate_snapshot.snapshot_sha256.encode(),
                ),
                _artifact("policy", canonical_json_bytes(bundle.policy)),
            )
        elif phase == "red-snapshot":
            values = tuple(
                _artifact(
                    "red-snapshot:" + tdd.acceptance_test_id,
                    item.snapshot.snapshot_sha256.encode(),
                )
                for item, tdd in zip(strict.red_snapshots, bundle.tdds, strict=True)
            )
        elif phase == "offline":
            values = []
            for run in state["raw_offline"]:
                prefix = "gate" if run.request.phase == "gate" else "tdd-" + run.request.phase
                values.append(
                    _artifact(
                        prefix + ":" + run.request.acceptance_test_id,
                        canonical_json_bytes(offline_summary(run)),
                    )
                )
            values = tuple(values)
        elif phase == "review-packet":
            values = (_artifact("review-packet", canonical_packet_bytes(bundle.review_packet)),)
        elif phase == "broker":
            values = tuple(
                _artifact(run.execution.role, canonical_json_bytes(broker_summary(run)))
                for run in state["raw_broker"]
            )
        elif phase == "sign":
            values = tuple(
                _artifact(item.statement.role, canonical_json_bytes(item))
                for item in state["attestations"]
            )
        else:
            values = (_artifact("verdict", canonical_json_bytes(state["verdict"])),)
        return tuple(sorted(values, key=lambda item: item.name))

    def coordinator_prepare(request: PhaseRequest, **handles: object):
        phase = request.phase
        state["request"] = request
        assert (handles["candidate_repo"] is not None) == (phase == "snapshot")
        assert (handles["signing_key"] is not None) == (phase == "sign")
        if phase == "snapshot":
            state["base_snapshot"] = strict.base_snapshot
            state["candidate_snapshot"] = strict.candidate_snapshot
        elif phase == "red-snapshot":
            state["red_snapshots"] = strict.red_snapshots
        elif phase == "review-packet":
            state["review_packet"] = bundle.review_packet
        elif phase == "sign":
            loaded = serialization.load_pem_private_key(
                Path(handles["signing_key"]).read_bytes(),
                password=None,
            )
            assert isinstance(loaded, Ed25519PrivateKey)
            state["loaded_key"] = loaded
            state["attestations"] = sign_strict_bundle(strict, loaded)
        elif phase == "attested-judge":
            attestations = state["attestations"]
            state["verdict"] = adapters.invoke_coordinator(
                "attested-judge",
                bundle.task,
                bundle.policy,
                bundle.reviews,
                bundle.gates,
                bundle.tdds,
                attestations,
                strict.non_offline_bindings,
                bundle.review_packet,
                bundle.broker_evidence,
                bundle.broker_requests,
                bundle.broker_artifacts,
                context=bundle.context,
                task_sha256=TASK_SHA,
                trusted_public_keys={attestations[0].key_id: state["loaded_key"].public_key()},
                nonce_ledger=InMemoryNonceLedger(),
                now=NOW,
                **strict.strict_kwargs,
            )
        payload = canonical_json_bytes({"phase": phase, "request_sha256": request.request_sha256})
        kind = "offline" if phase == "offline" else "broker" if phase == "broker" else "none"
        return (
            PhaseAction.create(
                request=request,
                external_kind=kind,
                payload_sha256=hashlib.sha256(payload).hexdigest(),
            ),
            payload,
        )

    def offline_execute(_action: PhaseAction, _payload: bytes) -> bytes:
        state["raw_offline"] = strict.raw_offline_runs
        return canonical_json_bytes([offline_summary(run) for run in strict.raw_offline_runs])

    def broker_execute(_action: PhaseAction, _payload: bytes) -> bytes:
        state["raw_broker"] = strict.provisioned_broker_executions
        return canonical_json_bytes(
            [broker_summary(run) for run in strict.provisioned_broker_executions]
        )

    def coordinator_finalize(_action: PhaseAction, _evidence: bytes, **_handles: object) -> bytes:
        request = state["request"]
        assert isinstance(request, PhaseRequest)
        return canonical_json_bytes(
            CoordinatorPhaseOutput.create(
                request=request,
                artifacts=phase_artifacts(request.phase),
            )
        )

    for phase in PHASE_ORDER:
        request = request_for_phase(phase)
        previous, artifact_input = driver.run_phase(
            request,
            artifact_input_root=artifact_input,
            coordinator_prepare=coordinator_prepare,
            coordinator_finalize=coordinator_finalize,
            offline_execute=offline_execute,
            broker_execute=broker_execute,
            candidate_repo=(fixture_root / "candidate-repository" if phase == "snapshot" else None),
            signing_key=private_path if phase == "sign" else None,
        )

    verdict = state["verdict"]
    assert verdict.status == "pass"
    assert verdict.human_approval_required is True
    assert previous.request.phase == "attested-judge"
    assert len(state["raw_broker"]) == 2
