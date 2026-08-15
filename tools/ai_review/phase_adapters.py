"""Narrow adapters from the phase protocol to the existing audited public APIs.

Keeping these imports and calls in one module prevents orchestration code from duplicating the
evidence logic owned by snapshot, offline_runner, review_packet, broker_executor, attestation,
and attested_judge.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from tools.ai_review.attestation import sign_attestation
from tools.ai_review.attested_judge import judge_attested
from tools.ai_review.broker_outer_executor import execute_prepared_broker_outer
from tools.ai_review.offline_runner import execute_offline
from tools.ai_review.phase_protocol import EXTERNAL_PHASES
from tools.ai_review.phase_protocol import PHASE_ORDER
from tools.ai_review.phase_protocol import PhaseName
from tools.ai_review.review_packet import build_review_packet_from_snapshots
from tools.ai_review.snapshot import create_readonly_snapshot
from tools.ai_review.snapshot import create_red_tdd_snapshot


class PhaseAdapterError(RuntimeError):
    """Raised before a phase crosses the wrong process or mount boundary."""


PhaseCallable = Callable[..., object]


@dataclass(frozen=True)
class PhaseAdapters:
    """Closed adapter registry; no dynamic names or candidate-supplied callables."""

    snapshot: PhaseCallable
    red_snapshot: PhaseCallable
    offline: PhaseCallable
    review_packet: PhaseCallable
    broker: PhaseCallable
    sign: PhaseCallable
    attested_judge: PhaseCallable

    @classmethod
    def from_public_apis(cls) -> PhaseAdapters:
        return cls(
            snapshot=create_readonly_snapshot,
            red_snapshot=create_red_tdd_snapshot,
            offline=execute_offline,
            review_packet=build_review_packet_from_snapshots,
            broker=execute_prepared_broker_outer,
            sign=sign_attestation,
            attested_judge=judge_attested,
        )

    @staticmethod
    def names() -> tuple[PhaseName, ...]:
        return PHASE_ORDER

    @staticmethod
    def execution_domain(phase: PhaseName) -> str:
        if phase not in PHASE_ORDER:
            raise PhaseAdapterError("unknown production phase")
        return "outer" if phase in EXTERNAL_PHASES else "coordinator"

    def _adapter(self, phase: PhaseName) -> PhaseCallable:
        names: dict[PhaseName, str] = {
            "snapshot": "snapshot",
            "red-snapshot": "red_snapshot",
            "offline": "offline",
            "review-packet": "review_packet",
            "broker": "broker",
            "sign": "sign",
            "attested-judge": "attested_judge",
        }
        try:
            return getattr(self, names[phase])
        except (KeyError, AttributeError) as exc:
            raise PhaseAdapterError("unknown production phase") from exc

    def invoke_coordinator(
        self,
        phase: PhaseName,
        /,
        *args: object,
        **kwargs: object,
    ) -> object:
        if self.execution_domain(phase) == "outer":
            raise PhaseAdapterError(f"{phase} is outer-only and cannot run in the coordinator")
        return self._adapter(phase)(*args, **kwargs)

    def invoke_outer(
        self,
        phase: PhaseName,
        /,
        *args: object,
        **kwargs: object,
    ) -> object:
        if self.execution_domain(phase) == "coordinator":
            raise PhaseAdapterError(f"{phase} is coordinator-only")
        if phase == "broker":
            forbidden = {
                "artifact_root",
                "candidate",
                "candidate_path",
                "candidate_repo",
                "candidate_snapshot",
                "candidate_snapshot_root",
                "cwd",
                "mount",
                "mounts",
                "snapshot_root",
                "workspace",
            }
            if forbidden & set(kwargs):
                raise PhaseAdapterError(
                    "broker adapter must not receive a candidate filesystem or mount parameter"
                )
        return self._adapter(phase)(*args, **kwargs)
