from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from engine.fleet.change import ChangeReport, TargetSnapshot
from engine.fleet.posture import PostureEngine


@dataclass(frozen=True, slots=True)
class TwinPrediction:
    """A simulated posture after applying a hypothetical change.

    Predictions are explicitly labeled `simulated`: they are computed by
    re-scoring the twin's own snapshot data and never claim to be measured.
    """

    target_id: str
    simulated_posture: float
    simulated_delta: float
    scenario: str
    simulated: bool = True
    predicted_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> dict[str, Any]:
        return {
            "target_id": self.target_id,
            "simulated_posture": self.simulated_posture,
            "simulated_delta": self.simulated_delta,
            "scenario": self.scenario,
            "predicted_at": self.predicted_at.isoformat(),
            "simulated": True,
        }


class TargetTwin:
    """A read-only mirror of the last known state of one target.

    The twin holds the latest `TargetSnapshot` and the set of finding
    records for the target. `predict` applies a hypothetical change to the
    mirrored data and re-scores posture; the result is a simulation, not a
    measurement.
    """

    def __init__(self, target_id: str, posture_engine: PostureEngine | None = None) -> None:
        self.target_id = target_id
        self._posture = posture_engine or PostureEngine()
        self.snapshot: TargetSnapshot | None = None
        self.findings: list[Any] = []

    def sync(self, snapshot: TargetSnapshot, findings: list[Any]) -> None:
        if snapshot.target_id != self.target_id:
            raise ValueError(f"twin {self.target_id!r} cannot mirror {snapshot.target_id!r}")
        self.snapshot = snapshot
        self.findings = list(findings)

    def current_posture(self, **factors: Any) -> float:
        if self.snapshot is None:
            raise RuntimeError(f"twin {self.target_id!r} has no snapshot yet")
        return self._posture.score(self.target_id, self.findings, **factors).posture_score

    def predict(self, scenario: str, change: dict[str, Any], **factors: Any) -> TwinPrediction:
        """Simulate a change.

        Supported change keys:
        - ``resolved``: finding ids to remove (e.g. remediation complete)
        - ``added``: finding records to add (e.g. new attack surface)
        """
        if self.snapshot is None:
            raise RuntimeError(f"twin {self.target_id!r} has no snapshot yet")

        removed = set(change.get("resolved") or ())
        simulated = [f for f in self.findings if f.finding_id not in removed]
        simulated.extend(change.get("added") or ())

        current = self.current_posture(**factors)
        predicted = self._posture.score(self.target_id, simulated, **factors).posture_score
        return TwinPrediction(
            target_id=self.target_id,
            simulated_posture=predicted,
            simulated_delta=round(predicted - current, 2),
            scenario=scenario,
        )