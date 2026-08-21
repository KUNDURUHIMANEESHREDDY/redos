from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from engine.model.plan import ReplayManifest
from engine.orchestration import AttackOrchestrator, RegressionCase, compare_regression, replay_attack
from engine.orchestration.replay import RegressionCase as _RegressionCase  # noqa: F401  (re-export for typing)


@dataclass(frozen=True, slots=True)
class RegressionTrend:
    """Change in regression status between two assessment points.

    - ``introduced``: keys absent before, now carrying a regression state.
    - ``regressed``: keys present and clean before, now carrying a
      regression state.
    - ``resolved``: keys with a regression state before, now clean or absent.
    - ``persisted``: keys with a regression state at both points.
    """

    introduced: tuple[str, ...]
    regressed: tuple[str, ...]
    resolved: tuple[str, ...]
    persisted: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "introduced": list(self.introduced),
            "regressed": list(self.regressed),
            "resolved": list(self.resolved),
            "persisted": list(self.persisted),
        }


class RegressionIntelligence:
    """Tracks replay baselines per (target, plugin) and reports regressions.

    This layer does not re-implement replay: it manages a registry of
    `RegressionCase` baselines and delegates verification to
    `engine.orchestration.replay` (`replay_attack` + `compare_regression`).
    """

    def __init__(self) -> None:
        self._baselines: dict[tuple[str, str], RegressionCase] = {}

    def register_baseline(self, case: RegressionCase) -> None:
        self._baselines[(case.manifest.definition["target"]["target_id"], case.manifest.definition["plugin"])] = case

    def register_manifest_baseline(
        self, target_id: str, plugin: str, manifest: ReplayManifest, result: Any
    ) -> RegressionCase:
        from engine.orchestration import make_regression_case

        case = make_regression_case(f"{target_id}:{plugin}", manifest, result)
        self._baselines[(target_id, plugin)] = case
        return case

    def baseline(self, target_id: str, plugin: str) -> RegressionCase | None:
        return self._baselines.get((target_id, plugin))

    async def evaluate(
        self,
        target_id: str,
        plugin: str,
        result: Any,
        *,
        orchestrator: AttackOrchestrator | None = None,
    ) -> list[str]:
        """Replay the baseline for (target, plugin) and compare it with the
        given result. Returns a list of differences (empty = no regression).
        Raises KeyError when no baseline exists for the pair.
        """
        case = self._baselines[(target_id, plugin)]
        if orchestrator is None:
            orchestrator = AttackOrchestrator()
        replayed = await replay_attack(case.manifest, orchestrator)
        return compare_regression(case, replayed)

    def trend(self, previous: dict[tuple[str, str], str], current: dict[tuple[str, str], str]) -> RegressionTrend:
        """Classify (target, plugin) regression states between two points.

        State is whatever the caller recorded (e.g. the diff list from
        `evaluate`); an empty value means "no regression". Keys present only
        in `current` with a regression state are `introduced`; keys present
        only in `previous` are `resolved`; keys in both are `persisted` if
        both record a regression.
        """
        introduced = sorted(
            key for key, state in current.items() if key not in previous and state
        )
        regressed = sorted(
            key for key, state in current.items()
            if key in previous and not previous[key] and state
        )
        resolved = sorted(
            key
            for key, state in previous.items()
            if state and (key not in current or not current[key])
        )
        persisted = sorted(
            key for key, state in current.items()
            if key in previous and previous[key] and state
        )
        return RegressionTrend(
            introduced=tuple(introduced),
            regressed=tuple(regressed),
            resolved=tuple(resolved),
            persisted=tuple(persisted),
        )