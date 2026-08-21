from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from engine.campaigns.campaign import Campaign, CampaignBudget, CampaignConfig
from engine.model.errors import ReplayMismatch
from engine.orchestration.replay import _rebuild_target


@dataclass(frozen=True, slots=True)
class CampaignManifest:
    campaign_replay_hash: str
    config: dict[str, Any]
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> dict[str, Any]:
        return {
            "campaign_replay_hash": self.campaign_replay_hash,
            "config": dict(self.config),
            "created_at": self.created_at.isoformat(),
        }


def build_campaign_manifest(config: CampaignConfig) -> CampaignManifest:
    return CampaignManifest(
        campaign_replay_hash=config.replay_hash(),
        config={
            "campaign_id": config.campaign_id,
            "name": config.name,
            "strategy": config.strategy,
            "seed": config.seed,
            "budget": config.budget.to_dict(),
            "plugin_filter": list(config.plugin_filter),
            "target": config.target.to_dict(),
        },
    )


def config_from_manifest(manifest: CampaignManifest) -> CampaignConfig:
    data = dict(manifest.config)
    budget_data = data.get("budget") or {}
    return CampaignConfig(
        campaign_id=str(data["campaign_id"]),
        name=str(data["name"]),
        target=_rebuild_target(data["target"]),
        strategy=str(data.get("strategy", "observation_driven")),
        seed=int(data.get("seed", 0)),
        budget=CampaignBudget(
            max_attacks=int(budget_data.get("max_attacks", 10)),
            max_duration_s=float(budget_data.get("max_duration_s", 300.0)),
            max_turns_total=budget_data.get("max_turns_total"),
            cost_per_turn=float(budget_data.get("cost_per_turn", 0.0)),
            max_cost=budget_data.get("max_cost"),
        ),
        plugin_filter=tuple(data.get("plugin_filter") or ()),
    )


def verify_campaign_manifest(config: CampaignConfig, manifest: CampaignManifest) -> None:
    if config.replay_hash() != manifest.campaign_replay_hash:
        raise ReplayMismatch(
            f"campaign replay hash {config.replay_hash()} does not match manifest {manifest.campaign_replay_hash}"
        )


async def replay_campaign(manifest: CampaignManifest, runner: Any, gateway: Any = None) -> Campaign:
    config = config_from_manifest(manifest)
    verify_campaign_manifest(config, manifest)
    campaign = Campaign(config=config)
    return await runner.run(campaign, gateway=gateway)