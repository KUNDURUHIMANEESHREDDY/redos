from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from engine.campaigns.campaign import Campaign


@dataclass(slots=True)
class CampaignEvidenceAggregator:
    def aggregate(self, campaign: Campaign) -> dict[str, Any]:
        steps = [step.to_dict() for step in campaign.steps]
        findings = []
        if campaign.evidence:
            findings = list(campaign.evidence.get("findings") or [])
        return {
            "campaign_id": campaign.config.campaign_id,
            "name": campaign.config.name,
            "strategy": campaign.config.strategy,
            "seed": campaign.config.seed,
            "status": campaign.status.value,
            "started_at": campaign.started_at.isoformat() if campaign.started_at else None,
            "finished_at": campaign.finished_at.isoformat() if campaign.finished_at else None,
            "stopped_reason": campaign.stopped_reason,
            "steps": steps,
            "turns_used": campaign.turns_used(),
            "estimated_cost": campaign.estimated_cost(),
            "replay_hash": campaign.config.replay_hash(),
            **({} if not campaign.evidence else dict(campaign.evidence)),
        }