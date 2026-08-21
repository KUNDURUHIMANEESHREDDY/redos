from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Mapping

from engine.model.attack import TargetKind


@dataclass(frozen=True, slots=True)
class TargetConfig:
    target_id: str
    kind: TargetKind
    base_url: str
    model: str | None = None
    api_key_ref: str | None = None
    headers: Mapping[str, str] = field(default_factory=dict)
    extra: Mapping[str, Any] = field(default_factory=dict)

    def canonical(self) -> dict[str, Any]:
        return {
            "target_id": self.target_id,
            "kind": self.kind.value,
            "base_url": self.base_url,
            "model": self.model,
            "api_key_ref": self.api_key_ref,
            "headers": dict(self.headers),
            "extra": dict(self.extra),
        }

    def fingerprint(self) -> str:
        material = json.dumps(self.canonical(), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(material.encode("utf-8")).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        return self.canonical()


@dataclass(frozen=True, slots=True)
class RAGTargetConfig(TargetConfig):
    retrieval_url: str | None = None
    retrieval_extra: Mapping[str, Any] = field(default_factory=dict)

    def canonical(self) -> dict[str, Any]:
        base = super().canonical()
        base["retrieval_url"] = self.retrieval_url
        base["retrieval_extra"] = dict(self.retrieval_extra)
        return base