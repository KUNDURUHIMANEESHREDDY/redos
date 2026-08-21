from datetime import datetime
from typing import Any, Optional
from uuid import UUID, uuid4
from pydantic import BaseModel, Field, ConfigDict


class RemediationAction(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="forbid")

    action_id: UUID = Field(default_factory=uuid4)
    finding_id: UUID
    title: str
    description: str
    priority: int = 1
    effort: str = "medium"
    category: str = "code_change"
    references: list[str] = Field(default_factory=list)
    verification_steps: list[str] = Field(default_factory=list)
    status: str = "pending"  # pending, in_progress, completed, verified
    assigned_to: Optional[str] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    completed_at: Optional[datetime] = None


class RemediationTemplate(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="forbid")

    template_id: UUID = Field(default_factory=uuid4)
    vulnerability_type: str
    title: str
    description: str
    default_actions: list[RemediationAction] = Field(default_factory=list)
    code_examples: dict[str, str] = Field(default_factory=dict)
    references: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)