from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.core.vocab import ALLOWED_ITOT_BOUNDARIES, ALLOWED_STATUSES

RISK_ID_PATTERN = r"^EG-R-\d{4,}$"


def _validate_status(v: Optional[str]) -> Optional[str]:
    if v is not None and v not in ALLOWED_STATUSES:
        raise ValueError(f"status must be one of {sorted(ALLOWED_STATUSES)}")
    return v


class RiskCard(BaseModel):
    risk_name: str
    description: str
    ai_model_type: List[str] = Field(default_factory=list)
    probability_level: int = Field(..., ge=1, le=5)
    impact_level: int = Field(..., ge=1, le=5)
    impact_dimensions: List[str] = Field(default_factory=list)
    trigger_conditions: str
    technological_dependencies: List[str] = Field(default_factory=list)
    known_mitigations: List[str] = Field(default_factory=list)
    regulatory_requirements: List[str] = Field(default_factory=list)
    operational_priority: int = Field(..., ge=1, le=5)
    source_reference: List[str] = Field(default_factory=list)
    provenance: List[Dict[str, Any]] = Field(default_factory=list)
    related_risks: List[str] = Field(default_factory=list)
    categories: List[str] = Field(default_factory=list)
    energy_context: List[str] = Field(default_factory=list)
    altai_requirements: List[str] = Field(default_factory=list)
    version: str
    stable_id: Optional[str] = None
    merge_hash: Optional[str] = None
    lifecycle_stage: Optional[str] = None
    risk_summary: Optional[str] = None
    it_ot_boundary: Optional[str] = None

    @field_validator("it_ot_boundary")
    @classmethod
    def validate_itot_boundary(cls, v: Optional[str]) -> Optional[str]:
        if v is not None and v not in ALLOWED_ITOT_BOUNDARIES:
            raise ValueError(f"it_ot_boundary must be one of {sorted(ALLOWED_ITOT_BOUNDARIES)}")
        return v

    @model_validator(mode="after")
    def set_stable_id(self) -> "RiskCard":
        if not self.stable_id:
            self.stable_id = self.risk_name.strip()
        return self

    model_config = ConfigDict(extra="ignore")


class RiskBase(BaseModel):
    risk_id: str = Field(..., pattern=RISK_ID_PATTERN)
    status: Optional[str] = None
    version: Optional[str] = None
    card: RiskCard

    _validate_status = field_validator("status")(_validate_status)

    @model_validator(mode="after")
    def align_stable_id(self) -> "RiskBase":
        if self.card:
            self.card.stable_id = self.risk_id
        return self


class RiskCreate(RiskBase):
    pass


class RiskUpdate(BaseModel):
    status: Optional[str] = None
    version: Optional[str] = None
    card: Optional[RiskCard] = None

    _validate_status = field_validator("status")(_validate_status)


class RiskPatch(BaseModel):
    status: Optional[str]
    version: Optional[str]
    card_updates: Optional[Dict[str, Any]]

    _validate_status = field_validator("status")(_validate_status)

    @field_validator("card_updates")
    def ensure_updates(cls, v: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        return v


class RiskResponse(BaseModel):
    risk_id: str
    status: Optional[str]
    version: Optional[str]
    card: RiskCard
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class RiskBrief(BaseModel):
    risk_id: str
    risk_name: str
    impact_level: int
    impact_dimensions: List[str]
