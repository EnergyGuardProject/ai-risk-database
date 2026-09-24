import re
from typing import Optional

from pydantic import BaseModel, ConfigDict, field_validator

from app.core.vocab import ALLOWED_RELATIONSHIP_TYPES, UC_ID_PATTERN


class RiskRelationshipCreate(BaseModel):
    target_risk_id: str
    relationship_type: str
    notes: Optional[str] = None

    @field_validator("relationship_type")
    @classmethod
    def validate_relationship_type(cls, v: str) -> str:
        if v not in ALLOWED_RELATIONSHIP_TYPES:
            raise ValueError(f"relationship_type must be one of {sorted(ALLOWED_RELATIONSHIP_TYPES)}")
        return v


class RiskRelationshipResponse(BaseModel):
    source_risk_id: str
    target_risk_id: str
    relationship_type: str
    notes: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)


class RiskUseCaseCreate(BaseModel):
    uc_id: str
    source_project: Optional[str] = None
    notes: Optional[str] = None

    @field_validator("uc_id")
    @classmethod
    def validate_uc_id(cls, v: str) -> str:
        if not re.match(UC_ID_PATTERN, v):
            raise ValueError(f"uc_id must match pattern {UC_ID_PATTERN} (e.g. UC-EG-1, UC-AG-2, UC-ET-S-18)")
        return v


class RiskUseCaseResponse(BaseModel):
    risk_id: str
    uc_id: str
    source_project: Optional[str] = None
    notes: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)
