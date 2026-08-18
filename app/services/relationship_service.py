from __future__ import annotations

from typing import List

from sqlalchemy import or_, select
from sqlalchemy.exc import NoResultFound
from sqlalchemy.orm import Session

from app.db.models import Risk, RiskRelationship, RiskUseCase
from app.schemas.relationship import RiskRelationshipCreate, RiskUseCaseCreate


class DuplicateRelationshipError(Exception):
    """Raised when a RiskRelationship with the same primary key already exists."""


class DuplicateUseCaseError(Exception):
    """Raised when a RiskUseCase with the same primary key already exists."""


def _ensure_risk_exists(session: Session, risk_id: str) -> None:
    if not session.get(Risk, risk_id):
        raise NoResultFound(f"Risk {risk_id} not found")


def add_relationship(session: Session, risk_id: str, payload: RiskRelationshipCreate) -> RiskRelationship:
    if risk_id == payload.target_risk_id:
        raise ValueError("source_risk_id and target_risk_id must differ")
    _ensure_risk_exists(session, risk_id)
    _ensure_risk_exists(session, payload.target_risk_id)
    existing = session.execute(
        select(RiskRelationship).where(
            RiskRelationship.source_risk_id == risk_id,
            RiskRelationship.target_risk_id == payload.target_risk_id,
            RiskRelationship.relationship_type == payload.relationship_type,
        )
    ).scalar_one_or_none()
    if existing is not None:
        raise DuplicateRelationshipError(
            f"Relationship already exists between {risk_id} and {payload.target_risk_id} "
            f"with type '{payload.relationship_type}'; delete it first or use a different relationship_type."
        )
    relationship = RiskRelationship(
        source_risk_id=risk_id,
        target_risk_id=payload.target_risk_id,
        relationship_type=payload.relationship_type,
        notes=payload.notes,
    )
    session.add(relationship)
    session.flush()
    return relationship


def get_relationships(session: Session, risk_id: str, direction: str = "both") -> List[RiskRelationship]:
    _ensure_risk_exists(session, risk_id)
    if direction == "outgoing":
        condition = RiskRelationship.source_risk_id == risk_id
    elif direction == "incoming":
        condition = RiskRelationship.target_risk_id == risk_id
    elif direction == "both":
        condition = or_(RiskRelationship.source_risk_id == risk_id, RiskRelationship.target_risk_id == risk_id)
    else:
        raise ValueError("direction must be one of 'outgoing', 'incoming', 'both'")
    stmt = select(RiskRelationship).where(condition)
    return list(session.execute(stmt).scalars().all())


def add_use_case(session: Session, risk_id: str, payload: RiskUseCaseCreate) -> RiskUseCase:
    _ensure_risk_exists(session, risk_id)
    existing = session.execute(
        select(RiskUseCase).where(
            RiskUseCase.risk_id == risk_id,
            RiskUseCase.uc_id == payload.uc_id,
        )
    ).scalar_one_or_none()
    if existing is not None:
        raise DuplicateUseCaseError(
            f"Use case '{payload.uc_id}' is already linked to risk {risk_id}; "
            "delete it first if you need to change its notes or source_project."
        )
    use_case = RiskUseCase(
        risk_id=risk_id,
        uc_id=payload.uc_id,
        source_project=payload.source_project,
        notes=payload.notes,
    )
    session.add(use_case)
    session.flush()
    return use_case


def get_use_cases(session: Session, risk_id: str) -> List[RiskUseCase]:
    _ensure_risk_exists(session, risk_id)
    stmt = select(RiskUseCase).where(RiskUseCase.risk_id == risk_id)
    return list(session.execute(stmt).scalars().all())
