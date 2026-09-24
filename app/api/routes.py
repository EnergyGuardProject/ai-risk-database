from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from fastapi.responses import StreamingResponse
from sqlalchemy.exc import NoResultFound
from sqlalchemy.orm import Session

from app.api.deps import enforce_api_token, get_db
from app.core.config import settings
from app.schemas.relationship import (
    RiskRelationshipCreate,
    RiskRelationshipResponse,
    RiskUseCaseCreate,
    RiskUseCaseResponse,
)
from app.schemas.risk import RiskBrief, RiskCreate, RiskPatch, RiskResponse, RiskUpdate
from app.services import relationship_service, risk_service
from app.services.export_service import export_csv_stream, export_json_bytes

router = APIRouter()


@router.get("/risks", response_model=List[RiskResponse])
def list_risks(
    q: Optional[str] = None,
    min_impact: Optional[int] = Query(default=None, ge=1, le=5),
    limit: int = Query(default=None, gt=0),
    ids: Optional[str] = Query(default=None),
    category: Optional[str] = Query(default=None),
    lifecycle_stage: Optional[str] = Query(default=None),
    altai: Optional[str] = Query(default=None, description="Filter by ALTAI requirement id"),
    db: Session = Depends(get_db),
) -> List[RiskResponse]:
    limit = limit or settings.default_limit
    limit = min(limit, settings.max_limit)
    id_list: Optional[List[str]] = ids.split(",") if ids else None
    return risk_service.get_risks(
        db,
        q=q,
        min_impact=min_impact,
        limit=limit,
        ids=id_list,
        category=category,
        lifecycle_stage=lifecycle_stage,
        altai=altai,
    )


@router.get("/risks/brief", response_model=List[RiskBrief])
def brief_risks(
    ids: Optional[str] = Query(default=None),
    db: Session = Depends(get_db),
) -> List[RiskBrief]:
    id_list = ids.split(",") if ids else None
    return risk_service.get_brief(db, id_list)


@router.get("/risks/{risk_id}", response_model=RiskResponse)
def fetch_risk(risk_id: str, db: Session = Depends(get_db)) -> RiskResponse:
    try:
        return risk_service.get_risk(db, risk_id)
    except NoResultFound as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/risks", response_model=RiskResponse, status_code=201, dependencies=[Depends(enforce_api_token)])
def create_risk(
    payload: RiskCreate,
    db: Session = Depends(get_db),
) -> RiskResponse:
    return risk_service.create_risk(db, payload, editor=settings.provenance_editor)


@router.put("/risks/{risk_id}", response_model=RiskResponse, dependencies=[Depends(enforce_api_token)])
def replace_risk(
    risk_id: str,
    payload: RiskUpdate,
    db: Session = Depends(get_db),
) -> RiskResponse:
    try:
        return risk_service.update_risk(db, risk_id, payload, editor=settings.provenance_editor)
    except NoResultFound as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.patch("/risks/{risk_id}", response_model=RiskResponse, dependencies=[Depends(enforce_api_token)])
def partial_update_risk(
    risk_id: str,
    payload: RiskPatch,
    db: Session = Depends(get_db),
) -> RiskResponse:
    try:
        return risk_service.patch_risk(db, risk_id, payload, editor=settings.provenance_editor)
    except NoResultFound as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.delete("/risks/{risk_id}", status_code=204, dependencies=[Depends(enforce_api_token)])
def remove_risk(risk_id: str, db: Session = Depends(get_db)) -> Response:
    try:
        risk_service.delete_risk(db, risk_id)
        return Response(status_code=204)
    except NoResultFound as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post(
    "/risks/{risk_id}/relationships",
    response_model=RiskRelationshipResponse,
    status_code=201,
    dependencies=[Depends(enforce_api_token)],
)
def add_relationship(
    risk_id: str,
    payload: RiskRelationshipCreate,
    db: Session = Depends(get_db),
) -> RiskRelationshipResponse:
    try:
        return relationship_service.add_relationship(db, risk_id, payload)
    except NoResultFound as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except relationship_service.DuplicateRelationshipError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/risks/{risk_id}/relationships", response_model=List[RiskRelationshipResponse])
def get_relationships(
    risk_id: str,
    direction: str = Query(default="both", description="'outgoing' | 'incoming' | 'both'"),
    db: Session = Depends(get_db),
) -> List[RiskRelationshipResponse]:
    try:
        return relationship_service.get_relationships(db, risk_id, direction=direction)
    except NoResultFound as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post(
    "/risks/{risk_id}/use-cases",
    response_model=RiskUseCaseResponse,
    status_code=201,
    dependencies=[Depends(enforce_api_token)],
)
def add_use_case(
    risk_id: str,
    payload: RiskUseCaseCreate,
    db: Session = Depends(get_db),
) -> RiskUseCaseResponse:
    try:
        return relationship_service.add_use_case(db, risk_id, payload)
    except NoResultFound as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except relationship_service.DuplicateUseCaseError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.get("/risks/{risk_id}/use-cases", response_model=List[RiskUseCaseResponse])
def get_use_cases(
    risk_id: str,
    db: Session = Depends(get_db),
) -> List[RiskUseCaseResponse]:
    try:
        return relationship_service.get_use_cases(db, risk_id)
    except NoResultFound as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/export/json")
def export_json(db: Session = Depends(get_db)) -> Response:
    payload = export_json_bytes(db)
    return Response(content=payload, media_type="application/json")


@router.get("/export/csv")
def export_csv(db: Session = Depends(get_db)) -> StreamingResponse:
    stream = export_csv_stream(db)
    return StreamingResponse(stream, media_type="text/csv")
