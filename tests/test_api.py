from __future__ import annotations

from pathlib import Path

import pytest
import json
from sqlalchemy import text
from typer.testing import CliRunner

from app.cli import cli as cli_app
from app.db.models import Risk
from app.db.session import get_session
from app.services.export_service import export_json_bytes


INVALID_CARD = {
    "risk_id": "EG-R-9000",
    "status": "draft",
    "version": "1.0",
    "card": {
        "risk_name": "Invalid Risk",
        "description": "Example invalid risk for testing.",
        "ai_model_type": ["forecasting"],
        "probability_level": 3,
        "impact_level": 6,
        "impact_dimensions": ["reliability"],
        "trigger_conditions": "Testing",
        "technological_dependencies": ["pipeline"],
        "known_mitigations": ["mitigation"],
        "regulatory_requirements": ["NERC-CIP-013"],
        "operational_priority": 3,
        "source_reference": ["MITRE_ATLAS:AML.T0020"],
        "provenance": [{"note": "unit-test"}],
        "related_risks": [],
        "categories": [],
        "energy_context": [],
        "version": "1.0",
    },
}


VALID_CARD = {
    "risk_id": "EG-R-9001",
    "status": "confirmed",
    "version": "1.0",
    "card": {
        "risk_name": "Forecast Bias",
        "description": "Forecast bias leading to operational issues.",
        "ai_model_type": ["forecasting"],
        "probability_level": 3,
        "impact_level": 4,
        "impact_dimensions": ["reliability"],
        "trigger_conditions": "Unexpected weather shift",
        "technological_dependencies": ["data lake"],
        "known_mitigations": ["retraining"],
        "regulatory_requirements": ["NERC-CIP-013"],
        "operational_priority": 4,
        "source_reference": ["MITRE_ATLAS:AML.T0020"],
        "provenance": [{"note": "unit-test"}],
        "related_risks": [],
        "categories": ["governance.monitoring"],
        "energy_context": ["transmission_planning"],
        "version": "1.0",
    },
}


def test_validation_rejects_invalid_levels(client):
    response = client.post("/risks", json=INVALID_CARD)
    assert response.status_code == 422


def test_search_and_filters(client):
    create = client.post("/risks", json=VALID_CARD)
    assert create.status_code == 201
    response = client.get("/risks", params={"q": "forecast", "min_impact": 4})
    assert response.status_code == 200
    items = response.json()
    assert any(item["risk_id"] == VALID_CARD["risk_id"] for item in items)
    brief = client.get("/risks/brief", params={"ids": VALID_CARD["risk_id"]})
    assert brief.status_code == 200
    brief_items = brief.json()
    assert brief_items[0]["risk_id"] == VALID_CARD["risk_id"]


@pytest.mark.parametrize("ingest_runs", [1, 2])
def test_import_idempotency(tmp_path, ingest_runs):
    seed_file = tmp_path / "seed.csv"
    seed_file.write_text(
        "risk_id,risk_name,description,ai_model_type,probability_level,impact_level,impact_dimensions,trigger_conditions,technological_dependencies,known_mitigations,regulatory_requirements,operational_priority,source_reference,provenance,related_risks,categories,energy_context,version\n"
        "EG-R-9100,Test Risk,Description,forecasting,3,4,reliability,Trigger,Dependency,Mitigation,NERC CIP-013,3,MITRE_ATLAS:AML.T0020,merged: MITRE_ATLAS:AML.T0020 | editor:ICCS | date:2024-03-20,,governance.oversight,control_rooms,1.0\n"
    )
    runner = CliRunner()
    for _ in range(ingest_runs):
        result = runner.invoke(cli_app, ["ingest", "canonical-seed", "--file", str(seed_file)])
        assert result.exit_code == 0
    with get_session() as session:
        count = session.query(Risk).count()
    assert count == 1


def test_export_parity(tmp_path):
    runner = CliRunner()
    runner.invoke(cli_app, ["ingest", "canonical-seed", "--file", str(Path("seed_canonical_risks.csv"))])
    with get_session() as session:
        db_count = session.query(Risk).count()
        export_payload = export_json_bytes(session)
    assert db_count >= 20
    assert len(export_payload) > 0


def test_ingest_seed_csv():
    runner = CliRunner()
    result = runner.invoke(cli_app, ["ingest", "canonical-seed", "--file", str(Path("seed_canonical_risks.csv"))])
    assert result.exit_code == 0
    with get_session() as session:
        count = session.query(Risk).count()
    assert count >= 20


def test_post_new_risk_json(client):
    new_risk_path = Path("new_risk.json")
    payload = json.loads(new_risk_path.read_text(encoding="utf-8"))
    response = client.post("/risks", json=payload)
    assert response.status_code == 201
    data = response.json()
    assert data["risk_id"] == payload["risk_id"]


SECOND_VALID_CARD = {
    "risk_id": "EG-R-9002",
    "status": "confirmed",
    "version": "1.0",
    "card": {
        "risk_name": "Protective Relay Cascade",
        "description": "Misclassified fault condition cascades into a protective relay trip.",
        "ai_model_type": ["forecasting"],
        "probability_level": 2,
        "impact_level": 5,
        "impact_dimensions": ["reliability", "safety"],
        "trigger_conditions": "Upstream forecast bias feeding relay logic",
        "technological_dependencies": ["relay control system"],
        "known_mitigations": ["redundant relay checks"],
        "regulatory_requirements": ["NERC-CIP-013"],
        "operational_priority": 5,
        "source_reference": ["MITRE_ATLAS:AML.T0020"],
        "provenance": [{"note": "unit-test"}],
        "related_risks": [],
        "categories": ["governance.monitoring"],
        "energy_context": ["transmission_control"],
        "version": "1.0",
    },
}


def test_relationship_causes_queryable_both_directions(client):
    assert client.post("/risks", json=VALID_CARD).status_code == 201
    assert client.post("/risks", json=SECOND_VALID_CARD).status_code == 201

    response = client.post(
        f"/risks/{VALID_CARD['risk_id']}/relationships",
        json={"target_risk_id": SECOND_VALID_CARD["risk_id"], "relationship_type": "causes", "notes": "cascade"},
    )
    assert response.status_code == 201

    outgoing = client.get(f"/risks/{VALID_CARD['risk_id']}/relationships", params={"direction": "outgoing"})
    assert outgoing.status_code == 200
    assert any(r["target_risk_id"] == SECOND_VALID_CARD["risk_id"] for r in outgoing.json())

    incoming = client.get(f"/risks/{SECOND_VALID_CARD['risk_id']}/relationships", params={"direction": "incoming"})
    assert incoming.status_code == 200
    assert any(r["source_risk_id"] == VALID_CARD["risk_id"] for r in incoming.json())


def test_relationship_rejects_duplicate(client):
    assert client.post("/risks", json=VALID_CARD).status_code == 201
    assert client.post("/risks", json=SECOND_VALID_CARD).status_code == 201

    first = client.post(
        f"/risks/{VALID_CARD['risk_id']}/relationships",
        json={"target_risk_id": SECOND_VALID_CARD["risk_id"], "relationship_type": "causes", "notes": "original"},
    )
    assert first.status_code == 201

    second = client.post(
        f"/risks/{VALID_CARD['risk_id']}/relationships",
        json={"target_risk_id": SECOND_VALID_CARD["risk_id"], "relationship_type": "causes", "notes": "overwrite attempt"},
    )
    assert second.status_code == 409

    outgoing = client.get(f"/risks/{VALID_CARD['risk_id']}/relationships", params={"direction": "outgoing"})
    assert outgoing.status_code == 200
    matches = [r for r in outgoing.json() if r["target_risk_id"] == SECOND_VALID_CARD["risk_id"]]
    assert len(matches) == 1
    assert matches[0]["notes"] == "original"


def test_relationship_rejects_self_reference(client):
    assert client.post("/risks", json=VALID_CARD).status_code == 201
    response = client.post(
        f"/risks/{VALID_CARD['risk_id']}/relationships",
        json={"target_risk_id": VALID_CARD["risk_id"], "relationship_type": "causes"},
    )
    assert response.status_code == 400


def test_relationship_rejects_invalid_type(client):
    assert client.post("/risks", json=VALID_CARD).status_code == 201
    assert client.post("/risks", json=SECOND_VALID_CARD).status_code == 201
    response = client.post(
        f"/risks/{VALID_CARD['risk_id']}/relationships",
        json={"target_risk_id": SECOND_VALID_CARD["risk_id"], "relationship_type": "obliterates"},
    )
    assert response.status_code == 422


def test_use_case_add_and_list(client):
    assert client.post("/risks", json=VALID_CARD).status_code == 201
    response = client.post(
        f"/risks/{VALID_CARD['risk_id']}/use-cases",
        json={"uc_id": "UC-ET-S-18", "source_project": "EnerTEF"},
    )
    assert response.status_code == 201

    listed = client.get(f"/risks/{VALID_CARD['risk_id']}/use-cases")
    assert listed.status_code == 200
    assert any(uc["uc_id"] == "UC-ET-S-18" for uc in listed.json())


def test_use_case_rejects_duplicate(client):
    assert client.post("/risks", json=VALID_CARD).status_code == 201

    first = client.post(
        f"/risks/{VALID_CARD['risk_id']}/use-cases",
        json={"uc_id": "UC-ET-S-18", "source_project": "EnerTEF", "notes": "original"},
    )
    assert first.status_code == 201

    second = client.post(
        f"/risks/{VALID_CARD['risk_id']}/use-cases",
        json={"uc_id": "UC-ET-S-18", "source_project": "EnerTEF", "notes": "overwrite attempt"},
    )
    assert second.status_code == 409

    listed = client.get(f"/risks/{VALID_CARD['risk_id']}/use-cases")
    assert listed.status_code == 200
    matches = [uc for uc in listed.json() if uc["uc_id"] == "UC-ET-S-18"]
    assert len(matches) == 1
    assert matches[0]["notes"] == "original"


def test_use_case_rejects_malformed_uc_id(client):
    assert client.post("/risks", json=VALID_CARD).status_code == 201
    response = client.post(
        f"/risks/{VALID_CARD['risk_id']}/use-cases",
        json={"uc_id": "UC-FOO-1"},
    )
    assert response.status_code == 422


def test_status_rejects_out_of_vocab_value(client):
    bad_status_card = json.loads(json.dumps(VALID_CARD))
    bad_status_card["status"] = "on_hold"
    response = client.post("/risks", json=bad_status_card)
    assert response.status_code == 422


def test_db_level_probability_range_constraint(client):
    """Confirms the JSONB range CHECK created by the after_create event listener on
    Risk.__table__ (app/db/models.py) on a raw, Pydantic-bypassing insert. Only
    meaningful against Postgres: the constraint is deliberately not a plain
    CheckConstraint on the SQLAlchemy model, so it does not exist on the SQLite
    engine the rest of this suite runs against, and is skipped there."""
    from app.db import session as session_module

    if session_module.engine.dialect.name != "postgresql":
        pytest.skip("JSONB range CHECK is Postgres-only; see app/db/models.py")

    with session_module.get_session() as session:
        session.execute(text("DELETE FROM risk WHERE risk_id = 'EG-R-9999'"))
        with pytest.raises(Exception):
            session.execute(
                text(
                    "INSERT INTO risk (risk_id, status, version, card) VALUES "
                    "('EG-R-9999', 'draft', '1.0', "
                    "'{\"probability_level\": 9, \"impact_level\": 1}'::jsonb)"
                )
            )
            session.commit()


def test_itot_boundary_rejects_out_of_vocab_value(client):
    bad_boundary_card = json.loads(json.dumps(VALID_CARD))
    bad_boundary_card["card"]["it_ot_boundary"] = "cloud_only"
    response = client.post("/risks", json=bad_boundary_card)
    assert response.status_code == 422


def test_itot_boundary_accepts_valid_value(client):
    good_boundary_card = json.loads(json.dumps(VALID_CARD))
    good_boundary_card["card"]["it_ot_boundary"] = "itot_virtual_sensor"
    response = client.post("/risks", json=good_boundary_card)
    assert response.status_code == 201
    assert response.json()["card"]["it_ot_boundary"] == "itot_virtual_sensor"


def test_init_db_creates_all_check_constraints_without_migration_script(client):
    """A fresh Postgres database created by init_db() alone must already have all
    eight CHECK constraints: the four that were always part of the SQLAlchemy
    model/table_args (chk_status_vocab, chk_relationship_type,
    chk_no_self_relationship, chk_uc_id_pattern) plus the four JSONB constraints
    wired up via the after_create event listener on Risk.__table__ in
    app/db/models.py (chk_probability_level_range, chk_impact_level_range,
    chk_operational_priority_range, chk_itot_boundary_vocab). There is no longer a
    separate migration script for any of these -- init_db() is the only setup path,
    by design (see README)."""
    from app.db import session as session_module

    if session_module.engine.dialect.name != "postgresql":
        pytest.skip("CHECK constraint existence via pg_constraint is Postgres-only")

    expected_constraints = {
        "chk_status_vocab",
        "chk_relationship_type",
        "chk_no_self_relationship",
        "chk_uc_id_pattern",
        "chk_probability_level_range",
        "chk_impact_level_range",
        "chk_operational_priority_range",
        "chk_itot_boundary_vocab",
    }

    with session_module.get_session() as session:
        found = {
            row[0]
            for row in session.execute(
                text("SELECT conname FROM pg_constraint WHERE conname = ANY(:names)"),
                {"names": list(expected_constraints)},
            )
        }

    assert found == expected_constraints


def test_db_level_itot_boundary_constraint(client):
    """Confirms the JSONB vocab CHECK (chk_itot_boundary_vocab) created by the
    after_create event listener on Risk.__table__ (app/db/models.py) on a raw,
    Pydantic-bypassing insert. Only meaningful against Postgres: the constraint is
    deliberately not a plain CheckConstraint on the SQLAlchemy model, so it does not
    exist on the SQLite engine the rest of this suite runs against, and is skipped
    there."""
    from app.db import session as session_module

    if session_module.engine.dialect.name != "postgresql":
        pytest.skip("it_ot_boundary vocab CHECK is Postgres-only; see app/db/models.py")

    with session_module.get_session() as session:
        session.execute(text("DELETE FROM risk WHERE risk_id = 'EG-R-9998'"))
        with pytest.raises(Exception):
            session.execute(
                text(
                    "INSERT INTO risk (risk_id, status, version, card) VALUES "
                    "('EG-R-9998', 'draft', '1.0', "
                    "'{\"probability_level\": 3, \"impact_level\": 3, \"it_ot_boundary\": \"cloud_only\"}'::jsonb)"
                )
            )
            session.commit()
