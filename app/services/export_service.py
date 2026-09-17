from __future__ import annotations

import csv
import io
import json
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Iterable, Iterator, List

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.db.models import Risk


def _ensure_export_dir() -> Path:
    export_path = Path(settings.export_dir)
    export_path.mkdir(parents=True, exist_ok=True)
    return export_path


def export_json_bytes(session: Session) -> bytes:
    risks = session.execute(select(Risk)).scalars().all()
    data = [dict(risk.card, risk_id=risk.risk_id, status=risk.status, version=risk.version) for risk in risks]
    return json.dumps(data, default=str, indent=2).encode()


def export_csv_stream(session: Session) -> Iterator[str]:
    risks = session.execute(select(Risk)).scalars().all()
    buffer = io.StringIO()
    writer = csv.DictWriter(
        buffer,
        fieldnames=[
            "risk_id",
            "risk_name",
            "description",
            "ai_model_type",
            "probability_level",
            "impact_level",
            "impact_dimensions",
            "trigger_conditions",
            "technological_dependencies",
            "known_mitigations",
            "regulatory_requirements",
            "operational_priority",
            "source_reference",
            "provenance",
            "related_risks",
            "categories",
            "energy_context",
            "version",
            "status",
        ],
    )
    writer.writeheader()
    yield buffer.getvalue()
    buffer.seek(0)
    buffer.truncate(0)
    for risk in risks:
        card = dict(risk.card)
        provenance_entries = []
        for entry in card.get("provenance", []):
            if isinstance(entry, (dict, list)):
                provenance_entries.append(json.dumps(entry, sort_keys=True))
            elif entry is not None:
                provenance_entries.append(str(entry))
        row = {
            "risk_id": risk.risk_id,
            "risk_name": card.get("risk_name"),
            "description": card.get("description"),
            "ai_model_type": ";".join(card.get("ai_model_type", [])),
            "probability_level": card.get("probability_level"),
            "impact_level": card.get("impact_level"),
            "impact_dimensions": ";".join(card.get("impact_dimensions", [])),
            "trigger_conditions": card.get("trigger_conditions"),
            "technological_dependencies": ";".join(card.get("technological_dependencies", [])),
            "known_mitigations": ";".join(card.get("known_mitigations", [])),
            "regulatory_requirements": ";".join(card.get("regulatory_requirements", [])),
            "operational_priority": card.get("operational_priority"),
            "source_reference": ";".join(card.get("source_reference", [])),
            "provenance": ";".join(provenance_entries),
            "related_risks": ";".join(card.get("related_risks", [])),
            "categories": ";".join(card.get("categories", [])),
            "energy_context": ";".join(card.get("energy_context", [])),
            "version": card.get("version"),
            "status": risk.status,
        }
        writer.writerow(row)
        yield buffer.getvalue()
        buffer.seek(0)
        buffer.truncate(0)


def export_to_files(session: Session) -> Dict[str, Path]:
    export_dir = _ensure_export_dir()
    timestamp = datetime.utcnow().strftime("%Y%m%d")
    json_path = export_dir / "eg_risks.json"
    json_path.write_bytes(export_json_bytes(session))
    csv_path = export_dir / "eg_risks.csv"
    # newline="" avoids double-translating the \r\n line terminators that
    # csv.writer already wrote into the stream (this double-translation is a
    # no-op on Linux, but corrupts the file with blank rows on Windows).
    csv_path.write_text("".join(export_csv_stream(session)), newline="")

    json_ts_path = export_dir / f"eg_risks_{timestamp}.json"
    csv_ts_path = export_dir / f"eg_risks_{timestamp}.csv"
    json_ts_path.write_bytes(json_path.read_bytes())
    csv_ts_path.write_bytes(csv_path.read_bytes())

    _prune_old_exports(export_dir)
    return {
        "json": json_path,
        "csv": csv_path,
        "json_timestamped": json_ts_path,
        "csv_timestamped": csv_ts_path,
    }


def _prune_old_exports(export_dir: Path) -> None:
    cutoff = datetime.utcnow() - timedelta(days=settings.export_retention_days)
    for file in export_dir.glob("eg_risks_*.json"):
        if _is_older_than(file, cutoff):
            file.unlink(missing_ok=True)
    for file in export_dir.glob("eg_risks_*.csv"):
        if _is_older_than(file, cutoff):
            file.unlink(missing_ok=True)


def _is_older_than(path: Path, cutoff: datetime) -> bool:
    return datetime.utcfromtimestamp(path.stat().st_mtime) < cutoff
