from __future__ import annotations

import csv
import io
import json
import math
import os
import re
import urllib.request
from collections import OrderedDict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple

import yaml
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.vocab import ALLOWED_CATEGORIES, ALLOWED_CONTEXTS
from app.db.models import EnergyContext, Risk
from app.schemas.risk import RiskCard, RiskCreate, RiskUpdate
from app.services import risk_service

ROOT_DIR = Path(__file__).resolve().parents[2]
DATA_DIR = ROOT_DIR / "data"
ATLAS_TECHNIQUES_PATH = ROOT_DIR / "atlas_techniques.yaml"
RISK_ATLAS_NEXUS_CACHE = DATA_DIR / "risk_atlas_nexus_mappings.json"
RISK_ATLAS_NEXUS_SOURCES = {
    "nexus": "https://raw.githubusercontent.com/IBM/risk-atlas-nexus/main/src/risk_atlas_nexus/data/knowledge_graph/mappings/mit-ai-risk-repository_ibm-risk-atlas_from_tsv_data.yaml",
    "nist": "https://raw.githubusercontent.com/IBM/risk-atlas-nexus/main/src/risk_atlas_nexus/data/knowledge_graph/mappings/ibm2nistgenai_from_tsv_data.yaml",
}
REFRESH_RISK_ATLAS = os.getenv("REFRESH_RISK_ATLAS_NEXUS", "").lower() in {"1", "true", "yes"}

REQUIRED_COLUMNS = {
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
}

ALLOWED_IMPACT_DIMENSIONS = {
    "safety",
    "reliability",
    "security",
    "privacy",
    "fairness",
    "compliance",
    "financial",
    "reputation",
    "operational",
}

IMPACT_DIMENSION_MAP = {
    "grid_stability": "reliability",
    "stability": "reliability",
    "resilience": "reliability",
    "grid_resilience": "reliability",
    "trust": "reputation",
    "equity": "fairness",
}

ALLOWED_SOURCE_PREFIXES = {
    "MITRE_ATLAS",
    "AIID",
    "MIT_AIRISK",
    "IEEE",
    "ARXIV",
    "NERC",
    "EU-REG",
    "FERC",
    "NIST",
    "FAA",
    "OSHA",
    "NASA",
    "US",
}

REGULATION_ALIASES = {
    "eu ai act art.9": "EU-AI-Act-Art9",
    "eu ai act art.13": "EU-AI-Act-Art13",
    "eu ai act art.14": "EU-AI-Act-Art14",
    "eu ai act art.15": "EU-AI-Act-Art15",
    "eu ai act art.52": "EU-AI-Act-Art52",
    "eu ai act art.53": "EU-AI-Act-Art53",
    "eu ai act title iii": "EU-AI-Act-TitleIII",
    "eu ai act title iv": "EU-AI-Act-TitleIV",
    "eu ai act title ix": "EU-AI-Act-TitleIX",
    "gdpr": "EU-GDPR",
    "eu gdpr (2016/679)": "EU-GDPR-2016-679",
    "ccpa": "US-CCPA",
    "us ca ccpa (2018)": "US-CCPA-2018",
    "trade secrets act": "US-Trade-Secrets-Act",
    "us 18 u.s.c. section 1905": "US-18USC-1905",
    "justice40 directives": "US-EO-14008",
    "us executive order 14008": "US-EO-14008",
    "state utility commission orders": "STATE-UTILITY-COMMISSION-ORDERS",
    "copyright law": "US-Copyright-Law",
    "sox itgc": "SOX-ITGC",
    "sec fair disclosure": "SEC-Fair-Disclosure",
    "sec 17a-4": "SEC-17A-4",
    "ferc order 2222": "FERC-Order-2222",
    "ferc filing mandates": "FERC-Filing-Mandates",
    "biometric privacy acts": "US-Biometric-Privacy-Acts",
    "doe cip guidance": "DOE-CIP-Guidance",
    "doe data privacy order": "DOE-Data-Privacy-Order",
    "iso 27036": "ISO-27036",
    "iso/iec 27036": "ISO-27036",
    "faa part 107": "FAA-Part107",
    "osha 1910": "OSHA-29CFR-1910",
}

REGULATION_PATTERNS: Sequence[Tuple[re.Pattern[str], str]] = (
    (re.compile(r"eu[\\s-]*ai[\\s-]*act.*title\s*([ivx]+)", re.IGNORECASE), "EU-AI-Act-Title{title}"),
    (re.compile(r"eu[\\s-]*ai[\\s-]*act.*art(?:icle)?\.?\s*(\d+)", re.IGNORECASE), "EU-AI-Act-Art{article}"),
    (
        re.compile(r"eu\s*regulation\s*(\d{4})/(\d+)\s*title\s*([ivx]+)", re.IGNORECASE),
        "EU-REG-{year}-{code}-Title{title}",
    ),
    (
        re.compile(r"eu\s*regulation\s*(\d{4})/(\d+)\s*article\s*(\d+)", re.IGNORECASE),
        "EU-REG-{year}-{code}-Art{article}",
    ),
    (
        re.compile(r"nerc\s*([a-z]+)[\s-](\d+)[\s-](\d+)", re.IGNORECASE),
        "NERC-{family}-{code}-{version}",
    ),
    (
        re.compile(r"nerc\s*([a-z]+)[\s-](\d+)", re.IGNORECASE),
        "NERC-{family}-{code}",
    ),
    (
        re.compile(r"(?:iec|iso)\s*(\d+)", re.IGNORECASE),
        "{org}-{code}",
    ),
    (
        re.compile(r"nist\s*sp\s*(\d+)[\.-](\d+)(?:[\.-](\d+))?\s*(rev\.?\s*\d+)?", re.IGNORECASE),
        "NIST-SP-{major}-{minor}{extra}{rev}",
    ),
    (
        re.compile(r"nist\s*(\d+)[\.-](\d+)", re.IGNORECASE),
        "NIST-{major}-{minor}",
    ),
)


@dataclass
class LintIssue:
    row: int
    field: str
    error: str
    suggestion: Optional[str] = None


@dataclass
class NormalizedRisk:
    row: int
    risk_id: str
    status: str
    version: str
    card: Dict[str, Any]


def _load_id_list(path: Path) -> Set[str]:
    if not path.exists():
        return set()
    return {
        line.strip().lower()
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    }


def _load_mitre_atlas_ids() -> Set[str]:
    ids: Set[str] = set()
    if not ATLAS_TECHNIQUES_PATH.exists():
        return ids
    pattern = re.compile(r"\bid:\s*(AML\.[A-Z0-9\.]+)", re.IGNORECASE)
    for line in ATLAS_TECHNIQUES_PATH.read_text(encoding="utf-8").splitlines():
        match = pattern.search(line)
        if match:
            ids.add(match.group(1).upper())
    return ids


def _download_yaml(url: str) -> Optional[Dict[str, Any]]:
    try:
        with urllib.request.urlopen(url, timeout=20) as resp:
            raw = resp.read().decode("utf-8")
            return yaml.safe_load(raw) or {}
    except Exception:
        return None


def _load_risk_atlas_nexus() -> Dict[str, Dict[str, List[str]]]:
    if RISK_ATLAS_NEXUS_CACHE.exists() and not REFRESH_RISK_ATLAS:
        try:
            return json.loads(RISK_ATLAS_NEXUS_CACHE.read_text(encoding="utf-8"))
        except Exception:
            pass

    combined: Dict[str, Dict[str, Set[str]]] = {}

    def _merge_entry(entry: Dict[str, Any], key: str) -> None:
        atlas_id = entry.get("id")
        if not atlas_id:
            return
        target = combined.setdefault(atlas_id, {"relatedMatch": set(), "nist": set(), "mit_ai": set(), "mitre": set()})
        if "relatedMatch" in entry and entry["relatedMatch"]:
            target["relatedMatch"].update(entry["relatedMatch"])

    # Base nexus matches
    base_data = _download_yaml(RISK_ATLAS_NEXUS_SOURCES["nexus"])
    if base_data:
        for entry in base_data.get("risks", []):
            _merge_entry(entry, "relatedMatch")

    # NIST crosswalk if available
    nist_data = _download_yaml(RISK_ATLAS_NEXUS_SOURCES["nist"])
    if nist_data:
        for entry in nist_data.get("risks", []):
            atlas_id = entry.get("id")
            if not atlas_id:
                continue
            target = combined.setdefault(atlas_id, {"relatedMatch": set(), "nist": set(), "mit_ai": set(), "mitre": set()})
            if "relatedMatch" in entry and entry["relatedMatch"]:
                target["nist"].update(entry["relatedMatch"])

    # Normalise to lists and cache
    normalized: Dict[str, Dict[str, List[str]]] = {}
    for atlas_id, buckets in combined.items():
        normalized[atlas_id] = {
            "relatedMatch": sorted(buckets.get("relatedMatch", [])),
            "nist": sorted(buckets.get("nist", [])),
            "mit_ai": sorted(buckets.get("mit_ai", [])),
            "mitre": sorted(buckets.get("mitre", [])),
        }
    if normalized:
        try:
            RISK_ATLAS_NEXUS_CACHE.parent.mkdir(parents=True, exist_ok=True)
            RISK_ATLAS_NEXUS_CACHE.write_text(json.dumps(normalized, indent=2), encoding="utf-8")
        except Exception:
            pass
    return normalized


RISK_ATLAS_NEXUS = _load_risk_atlas_nexus()


def _load_altai_requirements(path: Path) -> Set[str]:
    if not path.exists():
        return set()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return {item["id"] for item in data if item.get("id")}
    except Exception:
        return set()


def _load_altai_mapping(path: Path, allowed: Set[str]) -> Dict[str, List[str]]:
    if not path.exists():
        return {}
    mapping: Dict[str, List[str]] = {}
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
        for line in lines[1:]:
            parts = line.split(",")
            if len(parts) < 2:
                continue
            risk_id = parts[0].strip()
            altai_ids = [token.strip() for token in parts[1].split(";") if token.strip()]
            altai_ids = [aid for aid in altai_ids if aid in allowed]
            if risk_id and altai_ids:
                mapping[risk_id] = sorted(set(altai_ids))
    except Exception:
        return {}
    return mapping


ALTAI_REQUIREMENTS = _load_altai_requirements(DATA_DIR / "altai_requirements.json")
ALTAI_MAPPING = _load_altai_mapping(DATA_DIR / "altai_risk_mapping.csv", ALTAI_REQUIREMENTS)


MIT_AIRISK_IDS = _load_id_list(DATA_DIR / "mit_airisk_ids.txt")
AIID_IDS = {item.upper() for item in _load_id_list(DATA_DIR / "aiid_incidents.txt")}
MITRE_ATLAS_IDS = _load_mitre_atlas_ids()

AIID_PATTERN = re.compile(r"INC-\d{3,}", re.IGNORECASE)
MIT_AIRISK_PATTERN = re.compile(r"[a-z0-9][a-z0-9_\-\.]*$")


def _is_valid_source(prefix: str, identifier: str) -> bool:
    if prefix == "MITRE_ATLAS":
        if MITRE_ATLAS_IDS:
            return identifier.upper() in MITRE_ATLAS_IDS
        return identifier.upper().startswith("AML.")
    if prefix == "AIID":
        identifier_upper = identifier.upper()
        if AIID_IDS:
            return identifier_upper in AIID_IDS
        return bool(AIID_PATTERN.fullmatch(identifier_upper))
    if prefix == "MIT_AIRISK":
        identifier_lower = identifier.lower()
        if MIT_AIRISK_IDS:
            return identifier_lower in MIT_AIRISK_IDS
        return bool(MIT_AIRISK_PATTERN.fullmatch(identifier_lower))
    return True


class CsvIngestor:
    def __init__(self, editor: str):
        self.editor = editor

    def load(self, file_path: Path) -> Tuple[List[NormalizedRisk], List[LintIssue]]:
        raw_rows, header_issues = self._read_csv(file_path)
        if header_issues:
            return [], header_issues
        entries: List[NormalizedRisk] = []
        issues: List[LintIssue] = []
        for row_num, row in raw_rows:
            normalized, row_issues = self._normalize_row(row_num, row)
            if row_issues:
                issues.extend(row_issues)
            if normalized and not row_issues:
                entries.append(normalized)
        if not issues:
            self._ensure_relationships(entries, issues)
        return entries, issues

    def upsert(self, session: Session, entries: Sequence[NormalizedRisk]) -> None:
        for entry in entries:
            card_payload = dict(entry.card)
            card_payload["stable_id"] = entry.risk_id
            risk_card = RiskCard(**card_payload)
            target = session.get(Risk, entry.risk_id)
            if not target:
                target = (
                    session.execute(select(Risk).where(Risk.card["merge_hash"].astext == entry.card["merge_hash"]))
                    .scalars()
                    .first()
                )
            if target:
                merged = self._merge_cards(dict(target.card), entry.card)
                merged["stable_id"] = target.risk_id
                update_payload = RiskUpdate(
                    status=entry.status or target.status,
                    version=entry.version or target.version,
                    card=RiskCard(**merged),
                )
                risk_service.update_risk(session, target.risk_id, update_payload, editor=self.editor)
                risk_id = target.risk_id
            else:
                create_payload = RiskCreate(
                    risk_id=entry.risk_id,
                    status=entry.status,
                    version=entry.version,
                    card=risk_card,
                )
                risk_service.create_risk(session, create_payload, editor=self.editor)
                risk_id = entry.risk_id
            risk_service.set_categories(session, risk_id=risk_id, category_ids=entry.card.get("categories", []))
            context_ids = entry.card.get("energy_context", [])
            if context_ids:
                existing_context_ids = (
                    session.execute(
                        select(EnergyContext.context_id).where(EnergyContext.context_id.in_(context_ids))
                    ).scalars().all()
                )
            else:
                existing_context_ids = []
            context_refs = [
                {"context_id": context_id, "exposure_level": 3}
                for context_id in existing_context_ids
            ]
            risk_service.set_contexts(session, risk_id=risk_id, context_refs=context_refs)

    def _read_csv(self, file_path: Path) -> Tuple[List[Tuple[int, Dict[str, str]]], List[LintIssue]]:
        issues: List[LintIssue] = []
        with file_path.open("r", encoding="utf-8") as handle:
            reader = csv.DictReader(handle)
            if reader.fieldnames is None:
                issues.append(LintIssue(row=0, field="header", error="Missing header row"))
                return [], issues
            missing = REQUIRED_COLUMNS - set(reader.fieldnames)
            if missing:
                issues.append(
                    LintIssue(
                        row=0,
                        field="header",
                        error=f"Missing required columns: {', '.join(sorted(missing))}",
                    )
                )
                return [], issues
            rows = [(index + 2, row) for index, row in enumerate(reader)]
        return rows, issues

    def _normalize_row(self, row_num: int, row: Dict[str, str]) -> Tuple[Optional[NormalizedRisk], List[LintIssue]]:
        issues: List[LintIssue] = []
        risk_id = row.get("risk_id", "").strip()
        if not risk_id:
            issues.append(LintIssue(row=row_num, field="risk_id", error="risk_id is required"))
            return None, issues
        risk_name = row.get("risk_name", "").strip()
        if not risk_name:
            issues.append(LintIssue(row=row_num, field="risk_name", error="risk_name is required"))
        description = row.get("description", "").strip()
        ai_model_type = self._normalize_ai_model_type(row.get("ai_model_type", ""))
        probability_level = self._ensure_level(row.get("probability_level", ""), "probability_level", row_num, issues)
        impact_level = self._ensure_level(row.get("impact_level", ""), "impact_level", row_num, issues)
        operational_priority = self._ensure_level(
            row.get("operational_priority", ""), "operational_priority", row_num, issues
        )
        impact_dimensions = self._normalize_impact_dimensions(row.get("impact_dimensions", ""), row_num, issues)
        trigger_conditions = row.get("trigger_conditions", "").strip()
        technological_dependencies = self._split_and_clean(row.get("technological_dependencies", ""))
        known_mitigations = self._split_and_clean(row.get("known_mitigations", ""))
        regulatory_requirements = self._normalize_regulations(row.get("regulatory_requirements", ""))
        source_reference, source_issues = self._normalize_source_references(
            row.get("source_reference", ""), row_num
        )
        issues.extend(source_issues)
        provenance = self._normalize_provenance(row.get("provenance", ""), source_reference)
        related_risks = self._normalize_related_risks(row.get("related_risks", ""))
        categories, category_issues = self._normalize_categories(row.get("categories", ""), row_num)
        issues.extend(category_issues)
        energy_context, context_issues = self._normalize_contexts(row.get("energy_context", ""), row_num)
        issues.extend(context_issues)
        version = row.get("version", "").strip() or "1.0"
        status = (row.get("status") or "draft").strip()

        card: Dict[str, Any] = {
            "risk_name": risk_name,
            "description": description,
            "ai_model_type": ai_model_type,
            "probability_level": probability_level,
            "impact_level": impact_level,
            "impact_dimensions": impact_dimensions,
            "trigger_conditions": trigger_conditions,
            "technological_dependencies": technological_dependencies,
            "known_mitigations": known_mitigations,
            "regulatory_requirements": regulatory_requirements,
            "operational_priority": operational_priority,
            "source_reference": source_reference,
            "provenance": provenance,
            "related_risks": related_risks,
            "categories": categories,
            "energy_context": energy_context,
            "version": version,
        }
        card["merge_hash"] = risk_service.compute_risk_hash(risk_name, description)
        card["lifecycle_stage"] = self._derive_lifecycle_stage(card)
        card["risk_summary"] = self._derive_summary(description)

        # Optional ALTAI column in source data
        altai_raw = row.get("altai_requirements", "")
        if altai_raw:
            altai_ids = self._sort_list([token.strip() for token in altai_raw.split(";") if token.strip()])
            if altai_ids:
                card["altai_requirements"] = altai_ids
                card.setdefault("provenance", []).append(
                    {
                        "action": "altai-sourced",
                        "altai_requirements": altai_ids,
                        "note": "altai_requirements column",
                    }
                )

        self._augment_provenance_from_mappings(card)
        self._apply_altai_mapping(risk_id, card)

        return NormalizedRisk(row=row_num, risk_id=risk_id, status=status, version=version, card=card), issues

    def _ensure_relationships(self, entries: List[NormalizedRisk], issues: List[LintIssue]) -> None:
        lookup = {entry.risk_id: entry for entry in entries}
        for entry in entries:
            related = list(entry.card.get("related_risks", []))
            adjusted = False
            for rel in related:
                if rel not in lookup:
                    issues.append(
                        LintIssue(
                            row=entry.row,
                            field="related_risks",
                            error=f"Unknown related risk '{rel}'",
                        )
                    )
                    continue
                counterpart = lookup[rel]
                counterpart_related = set(counterpart.card.get("related_risks", []))
                if entry.risk_id not in counterpart_related:
                    counterpart_related.add(entry.risk_id)
                    counterpart.card["related_risks"] = self._sort_list(counterpart_related)
                adjusted = True
            if adjusted:
                entry.card["related_risks"] = self._sort_list(entry.card.get("related_risks", []))

    def _merge_cards(self, existing: Dict[str, Any], incoming: Dict[str, Any]) -> Dict[str, Any]:
        list_fields = {
            "ai_model_type",
            "impact_dimensions",
            "technological_dependencies",
            "known_mitigations",
            "regulatory_requirements",
            "source_reference",
            "related_risks",
            "categories",
            "energy_context",
        }
        merged = dict(existing)
        for key, value in incoming.items():
            if key in list_fields:
                merged[key] = self._merge_lists(merged.get(key, []), value)
            elif key == "provenance":
                merged[key] = self._merge_provenance(merged.get(key, []), value)
            else:
                merged[key] = value
        return merged

    def _merge_lists(self, left: Iterable[str], right: Iterable[str]) -> List[str]:
        return self._sort_list(list(left) + list(right))

    def _merge_provenance(self, left: Iterable[Any], right: Iterable[Any]) -> List[Any]:
        result: List[Any] = []
        seen = set()
        for source in list(left) + list(right):
            normalized = self._normalize_provenance_entry(source)
            key = json.dumps(normalized, sort_keys=True)
            if key not in seen:
                result.append(normalized)
                seen.add(key)
        return result

    def _augment_provenance_from_mappings(self, card: Dict[str, Any]) -> None:
        if not RISK_ATLAS_NEXUS:
            return
        atlas_matches = self._guess_atlas_matches(card.get("risk_name", ""))
        if not atlas_matches:
            return
        for atlas_id in atlas_matches:
            mapping = RISK_ATLAS_NEXUS.get(atlas_id, {})
            entry: Dict[str, Any] = {
                "action": "mapped",
                "sources": [f"IBM_RISK_ATLAS:{atlas_id}"],
            }
            if mapping.get("relatedMatch"):
                entry["nexus_matches"] = mapping["relatedMatch"]
            if mapping.get("nist"):
                entry["nist_controls"] = mapping["nist"]
            if mapping.get("mitre"):
                entry["mitre_atlas"] = mapping["mitre"]
            if mapping.get("mit_ai"):
                entry["mit_ai"] = mapping["mit_ai"]
            card.setdefault("provenance", []).append(entry)

    def _apply_altai_mapping(self, risk_id: str, card: Dict[str, Any]) -> None:
        altai_ids = ALTAI_MAPPING.get(risk_id)
        if not altai_ids:
            return
        merged = self._sort_list(set(card.get("altai_requirements", [])) | set(altai_ids))
        card["altai_requirements"] = merged
        provenance_entry = {
            "action": "altai-mapped",
            "altai_requirements": merged,
            "note": "altai_risk_mapping.csv",
        }
        card.setdefault("provenance", []).append(provenance_entry)

    def _guess_atlas_matches(self, risk_name: str) -> List[str]:
        slug = self._slugify(risk_name)
        matches: List[str] = []
        for atlas_id in RISK_ATLAS_NEXUS.keys():
            atlas_slug = atlas_id.replace("atlas-", "")
            if slug == atlas_slug or slug.endswith(atlas_slug) or atlas_slug.endswith(slug):
                matches.append(atlas_id)
                continue
            atlas_tokens = set(atlas_slug.split("-"))
            slug_tokens = set(slug.split("-"))
            shared = atlas_tokens & slug_tokens
            if shared and len(shared) >= max(1, min(len(atlas_tokens), len(slug_tokens)) - 1):
                matches.append(atlas_id)
        return sorted(set(matches))

    def _slugify(self, value: str) -> str:
        value = value.lower()
        value = re.sub(r"[^a-z0-9]+", "-", value)
        return value.strip("-")

    def _normalize_provenance_entry(self, entry: Any) -> Dict[str, Any]:
        if isinstance(entry, dict):
            return entry
        if isinstance(entry, str):
            parsed = self._normalize_provenance(entry, [])
            return parsed[0] if parsed else {"note": entry}
        return {"note": str(entry)}

    def _normalize_ai_model_type(self, value: str) -> List[str]:
        tokens = [token.strip().lower() for token in value.split(";") if token.strip()]
        return self._sort_list(tokens)

    def _ensure_level(self, raw: str, field: str, row: int, issues: List[LintIssue]) -> Optional[int]:
        raw = raw.strip()
        if not raw:
            issues.append(LintIssue(row=row, field=field, error=f"{field} is required"))
            return None
        try:
            number = int(raw)
        except ValueError:
            issues.append(LintIssue(row=row, field=field, error=f"{field} must be an integer"))
            return None
        if number < 1 or number > 5:
            issues.append(LintIssue(row=row, field=field, error=f"{field} must be between 1 and 5"))
        return number

    def _normalize_impact_dimensions(self, value: str, row: int, issues: List[LintIssue]) -> List[str]:
        tokens = [token.strip().lower() for token in value.split(";") if token.strip()]
        normalized: List[str] = []
        for token in tokens:
            mapped = IMPACT_DIMENSION_MAP.get(token, token)
            if mapped not in ALLOWED_IMPACT_DIMENSIONS:
                issues.append(
                    LintIssue(
                        row=row,
                        field="impact_dimensions",
                        error=f"Unknown impact dimension '{token}'",
                    )
                )
            else:
                normalized.append(mapped)
        return self._sort_list(normalized)

    def _split_and_clean(self, value: str) -> List[str]:
        tokens = [token.strip() for token in value.split(";") if token.strip()]
        return self._sort_list(tokens)

    def _normalize_regulations(self, value: str) -> List[str]:
        tokens = [token.strip() for token in value.split(";") if token.strip()]
        normalized: List[str] = []
        for token in tokens:
            key = re.sub(r"[^\w]+", " ", token).strip().lower()
            mapped = REGULATION_ALIASES.get(key)
            if not mapped:
                mapped = self._apply_regulation_patterns(token)
            if not mapped:
                mapped = self._fallback_regulation(token)
            normalized.append(mapped)
        return self._sort_list(normalized)

    def _apply_regulation_patterns(self, token: str) -> Optional[str]:
        for pattern, template in REGULATION_PATTERNS:
            match = pattern.search(token)
            if not match:
                continue
            if "{year}" in template:
                year, code = match.group(1), match.group(2)
                if "TITLE" in template:
                    title = match.group(3).upper()
                    return template.format(year=year, code=code, title=title)
                if "ART" in template:
                    article = match.group(3)
                    return template.format(year=year, code=code, article=article)
            elif "{family}" in template and match.lastindex:
                family = match.group(1).upper()
                code = match.group(2)
                if match.lastindex >= 3 and match.group(3):
                    version = match.group(3)
                    return template.format(family=family, code=code, version=version)
                return template.format(family=family, code=code)
            elif "{org}" in template:
                org = "IEC" if token.lower().startswith("iec") else "ISO"
                code = match.group(1)
                return template.format(org=org, code=code)
            elif "{major}" in template:
                major = match.group(1)
                minor = match.group(2)
                extra = ""
                if match.lastindex and match.lastindex >= 3:
                    extra_val = match.group(3)
                    extra = f"-{extra_val}" if extra_val else ""
                rev = ""
                if match.lastindex and match.lastindex >= 4:
                    rev_val = match.group(4) or ""
                    rev_val = rev_val.replace(" ", "")
                    rev = f"-{rev_val}" if rev_val else ""
                return template.format(major=major, minor=minor, extra=extra, rev=rev)
            elif "{article}" in template:
                article = match.group(1)
                return template.format(article=article)
            elif "{title}" in template:
                title = match.group(1).upper()
                return template.format(title=title)
        return None

    def _fallback_regulation(self, token: str) -> str:
        cleaned = re.sub(r"[^\w]+", "-", token.strip())
        return cleaned.upper()

    def _normalize_source_references(self, value: str, row: int) -> Tuple[List[str], List[LintIssue]]:
        tokens = [token.strip() for token in value.split(";") if token.strip()]
        normalized: List[str] = []
        issues: List[LintIssue] = []
        for token in tokens:
            mapped = self._map_source_reference(token)
            if not mapped:
                issues.append(
                    LintIssue(
                        row=row,
                        field="source_reference",
                        error=f"Unsupported source reference '{token}'",
                    )
                )
            else:
                normalized.append(mapped)
        return self._sort_list(normalized), issues

    def _map_source_reference(self, token: str) -> Optional[str]:
        token = token.strip()
        if not token:
            return None
        match = re.match(r"\s*([A-Za-z0-9_\-]+)\s*:\s*(.+)", token)
        if not match:
            return None
        prefix_raw, body_raw = match.groups()
        prefix = prefix_raw.upper()
        if prefix not in ALLOWED_SOURCE_PREFIXES:
            return None
        body = body_raw.strip()
        if not body:
            return None
        if prefix == "IEEE":
            if not body.upper().startswith("DOI:"):
                body = f"DOI:{body}"
        elif prefix in {"MITRE_ATLAS", "AIID"}:
            body = body.upper()
        elif prefix in {"NERC", "FERC", "NIST"}:
            body = body.upper()
        elif prefix == "OSHA":
            body = body.replace(" ", "")
        elif prefix == "FAA":
            body = body.replace(" ", "")
        elif prefix == "MIT_AIRISK":
            body = body.strip().lower()
        elif prefix == "NASA":
            body = body.upper()
        elif prefix == "US":
            body = body.upper()
        normalized = f"{prefix}:{body}"
        if not _is_valid_source(prefix, body):
            return None
        return normalized

    def _normalize_provenance(self, value: str, normalized_sources: List[str]) -> List[Dict[str, Any]]:
        entries = [token.strip() for token in value.split(";") if token.strip()]
        results: List[Dict[str, Any]] = []
        for entry in entries:
            parts = [part.strip() for part in entry.split("|") if part.strip()]
            action: Optional[str] = None
            sources: List[str] = []
            metadata: Dict[str, Any] = {}
            for part in parts:
                if ":" not in part:
                    normalized = self._map_source_reference(part) or part
                    if normalized in normalized_sources and normalized not in sources:
                        sources.append(normalized)
                    continue
                key, raw_value = part.split(":", 1)
                key_lower = key.strip().lower()
                raw_value = raw_value.strip()
                if key_lower == "merged":
                    action = "merged"
                    if raw_value:
                        mapped = self._map_source_reference(raw_value) or raw_value
                        if mapped not in sources:
                            sources.append(mapped)
                elif key_lower in {"source", "src"}:
                    mapped = self._map_source_reference(raw_value) or raw_value
                    if mapped not in sources:
                        sources.append(mapped)
                elif key_lower == "editor":
                    metadata["editor"] = raw_value
                elif key_lower in {"date", "timestamp"}:
                    metadata[key_lower] = raw_value
                elif key_lower == "action":
                    action = raw_value.lower()
                else:
                    metadata[key_lower] = raw_value
            if action or sources:
                payload: Dict[str, Any] = {}
                if action:
                    payload["action"] = action
                if sources:
                    payload["sources"] = sources
                if payload:
                    results.append(payload)
            if metadata:
                results.append(metadata)
        return results

    def _normalize_related_risks(self, value: str) -> List[str]:
        tokens = [token.strip().upper() for token in value.split(";") if token.strip()]
        return self._sort_list(tokens)

    def _normalize_categories(self, value: str, row: int) -> Tuple[List[str], List[LintIssue]]:
        tokens = [token.strip() for token in value.split(";") if token.strip()]
        normalized: List[str] = []
        issues: List[LintIssue] = []
        for token in tokens:
            if token in ALLOWED_CATEGORIES:
                normalized.append(token)
            else:
                suggestion = self._suggest(token, ALLOWED_CATEGORIES)
                issues.append(
                    LintIssue(
                        row=row,
                        field="categories",
                        error=f"Unknown category '{token}'",
                        suggestion=suggestion,
                    )
                )
        return self._sort_list(normalized), issues

    def _normalize_contexts(self, value: str, row: int) -> Tuple[List[str], List[LintIssue]]:
        tokens = [token.strip() for token in value.split(";") if token.strip()]
        normalized: List[str] = []
        issues: List[LintIssue] = []
        for token in tokens:
            if token not in ALLOWED_CONTEXTS:
                issues.append(
                    LintIssue(
                        row=row,
                        field="energy_context",
                        error=f"Unknown energy context '{token}'",
                    )
                )
            else:
                normalized.append(token)
        return self._sort_list(normalized), issues

    def _derive_lifecycle_stage(self, card: Dict[str, Any]) -> str:
        text = f"{card.get('risk_name', '')} {card.get('description', '')}".lower()
        categories = set(card.get("categories", []))
        if any(keyword in text for keyword in ("poison", "backdoor")):
            return "training"
        if any(keyword in text for keyword in ("evasion", "spoof", "adversarial")):
            return "deployment"
        if any(keyword in text for keyword in ("drift", "monitor")):
            return "monitoring"
        if any(keyword in text for keyword in ("licens", "compliance", "oversight", "transparenc", "bias")):
            return "governance"
        if categories & {
            "governance.oversight",
            "governance.compliance",
            "governance.transparency",
            "governance.fairness",
            "governance.legal",
        }:
            return "governance"
        if "technical.attack" in categories:
            return "deployment"
        if "data" in text and not categories:
            return "data"
        return "governance"

    def _derive_summary(self, description: str) -> str:
        description = description.strip()
        if not description:
            return ""
        match = re.search(r"([^.?!]+[.?!])", description)
        sentence = match.group(1) if match else description
        sentence = sentence.strip()
        if len(sentence) <= 160:
            return sentence
        truncated = sentence[:160].rstrip()
        if not truncated.endswith("."):
            truncated = truncated.rstrip(" ,;:")
        if len(truncated) < len(sentence):
            truncated = truncated.rstrip(".") + "..."
        return truncated

    def _sort_list(self, values: Iterable[str]) -> List[str]:
        ordered = OrderedDict()
        for value in values:
            if not value:
                continue
            key = value.strip()
            ordered.setdefault(key.lower(), key.strip())
        return [ordered[key] for key in sorted(ordered)]

    def _suggest(self, token: str, candidates: Iterable[str]) -> Optional[str]:
        token_lower = token.lower()
        closest: Optional[str] = None
        min_distance = math.inf
        for candidate in candidates:
            distance = self._levenshtein(token_lower, candidate.lower())
            if distance < min_distance:
                min_distance = distance
                closest = candidate
        if min_distance <= 2:
            return closest
        return None

    def _levenshtein(self, s1: str, s2: str) -> int:
        if s1 == s2:
            return 0
        if not s1:
            return len(s2)
        if not s2:
            return len(s1)
        previous_row = list(range(len(s2) + 1))
        for i, c1 in enumerate(s1, start=1):
            current_row = [i]
            for j, c2 in enumerate(s2, start=1):
                insertions = previous_row[j] + 1
                deletions = current_row[j - 1] + 1
                substitutions = previous_row[j - 1] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row
        return previous_row[-1]


def format_lint_issues(issues: Sequence[LintIssue]) -> str:
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["row", "field", "error", "suggestion"])
    for issue in issues:
        writer.writerow([issue.row, issue.field, issue.error, issue.suggestion or ""])
    return output.getvalue()

