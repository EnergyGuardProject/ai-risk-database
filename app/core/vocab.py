from __future__ import annotations

from typing import Dict


def _titleize(identifier: str) -> str:
    if "." in identifier:
        parts = identifier.split(".")
    else:
        parts = identifier.split("_")
    return " ".join(part.capitalize() for part in parts)


CATEGORY_DEFINITIONS: Dict[str, Dict[str, str]] = {
    "technical.attack": {
        "name": "Technical Attack",
        "description": "Adversarial or malicious technical actions against AI systems.",
    },
    "governance.oversight": {
        "name": "Governance Oversight",
        "description": "Oversight and accountability gaps in AI operations.",
    },
    "governance.fairness": {
        "name": "Governance Fairness",
        "description": "Equity, bias, or fairness risks within AI governance.",
    },
    "governance.monitoring": {
        "name": "Governance Monitoring",
        "description": "Monitoring and performance management risks for AI systems.",
    },
    "governance.transparency": {
        "name": "Governance Transparency",
        "description": "Transparency, explainability, or stakeholder communication risks.",
    },
    "governance.compliance": {
        "name": "Governance Compliance",
        "description": "Regulatory reporting, documentation, or compliance gaps.",
    },
    "governance.legal": {
        "name": "Governance Legal",
        "description": "Legal exposure and contractual obligations tied to AI usage.",
    },
    "privacy.governance": {
        "name": "Privacy Governance",
        "description": "Privacy and data protection issues in AI governance.",
    },
    "safety.incidents": {
        "name": "Safety Incidents",
        "description": "Documented AI-related safety or operational incidents.",
    },
}

ALLOWED_CATEGORIES = set(CATEGORY_DEFINITIONS.keys())

ENERGY_CONTEXT_DEFINITIONS: Dict[str, Dict[str, str]] = {
    "generation_renewables": {
        "name": "Renewable Generation",
        "description": "Solar, wind, hydro, or other renewable generation assets.",
        "criticality": 3,
    },
    "generation_conventional": {
        "name": "Conventional Generation",
        "description": "Thermal, nuclear, or fossil-based power plants.",
        "criticality": 3,
    },
    "transmission_control": {
        "name": "Transmission Control",
        "description": "Transmission network operations, substations, relay protection.",
        "criticality": 4,
    },
    "distribution_operations": {
        "name": "Distribution Operations",
        "description": "Distribution management systems, outage restoration, voltage regulation.",
        "criticality": 3,
    },
    "market_operations": {
        "name": "Market Operations",
        "description": "Trading, dispatch optimisation, balancing markets, price forecasting.",
        "criticality": 3,
    },
    "demand_response": {
        "name": "Demand Response",
        "description": "Flexibility management, demand response aggregators, prosumer programmes.",
        "criticality": 3,
    },
    "retail_energy": {
        "name": "Retail Energy",
        "description": "Customer-facing services, billing, personalisation, demand prediction.",
        "criticality": 2,
    },
    "enterprise_it": {
        "name": "Enterprise IT",
        "description": "Back-office AI (HR, cybersecurity, procurement, document processing).",
        "criticality": 2,
    },
    "asset_management": {
        "name": "Asset Management",
        "description": "Predictive maintenance, inspection drones, fault detection.",
        "criticality": 3,
    },
    "public_affairs": {
        "name": "Public Affairs",
        "description": "External communications, regulatory transparency, explainability obligations.",
        "criticality": 2,
    },
    "legal_affairs": {
        "name": "Legal Affairs",
        "description": "Compliance tracking, documentation, regulatory submissions.",
        "criticality": 2,
    },
    "supply_chain": {
        "name": "Supply Chain",
        "description": "Vendor data, model sourcing, and third-party dependencies.",
        "criticality": 3,
    },
    "control_rooms": {
        "name": "Control Rooms",
        "description": "Real-time supervision, operator decision support, human-AI teaming.",
        "criticality": 4,
    },
    "transmission_planning": {
        "name": "Transmission Planning",
        "description": "Grid expansion, capacity planning, load flow simulations.",
        "criticality": 3,
    },
    "distributed_generation": {
        "name": "Distributed Generation",
        "description": "DER forecasting, microgrids, and virtual power plants.",
        "criticality": 3,
    },
    "substation_security": {
        "name": "Substation Security",
        "description": "Physical and digital security, surveillance analytics.",
        "criticality": 4,
    },
}

ALLOWED_CONTEXTS = set(ENERGY_CONTEXT_DEFINITIONS.keys())

RELATIONSHIP_TYPE_DEFINITIONS: Dict[str, str] = {
    "causes": "Source risk is a direct causal trigger for the target risk (e.g. a cascading OT failure chain).",
    "amplifies": "Source risk increases the probability or impact of the target risk without directly causing it.",
    "depends_on": "Source risk only materialises if the target risk's precondition is present.",
    "mitigates": "Source risk's controls reduce the probability or impact of the target risk.",
    "duplicates": "Source and target risks describe closely related but distinct findings that were not merged via merge_hash.",
}

ALLOWED_RELATIONSHIP_TYPES = set(RELATIONSHIP_TYPE_DEFINITIONS.keys())

STATUS_DEFINITIONS: Dict[str, str] = {
    "draft": "Newly ingested or authored; not yet reviewed.",
    "pending_review": "Submitted for editorial review.",
    "confirmed": "Reviewed and confirmed accurate, mirrors Scoping Register Column K 'CONFIRMED'.",
    "pending_approval": "Awaiting governance sign-off, mirrors Scoping Register Column K 'PENDING APPROVAL'.",
    "deprecated": "Superseded or withdrawn; retained for historical reference.",
}

ALLOWED_STATUSES = set(STATUS_DEFINITIONS.keys())

UC_ID_PATTERN = r"^UC-(EG|AG|ET-S)-\d+$"

# Source: D5.1_Step1_GOVERN_Methodology_v6.docx, Section 3.2.6, Column H
# ("IT/OT Boundary"). Transcribed from the Scoping Register's data dictionary.
ITOT_BOUNDARY_DEFINITIONS: Dict[str, Dict[str, str]] = {
    "it_only": {
        "name": "IT layer only; no OT interface",
        "description": (
            "AI operates entirely in the IT environment. Inputs from operational data "
            "historians, APIs, or data lakes. No direct control of physical equipment. "
            "Risk profile: data quality, model accuracy, GDPR, and supply chain (ML "
            "library) risks. OT-specific risks do not apply."
        ),
    },
    "it_historian_dmz_input": {
        "name": "IT layer; OT sensor/SCADA inputs via historian/DMZ",
        "description": (
            "AI receives data from OT systems but the data flow is unidirectional "
            "(OT -> IT via historian or DMZ). No AI output crosses into OT. Risk: data "
            "integrity of OT inputs (adversarial sensor manipulation, historian "
            "poisoning); distribution shift if OT operating conditions change without "
            "model retraining."
        ),
    },
    "itot_actuation": {
        "name": "IT/OT interface — AI outputs actuate OT systems",
        "description": (
            "AI outputs (control recommendations, setpoints, schedules) cross the "
            "IT/OT boundary and directly actuate physical equipment. Highest IT/OT "
            "risk category. Activates Gap G4 risk entries: adversarial manipulation "
            "of AI control outputs, insufficient latency for safety-critical real-time "
            "control, IT security compromise propagating to physical equipment."
        ),
    },
    "itot_readonly_no_actuation": {
        "name": "IT/OT interface — AI reads OT data; no direct actuation",
        "description": (
            "AI reads protection relay, COMTRADE, or IED data from the OT layer but "
            "does not send control commands back. Risk: relay data integrity "
            "(manipulated fault records misleading the AI classifier), communication "
            "protocol vulnerabilities (IEC 61850 GOOSE/SV), and the critical Gap G2 "
            "risk: AI misclassification of a genuine fault = uncleared event = "
            "protective relay cascade."
        ),
    },
    "itot_virtual_sensor": {
        "name": "IT/OT interface — AI virtual sensors replace SCADA measurements",
        "description": (
            "AI-generated virtual measurements substitute for missing real SCADA "
            "readings in downstream grid management tools. Most subtle IT/OT risk: if "
            "AI state estimates are treated as authoritative inputs by OT-adjacent "
            "EMS/SCADA, systematic AI estimation errors propagate into operational "
            "decisions without the usual SCADA measurement validation."
        ),
    },
    "ot_direct_execution": {
        "name": "OT environment — AI scenarios executed on physical equipment",
        "description": (
            "AI outputs are directly executed as operational commands on real "
            "physical equipment (electrolysis stacks, test benches). No IT "
            "intermediary. Highest physical safety risk category. Activates "
            "functional safety failure modes: safety integrity level (SIL) "
            "requirements for AI-generated operational scenarios, operator override "
            "latency, emergency shutdown system bypass risks."
        ),
    },
    "itot_advisory_readonly": {
        "name": "IT/OT interface (read-only from OT) — advisory outputs only",
        "description": (
            "AI reads from OT sensor data but outputs are advisory analyses, reports, "
            "or planning recommendations with no automated actuation pathway. Risk is "
            "lower than full IT/OT interface but indirect actuation is possible if an "
            "operator implements recommendations without independent validation."
        ),
    },
}

ALLOWED_ITOT_BOUNDARIES = set(ITOT_BOUNDARY_DEFINITIONS.keys())


def get_category_display_name(category_id: str) -> str:
    meta = CATEGORY_DEFINITIONS.get(category_id)
    if meta and meta.get("name"):
        return meta["name"]
    return _titleize(category_id)


def get_context_display_name(context_id: str) -> str:
    meta = ENERGY_CONTEXT_DEFINITIONS.get(context_id)
    if meta and meta.get("name"):
        return meta["name"]
    return _titleize(context_id)


def get_itot_boundary_display_name(boundary_id: str) -> str:
    meta = ITOT_BOUNDARY_DEFINITIONS.get(boundary_id)
    if meta and meta.get("name"):
        return meta["name"]
    return _titleize(boundary_id)
