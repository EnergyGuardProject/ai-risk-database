from sqlalchemy import (
    CheckConstraint,
    Column,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    JSON,
    String,
    Text,
    event,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import declarative_base, relationship

Base = declarative_base()


class Risk(Base):
    __tablename__ = "risk"
    __table_args__ = (
        CheckConstraint(
            "status IS NULL OR status IN ('draft','pending_review','confirmed','pending_approval','deprecated')",
            name="chk_status_vocab",
        ),
    )

    risk_id = Column(String, primary_key=True)
    status = Column(String, nullable=True)
    version = Column(String, nullable=True)
    card = Column(JSONB().with_variant(JSON, "sqlite"), nullable=False)
    created_at = Column(DateTime, server_default=func.now(), nullable=False)
    updated_at = Column(DateTime, server_default=func.now(), nullable=False)

    categories = relationship("RiskCategory", back_populates="risk", cascade="all, delete-orphan")
    contexts = relationship("RiskContext", back_populates="risk", cascade="all, delete-orphan")


class Category(Base):
    __tablename__ = "category"

    category_id = Column(String, primary_key=True)
    name = Column(String, nullable=False)
    description = Column(Text, nullable=True)
    parent_category_id = Column(String, ForeignKey("category.category_id"), nullable=True)

    parent = relationship("Category", remote_side=[category_id])


class EnergyContext(Base):
    __tablename__ = "energy_context"

    context_id = Column(String, primary_key=True)
    name = Column(String, nullable=False, unique=True)
    description = Column(Text, nullable=True)
    criticality_level = Column(Integer, CheckConstraint("criticality_level BETWEEN 1 AND 5"), nullable=False)


class RiskCategory(Base):
    __tablename__ = "risk_category"
    __table_args__ = (
        CheckConstraint("assignment_type <> ''", name="chk_assignment_type"),
        Index("risk_category_risk_id_idx", "risk_id"),
        Index("risk_category_category_id_idx", "category_id"),
        {
            "postgresql_partition_by": None,
        },
    )

    risk_id = Column(String, ForeignKey("risk.risk_id", ondelete="CASCADE"), primary_key=True)
    category_id = Column(String, ForeignKey("category.category_id", ondelete="CASCADE"), primary_key=True)
    assignment_type = Column(String, nullable=False, default="primary")

    risk = relationship("Risk", back_populates="categories")
    category = relationship("Category")


class RiskContext(Base):
    __tablename__ = "risk_context"
    __table_args__ = (
        CheckConstraint("exposure_level BETWEEN 1 AND 5", name="chk_exposure_level"),
        Index("risk_context_risk_id_idx", "risk_id"),
        Index("risk_context_context_id_idx", "context_id"),
    )

    risk_id = Column(String, ForeignKey("risk.risk_id", ondelete="CASCADE"), primary_key=True)
    context_id = Column(String, ForeignKey("energy_context.context_id", ondelete="CASCADE"), primary_key=True)
    exposure_level = Column(Integer, nullable=False)

    risk = relationship("Risk", back_populates="contexts")
    context = relationship("EnergyContext")


class RiskRelationship(Base):
    __tablename__ = "risk_relationship"
    __table_args__ = (
        CheckConstraint(
            "relationship_type IN ('causes','amplifies','depends_on','mitigates','duplicates')",
            name="chk_relationship_type",
        ),
        CheckConstraint("source_risk_id <> target_risk_id", name="chk_no_self_relationship"),
        Index("risk_relationship_source_idx", "source_risk_id"),
        Index("risk_relationship_target_idx", "target_risk_id"),
    )

    source_risk_id = Column(String, ForeignKey("risk.risk_id", ondelete="CASCADE"), primary_key=True)
    target_risk_id = Column(String, ForeignKey("risk.risk_id", ondelete="CASCADE"), primary_key=True)
    relationship_type = Column(String, primary_key=True)
    notes = Column(Text, nullable=True)

    source_risk = relationship(
        "Risk", foreign_keys=[source_risk_id], backref="outgoing_relationships"
    )
    target_risk = relationship(
        "Risk", foreign_keys=[target_risk_id], backref="incoming_relationships"
    )


# UC_ID_PATTERN mirrors app.schemas.relationship.UC_ID_PATTERN; kept as a plain
# comment here (rather than a shared import) to avoid a schemas -> db import cycle.
UC_ID_REGEX_SQL = r"^UC-(EG|AG|ET-S)-[0-9]+$"


class RiskUseCase(Base):
    __tablename__ = "risk_use_case"
    __table_args__ = (
        Index("risk_use_case_risk_id_idx", "risk_id"),
        Index("risk_use_case_uc_id_idx", "uc_id"),
    )

    risk_id = Column(String, ForeignKey("risk.risk_id", ondelete="CASCADE"), primary_key=True)
    uc_id = Column(String, primary_key=True)
    source_project = Column(String, nullable=True)  # "EnergyGuard" | "AI.Grids" | "EnerTEF"
    notes = Column(Text, nullable=True)

    risk = relationship("Risk", backref="use_cases")


@event.listens_for(RiskUseCase.__table__, "after_create")
def create_uc_id_pattern_constraint(target, connection, **kw):
    # Postgres-only: SQLite (used for the test suite, see tests/conftest.py) has no
    # POSIX regex `~` operator, so a literal CheckConstraint on the model would fail
    # DDL on every test run. The pattern is also enforced in Python at the schema
    # layer (app.schemas.relationship.UC_ID_PATTERN) so SQLite-backed paths stay covered.
    if connection.dialect.name != "postgresql":
        return
    connection.execute(
        text(f"ALTER TABLE risk_use_case ADD CONSTRAINT chk_uc_id_pattern CHECK (uc_id ~ '{UC_ID_REGEX_SQL}')")
    )


@event.listens_for(Risk.__table__, "after_create")
def create_risk_card_check_constraints(target, connection, **kw):
    # Postgres-only: these are JSONB `->>'field'` extraction CHECKs, which SQLite
    # (used for the test suite, see tests/conftest.py) cannot express. Pydantic
    # enforces the same rules at the API layer (app/schemas/risk.py), so SQLite-backed
    # paths stay covered; these constraints are the DB-level backstop for writes that
    # bypass Pydantic. Mirrors create_uc_id_pattern_constraint above.
    if connection.dialect.name != "postgresql":
        return
    connection.execute(
        text(
            "ALTER TABLE risk ADD CONSTRAINT chk_probability_level_range "
            "CHECK ((card->>'probability_level') IS NULL OR (card->>'probability_level')::int BETWEEN 1 AND 5)"
        )
    )
    connection.execute(
        text(
            "ALTER TABLE risk ADD CONSTRAINT chk_impact_level_range "
            "CHECK ((card->>'impact_level') IS NULL OR (card->>'impact_level')::int BETWEEN 1 AND 5)"
        )
    )
    connection.execute(
        text(
            "ALTER TABLE risk ADD CONSTRAINT chk_operational_priority_range "
            "CHECK ((card->>'operational_priority') IS NULL OR (card->>'operational_priority')::int BETWEEN 1 AND 5)"
        )
    )
    connection.execute(
        text(
            "ALTER TABLE risk ADD CONSTRAINT chk_itot_boundary_vocab "
            "CHECK ((card->>'it_ot_boundary') IS NULL OR (card->>'it_ot_boundary') IN "
            "('it_only','it_historian_dmz_input','itot_actuation','itot_readonly_no_actuation',"
            "'itot_virtual_sensor','ot_direct_execution','itot_advisory_readonly'))"
        )
    )


risk_card_index = Index("risk_card_gin_idx", Risk.card, postgresql_using="gin", postgresql_ops={"card": "jsonb_path_ops"})


@event.listens_for(Risk.__table__, "after_create")
def create_risk_update_trigger(target, connection, **kw):
    if connection.dialect.name != "postgresql":
        return
    connection.execute(
        text(
            """
            CREATE OR REPLACE FUNCTION set_updated_at()
            RETURNS TRIGGER AS $$
            BEGIN
                NEW.updated_at = NOW();
                RETURN NEW;
            END;
            $$ LANGUAGE plpgsql;

            CREATE TRIGGER trg_set_updated_at
            BEFORE UPDATE ON risk
            FOR EACH ROW
            EXECUTE PROCEDURE set_updated_at();
            """
        )
    )


@event.listens_for(Risk.__table__, "after_drop")
def drop_risk_update_trigger(target, connection, **kw):
    if connection.dialect.name != "postgresql":
        return
    connection.execute(
        text(
            """
            DROP TRIGGER IF EXISTS trg_set_updated_at ON risk;
            DROP FUNCTION IF EXISTS set_updated_at();
            """
        )
    )
