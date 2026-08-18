from sqlalchemy import inspect
from sqlalchemy.orm import Session

from app.core.vocab import CATEGORY_DEFINITIONS, ENERGY_CONTEXT_DEFINITIONS, get_category_display_name, get_context_display_name
from app.db.models import Base, Category, EnergyContext
from app.db import session as db_session


def init_db() -> None:
    # Look up the engine on the module (not `from app.db.session import engine`):
    # tests reassign app.db.session.engine at runtime via configure_engine(), and a
    # name imported at module load time would keep pointing at the original engine.
    inspector = inspect(db_session.engine)
    Base.metadata.create_all(bind=db_session.engine)
    _seed_reference_tables()


def _seed_reference_tables() -> None:
    with Session(db_session.engine) as session:
        for category_id, meta in CATEGORY_DEFINITIONS.items():
            if session.get(Category, category_id):
                continue
            session.add(
                Category(
                    category_id=category_id,
                    name=get_category_display_name(category_id),
                    description=meta.get("description"),
                    parent_category_id=meta.get("parent"),
                )
            )
        for context_id, meta in ENERGY_CONTEXT_DEFINITIONS.items():
            if session.get(EnergyContext, context_id):
                continue
            session.add(
                EnergyContext(
                    context_id=context_id,
                    name=get_context_display_name(context_id),
                    description=meta.get("description"),
                    criticality_level=meta.get("criticality", 3),
                )
            )
        session.commit()


if __name__ == "__main__":
    init_db()

