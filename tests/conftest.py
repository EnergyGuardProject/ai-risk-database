import os
from pathlib import Path
from typing import Generator

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text

from app.core import config
from app.db import session as session_module
from app.db.init_db import init_db
from app.main import create_app


@pytest.fixture(scope="session", autouse=True)
def configure_test_environment(tmp_path_factory: pytest.TempPathFactory) -> Generator[None, None, None]:
    db_path = tmp_path_factory.mktemp("data") / "test.db"
    export_dir = tmp_path_factory.mktemp("exports")
    config.reload_settings(database_url=f"sqlite:///{db_path}", export_dir=str(export_dir))
    session_module.configure_engine(config.settings.database_url)
    init_db()
    yield
    # Cleanup
    if Path(db_path).exists():
        os.remove(db_path)


@pytest.fixture()
def client() -> Generator[TestClient, None, None]:
    app = create_app()
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture(autouse=True)
def cleanup_db() -> Generator[None, None, None]:
    yield
    with session_module.get_session() as session:
        session.execute(text("DELETE FROM risk_relationship"))
        session.execute(text("DELETE FROM risk_use_case"))
        session.execute(text("DELETE FROM risk_context"))
        session.execute(text("DELETE FROM risk_category"))
        session.execute(text("DELETE FROM risk"))
