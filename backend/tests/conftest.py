"""Global test configuration and fixtures.

Guarantees all tests run against disposable in-memory databases with zero residue.
"""

import os

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

# Force in-memory database and test environment before any module imports
os.environ["CYBERQ_DATABASE_URL"] = "sqlite:///:memory:"
os.environ["CYBERQ_ENV"] = "demo"
os.environ["CYBERQ_AUDIT_SIGNING_SEED"] = (
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
)

import cyberq.audit.models  # noqa: F401
import cyberq.clocks.models  # noqa: F401
import cyberq.iam.models  # noqa: F401
import cyberq.incidents.models  # noqa: F401
from cyberq.api.app import app
from cyberq.core.database import Base, get_db, install_audit_immutability_triggers


@pytest.fixture(autouse=True)
def isolated_db():
    """Provides a fresh, isolated in-memory SQLite database for every test.

    Ensures zero disk residue, installs audit triggers, and tears down completely.
    """
    test_engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=test_engine)
    install_audit_immutability_triggers(test_engine)
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)

    def _get_test_db():
        db = TestingSessionLocal()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = _get_test_db

    yield TestingSessionLocal

    app.dependency_overrides.clear()
    Base.metadata.drop_all(bind=test_engine)
    test_engine.dispose()


def pytest_collection_modifyitems(config, items):
    pg_url = os.environ.get("CYBERQ_TEST_PG_URL")
    if not pg_url:
        skip_pg = pytest.mark.skip(
            reason="CYBERQ_TEST_PG_URL not set; real PostgreSQL 16 database required"
        )
        for item in items:
            if "postgres" in item.keywords:
                item.add_marker(skip_pg)
