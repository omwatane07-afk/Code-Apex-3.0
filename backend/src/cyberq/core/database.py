"""Database connection and session management using SQLAlchemy 2."""

import contextlib
from collections.abc import Generator
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import DateTime, TypeDecorator, create_engine, event, text
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from cyberq.core.config import get_settings


class Base(DeclarativeBase):
    """Base class for all SQLAlchemy ORM models."""

    pass


class UTCDateTime(TypeDecorator[datetime]):
    """DateTime type that guarantees offset-aware UTC datetimes across SQLite and PostgreSQL."""

    impl = DateTime(timezone=True)
    cache_ok = True

    def process_result_value(self, value: Any, dialect: Any) -> datetime | None:
        if value is None:
            return None
        if isinstance(value, datetime):
            if value.tzinfo is None:
                return value.replace(tzinfo=UTC)
            return value.astimezone(UTC)
        if isinstance(value, str):
            dt = datetime.fromisoformat(value)
            return dt if dt.tzinfo else dt.replace(tzinfo=UTC)
        return None

    def process_bind_param(self, value: Any, dialect: Any) -> datetime | None:
        if value is None:
            return None
        if isinstance(value, datetime):
            if value.tzinfo is None:
                return value.replace(tzinfo=UTC)
            return value.astimezone(UTC)
        return None



settings = get_settings()

connect_args: dict[str, Any] = {}
if settings.DATABASE_URL.startswith("sqlite"):
    connect_args["check_same_thread"] = False

engine = create_engine(
    settings.DATABASE_URL,
    connect_args=connect_args,
    pool_pre_ping=True,
)

SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine,
    expire_on_commit=False,
)


def get_db() -> Generator[Session, None, None]:
    """Dependency that yields a database session and ensures clean closure."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@contextlib.contextmanager
def db_session() -> Generator[Session, None, None]:
    """Context manager for non-request database transactions."""
    session = SessionLocal()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def install_audit_immutability_triggers(target_engine: Any) -> None:
    """Installs database-level triggers preventing raw UPDATE and DELETE on audit_event."""
    dialect = target_engine.dialect.name
    with target_engine.connect() as conn:
        if dialect == "sqlite":
            conn.execute(
                text("""
                CREATE TRIGGER IF NOT EXISTS prevent_audit_event_update
                BEFORE UPDATE ON audit_event
                BEGIN
                    SELECT RAISE(FAIL, 'audit_event is append-only: cannot modify audit_event');
                END;
            """)
            )
            conn.execute(
                text("""
                CREATE TRIGGER IF NOT EXISTS prevent_audit_event_delete
                BEFORE DELETE ON audit_event
                BEGIN
                    SELECT RAISE(FAIL, 'audit_event is append-only: cannot delete from audit_event');
                END;
            """)
            )
            conn.execute(
                text("""
                CREATE TRIGGER IF NOT EXISTS prevent_audit_event_replace
                BEFORE INSERT ON audit_event
                WHEN EXISTS (SELECT 1 FROM audit_event WHERE id = NEW.id OR sequence_number = NEW.sequence_number)
                BEGIN
                    SELECT RAISE(FAIL, 'audit_event is append-only: cannot replace or overwrite existing audit_event rows');
                END;
            """)
            )
            conn.execute(
                text("""
                CREATE TRIGGER IF NOT EXISTS prevent_audit_checkpoint_update
                BEFORE UPDATE ON audit_checkpoint
                BEGIN
                    SELECT RAISE(FAIL, 'audit_checkpoint is append-only: cannot modify audit_checkpoint');
                END;
            """)
            )
            conn.execute(
                text("""
                CREATE TRIGGER IF NOT EXISTS prevent_audit_checkpoint_delete
                BEFORE DELETE ON audit_checkpoint
                BEGIN
                    SELECT RAISE(FAIL, 'audit_checkpoint is append-only: cannot delete from audit_checkpoint');
                END;
            """)
            )
            conn.execute(
                text("""
                CREATE TRIGGER IF NOT EXISTS prevent_audit_checkpoint_replace
                BEFORE INSERT ON audit_checkpoint
                WHEN EXISTS (SELECT 1 FROM audit_checkpoint WHERE id = NEW.id OR sequence_number = NEW.sequence_number)
                BEGIN
                    SELECT RAISE(FAIL, 'audit_checkpoint is append-only: cannot replace or overwrite existing audit_checkpoint rows');
                END;
            """)
            )
            conn.commit()
        elif dialect == "postgresql":
            conn.execute(
                text("""
                CREATE OR REPLACE FUNCTION prevent_audit_mutation()
                RETURNS TRIGGER AS $$
                BEGIN
                    RAISE EXCEPTION 'Audit tables are append-only: modifications and deletions are strictly forbidden';
                END;
                $$ LANGUAGE plpgsql;

                CREATE OR REPLACE FUNCTION prevent_audit_truncate()
                RETURNS TRIGGER AS $$
                BEGIN
                    RAISE EXCEPTION 'Audit tables are append-only: TRUNCATE is strictly forbidden';
                END;
                $$ LANGUAGE plpgsql;
            """)
            )
            conn.execute(
                text("""
                DO $$
                BEGIN
                    IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'trg_prevent_audit_event_mutation') THEN
                        CREATE TRIGGER trg_prevent_audit_event_mutation
                        BEFORE UPDATE OR DELETE ON audit_event
                        FOR EACH ROW EXECUTE FUNCTION prevent_audit_mutation();
                    END IF;
                    IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'trg_prevent_audit_checkpoint_mutation') THEN
                        CREATE TRIGGER trg_prevent_audit_checkpoint_mutation
                        BEFORE UPDATE OR DELETE ON audit_checkpoint
                        FOR EACH ROW EXECUTE FUNCTION prevent_audit_mutation();
                    END IF;
                    IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'trg_prevent_audit_event_truncate') THEN
                        CREATE TRIGGER trg_prevent_audit_event_truncate
                        BEFORE TRUNCATE ON audit_event
                        FOR EACH STATEMENT EXECUTE FUNCTION prevent_audit_truncate();
                    END IF;
                    IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'trg_prevent_audit_checkpoint_truncate') THEN
                        CREATE TRIGGER trg_prevent_audit_checkpoint_truncate
                        BEFORE TRUNCATE ON audit_checkpoint
                        FOR EACH STATEMENT EXECUTE FUNCTION prevent_audit_truncate();
                    END IF;
                END $$;
            """)
            )
            conn.commit()


@event.listens_for(Base.metadata, "after_create")
def receive_after_create(target: Any, connection: Any, **kw: Any) -> None:
    install_audit_immutability_triggers(connection.engine)


def init_db() -> None:
    """Create all registered tables and install database immutability triggers."""
    import cyberq.audit.models  # noqa: F401
    import cyberq.clocks.models  # noqa: F401
    import cyberq.filings.models  # noqa: F401
    import cyberq.governance.models  # noqa: F401
    import cyberq.iam.models  # noqa: F401
    import cyberq.incidents.models  # noqa: F401
    import cyberq.intake.models  # noqa: F401

    Base.metadata.create_all(bind=engine)
    install_audit_immutability_triggers(engine)
