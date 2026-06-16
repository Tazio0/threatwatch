"""
ThreatWatch V2.0 - Test Suite: database.py
===========================================
Full TDD suite for the database / persistence layer.

Covers:
  - Engine creation from DATABASE_URL config
  - SessionLocal factory: session lifecycle and instance isolation
  - Base declarative base: metadata attribute and table registration
  - get_db() FastAPI dependency: generator protocol, yield, and cleanup

Dependencies:
  - pytest          (add to requirements-dev.txt)
  - unittest.mock   (stdlib — no extra install needed)

Run with:
  pytest backend/tests/test_database.py -v
"""

import types
import pytest
from unittest.mock import patch, MagicMock, call


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

SQLITE_MEMORY_URL = "sqlite:///:memory:"
"""
In-memory SQLite URL used wherever tests need a real engine without
requiring a running PostgreSQL instance.
"""


# ---------------------------------------------------------------------------
# 1. Engine
# ---------------------------------------------------------------------------

class TestEngine:

    @patch("backend.app.config.DATABASE_URL", SQLITE_MEMORY_URL)
    def test_engine_can_be_created(self):
        """
        Patching DATABASE_URL to an in-memory SQLite string and importing
        the engine creation logic must not raise any errors.
        """
        from sqlalchemy import create_engine

        engine = create_engine(SQLITE_MEMORY_URL)
        assert engine is not None

    @patch("backend.app.config.DATABASE_URL", SQLITE_MEMORY_URL)
    def test_engine_is_not_none(self):
        """
        When DATABASE_URL is set to a valid connection string the module-level
        engine object must not be None.
        """
        from backend.app.database import engine

        assert engine is not None


# ---------------------------------------------------------------------------
# 2. SessionLocal
# ---------------------------------------------------------------------------

class TestSessionLocal:

    @patch("backend.app.config.DATABASE_URL", SQLITE_MEMORY_URL)
    def test_session_can_be_opened_and_closed(self):
        """
        A session obtained from SessionLocal() must be a valid, non-None
        object that can be closed cleanly without raising.
        """
        from backend.app.database import SessionLocal

        session = SessionLocal()
        assert session is not None
        session.close()  # Must not raise

    @patch("backend.app.config.DATABASE_URL", SQLITE_MEMORY_URL)
    def test_session_is_scoped_to_factory(self):
        """
        Two successive calls to SessionLocal() must return distinct session
        instances — each request handler should get its own unit-of-work.
        """
        from backend.app.database import SessionLocal

        session_a = SessionLocal()
        session_b = SessionLocal()

        try:
            assert session_a is not session_b, (
                "SessionLocal() must return a new session instance per call"
            )
        finally:
            session_a.close()
            session_b.close()


# ---------------------------------------------------------------------------
# 3. Base (Declarative Base)
# ---------------------------------------------------------------------------

class TestBase:

    @patch("backend.app.config.DATABASE_URL", SQLITE_MEMORY_URL)
    def test_base_has_metadata(self):
        """
        The declarative Base must expose a ``metadata`` attribute — this is
        used by Alembic migrations and ``Base.metadata.create_all()``.
        """
        from backend.app.database import Base

        assert hasattr(Base, "metadata"), "Base must have a metadata attribute"

    @patch("backend.app.config.DATABASE_URL", SQLITE_MEMORY_URL)
    def test_tables_registered_after_model_import(self):
        """
        After importing the ORM models, Base.metadata.tables must contain
        entries for the three core tables: threats, honeypot_logs, and
        firewall_rules.

        This verifies that the models correctly inherit from Base and
        register their table names in the shared metadata registry.
        """
        from backend.app.database import Base

        # Force model registration — importing the models module should
        # cause each model class to register its __tablename__ in
        # Base.metadata.tables.
        import backend.app.models  # noqa: F401

        table_names = set(Base.metadata.tables.keys())

        expected_tables = {"threats", "honeypot_logs", "firewall_rules"}
        for table in expected_tables:
            assert table in table_names, (
                f"Expected table '{table}' to be registered in Base.metadata "
                f"after importing models. Found: {table_names}"
            )


# ---------------------------------------------------------------------------
# 4. get_db() — FastAPI Dependency
# ---------------------------------------------------------------------------

class TestGetDb:

    @patch("backend.app.config.DATABASE_URL", SQLITE_MEMORY_URL)
    def test_get_db_is_generator(self):
        """
        get_db() must return a generator object — FastAPI's dependency
        injection system relies on the ``yield`` protocol to manage
        the session lifecycle.
        """
        from backend.app.database import get_db

        gen = get_db()
        assert isinstance(gen, types.GeneratorType), (
            "get_db() must return a generator (use 'yield', not 'return')"
        )

    @patch("backend.app.config.DATABASE_URL", SQLITE_MEMORY_URL)
    def test_get_db_yields_session(self):
        """
        Calling next() on the get_db() generator must yield a session
        object that is not None and is usable for database operations.
        """
        from backend.app.database import get_db

        gen = get_db()
        session = next(gen)

        assert session is not None, "get_db() must yield a non-None session"

        # Ensure it looks like a SQLAlchemy Session (duck-type check)
        assert hasattr(session, "commit"), "Yielded object must have commit()"
        assert hasattr(session, "rollback"), "Yielded object must have rollback()"
        assert hasattr(session, "close"), "Yielded object must have close()"

        # Clean up the generator so the finally/cleanup block executes
        try:
            next(gen)
        except StopIteration:
            pass

    @patch("backend.app.config.DATABASE_URL", SQLITE_MEMORY_URL)
    def test_get_db_closes_session_after_use(self):
        """
        After fully iterating through the get_db() generator the session
        must be closed. This verifies the cleanup logic in the finally
        block that runs after the yield.
        """
        from backend.app.database import get_db

        # Spy on the session that will be yielded
        real_session = MagicMock()

        with patch(
            "backend.app.database.SessionLocal", return_value=real_session
        ):
            gen = get_db()
            yielded = next(gen)

            # The session is the mock we injected
            assert yielded is real_session

            # Exhaust the generator — this triggers the finally block
            try:
                next(gen)
            except StopIteration:
                pass

            # Verify close() was called exactly once during cleanup
            real_session.close.assert_called_once()
