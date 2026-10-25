"""
SCOUT Database Engine and Session Factory
Thread-safe SQLite engine with WAL journaling and enforced foreign keys.
"""

import os
from pathlib import Path
from contextlib import contextmanager
from typing import Generator
from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine
from sqlalchemy.orm import sessionmaker, Session

from .models import Base

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
INSTANCE_DIR = PROJECT_ROOT / "instance"
INSTANCE_DIR.mkdir(parents=True, exist_ok=True)

DEFAULT_DB_PATH = INSTANCE_DIR / "scout.db"
SCOUT_DB_PATH = Path(os.environ.get("SCOUT_DB_PATH", str(DEFAULT_DB_PATH)))

_engine: Engine = None
_SessionFactory: sessionmaker = None


@event.listens_for(Engine, "connect")
def _set_sqlite_pragmas(dbapi_connection, connection_record):
    """Enforces SQLite foreign keys and WAL performance mode on every connection."""
    try:
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys = ON;")
        cursor.execute("PRAGMA journal_mode = WAL;")
        cursor.execute("PRAGMA synchronous = NORMAL;")
        cursor.close()
    except Exception:
        pass


def get_engine(db_path: Path = None, reset: bool = False) -> Engine:
    """Returns or creates the singleton SQLAlchemy SQLite engine."""
    global _engine, _SessionFactory
    if _engine is None or db_path is not None or reset:
        target_path = Path(db_path) if db_path else SCOUT_DB_PATH
        target_path.parent.mkdir(parents=True, exist_ok=True)
        db_uri = f"sqlite:///{target_path.as_posix()}"
        engine = create_engine(
            db_uri,
            echo=False,
            future=True,
            connect_args={"check_same_thread": False, "timeout": 30.0}
        )
        factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False, future=True)
        _engine = engine
        _SessionFactory = factory
        return engine
    return _engine


def get_session_factory(engine: Engine = None) -> sessionmaker:
    """Returns the configured SessionFactory or one bound to the specified engine."""
    global _SessionFactory
    if engine is not None:
        return sessionmaker(bind=engine, autoflush=False, expire_on_commit=False, future=True)
    if _SessionFactory is None:
        get_engine()
    return _SessionFactory


@contextmanager
def get_db_session(engine: Engine = None) -> Generator[Session, None, None]:
    """
    Context manager providing a transactional database session.
    Automatically commits on normal exit and rolls back on unhandled exceptions.
    """
    factory = get_session_factory(engine=engine)
    session = factory()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def init_db(engine_override: Engine = None) -> None:
    """Creates all database tables registered with Base.metadata if they do not exist."""
    try:
        import modules.subscriptions.models  # Register subscription models with Base.metadata
    except ImportError:
        pass
    engine = engine_override or get_engine()
    Base.metadata.create_all(bind=engine)
