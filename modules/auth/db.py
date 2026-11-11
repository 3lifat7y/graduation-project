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

def get_db_path() -> Path:
    """Returns the effective database path from environment or default."""
    return Path(os.environ.get("SCOUT_DB_PATH", str(DEFAULT_DB_PATH)))

SCOUT_DB_PATH = get_db_path()

_engine: Engine = None
_SessionFactory: sessionmaker = None
_current_engine_path: Path = None


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
    global _engine, _SessionFactory, _current_engine_path
    target_path = Path(db_path) if db_path else get_db_path()
    if _engine is None or db_path is not None or reset or _current_engine_path != target_path:
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
        _current_engine_path = target_path
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
    """Creates all database tables registered with Base.metadata if they do not exist and runs safe migrations."""
    try:
        import modules.subscriptions.models  # Register subscription models with Base.metadata
    except ImportError:
        pass
    engine = engine_override or get_engine()
    Base.metadata.create_all(bind=engine)

    # Safe automated schema migration: Ensure phone_number column and unique index exist without data loss
    try:
        with engine.connect() as conn:
            result = conn.exec_driver_sql("PRAGMA table_info(users);").fetchall()
            columns = [row[1] for row in result]
            if columns and "phone_number" not in columns:
                conn.exec_driver_sql("ALTER TABLE users ADD COLUMN phone_number VARCHAR(30);")
                conn.commit()
            if columns:
                conn.exec_driver_sql("CREATE UNIQUE INDEX IF NOT EXISTS ix_users_phone_number ON users (phone_number);")
                conn.commit()

            # Ensure manual payment columns on user_subscriptions exist
            sub_res = conn.exec_driver_sql("PRAGMA table_info(user_subscriptions);").fetchall()
            sub_cols = [row[1] for row in sub_res]
            if sub_cols:
                migration_columns = [
                    ("payment_method_id", "INTEGER"),
                    ("receiving_account_id", "INTEGER"),
                    ("payment_amount", "FLOAT"),
                    ("payment_currency", "VARCHAR(10)"),
                    ("payment_status", "VARCHAR(30) DEFAULT 'none'"),
                    ("payment_method_name_snapshot", "VARCHAR(100)"),
                    ("payment_method_type_snapshot", "VARCHAR(50)"),
                    ("receiving_account_identifier_snapshot", "VARCHAR(100)"),
                    ("receiving_account_holder_snapshot", "VARCHAR(100)"),
                    ("plan_name_snapshot", "VARCHAR(100)"),
                    ("plan_price_snapshot", "FLOAT"),
                    ("receipt_filename", "VARCHAR(255)"),
                    ("receipt_original_name", "VARCHAR(255)"),
                    ("receipt_content_type", "VARCHAR(50)"),
                    ("receipt_file_size", "INTEGER"),
                    ("transaction_reference", "VARCHAR(100)"),
                    ("payment_notes", "TEXT"),
                    ("rejection_reason", "TEXT")
                ]
                for col_name, col_type in migration_columns:
                    if col_name not in sub_cols:
                        conn.exec_driver_sql(f"ALTER TABLE user_subscriptions ADD COLUMN {col_name} {col_type};")
                conn.commit()

            # Ensure is_free column on subscription_plans exists
            plan_res = conn.exec_driver_sql("PRAGMA table_info(subscription_plans);").fetchall()
            plan_cols = [row[1] for row in plan_res]
            if plan_cols and "is_free" not in plan_cols:
                conn.exec_driver_sql("ALTER TABLE subscription_plans ADD COLUMN is_free BOOLEAN DEFAULT 0;")
                conn.exec_driver_sql("CREATE INDEX IF NOT EXISTS ix_subscription_plans_is_free ON subscription_plans (is_free);")
                conn.commit()
    except Exception:
        pass

    # Ensure default payment methods if table is empty
    try:
        from modules.subscriptions.models import PaymentMethod, PaymentReceivingAccount
        factory = get_session_factory(engine=engine)
        with factory() as session:
            if session.query(PaymentMethod).count() == 0:
                instapay = PaymentMethod(
                    name="instapay",
                    display_name="InstaPay",
                    description="Instant bank transfer via Egyptian Banks & InstaPay Network.",
                    instructions="Open your InstaPay app, select Transfer to Mobile Number or IPA, enter the amount, and save the payment receipt screenshot.",
                    provider_type="instapay",
                    logo_icon="fas fa-bolt",
                    is_active=True,
                    display_order=1
                )
                session.add(instapay)
                session.flush()

                session.add(PaymentReceivingAccount(
                    payment_method_id=instapay.id,
                    account_identifier="01012345678",
                    account_holder_name="SCOUT Operations Hub",
                    description="Primary Corporate Mobile IPA",
                    is_active=True,
                    display_order=1
                ))
                session.add(PaymentReceivingAccount(
                    payment_method_id=instapay.id,
                    account_identifier="scout@instapay",
                    account_holder_name="SCOUT Security Systems",
                    description="Instant Payment Address (IPA)",
                    is_active=True,
                    display_order=2
                ))

                vodafone = PaymentMethod(
                    name="vodafone-cash",
                    display_name="Vodafone Cash",
                    description="Electronic wallet transfer via Vodafone Cash Egypt.",
                    instructions="Dial *9*7*Number*Amount# or use the Ana Vodafone app to transfer money. Take a screenshot of the transfer confirmation message.",
                    provider_type="vodafone_cash",
                    logo_icon="fas fa-wallet",
                    is_active=True,
                    display_order=2
                )
                session.add(vodafone)
                session.flush()

                session.add(PaymentReceivingAccount(
                    payment_method_id=vodafone.id,
                    account_identifier="01098765432",
                    account_holder_name="SCOUT Billing Desk",
                    description="Official Vodafone Cash Wallet",
                    is_active=True,
                    display_order=1
                ))

                session.commit()
    except Exception:
        pass

