from pathlib import Path

from sqlalchemy import create_engine, inspect
from sqlalchemy.orm import DeclarativeBase, sessionmaker

from app.core.config import settings

connect_args = {"check_same_thread": False} if settings.database_url.startswith("sqlite") else {}
engine = create_engine(settings.database_url, connect_args=connect_args)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


class Base(DeclarativeBase):
    pass


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def _alembic_config():
    """Build an Alembic Config bound to the application's database URL.

    Imported lazily so non-migration code paths don't pay the alembic import
    cost.
    """
    from alembic.config import Config

    here = Path(__file__).resolve().parents[2]  # backend/
    cfg = Config(str(here / "alembic.ini"))
    cfg.set_main_option("script_location", str(here / "alembic"))
    cfg.set_main_option("sqlalchemy.url", settings.database_url)
    return cfg


def _has_legacy_schema() -> bool:
    """Return True if the DB already contains SNPanel tables but has never
    been stamped by Alembic. This is the case for servers that ran the old
    apply_simple_migrations() bootstrap before we adopted Alembic."""
    inspector = inspect(engine)
    return inspector.has_table("users") and not inspector.has_table("alembic_version")


def run_migrations() -> None:
    """Bring the schema up to date with the latest Alembic revision.

    - Fresh install (empty DB): runs every migration from 0001 onwards.
    - Legacy install (tables exist, alembic_version absent): stamps the DB
      to '0001_initial' (matching the schema as it existed before Alembic),
      then upgrades to head. No DDL is replayed for tables that already
      exist with the correct columns.
    - Already-managed install: upgrades from current revision to head.
    """
    from alembic import command

    cfg = _alembic_config()
    if _has_legacy_schema():
        command.stamp(cfg, "0001_initial")
    command.upgrade(cfg, "head")
