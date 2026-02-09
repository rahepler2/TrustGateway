"""
Database session management.
"""
import logging

from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker, scoped_session

from .config import DATABASE_URL
from .models import Base

log = logging.getLogger("trust-gateway")

engine = create_engine(DATABASE_URL, pool_pre_ping=True, pool_size=5, max_overflow=10)
SessionLocal = scoped_session(sessionmaker(bind=engine, autoflush=False, autocommit=False))


def create_tables():
    Base.metadata.create_all(bind=engine)
    # Migrate existing json columns to jsonb (needed for jsonb_* Grafana queries)
    try:
        with engine.begin() as conn:
            conn.execute(text(
                "ALTER TABLE jobs ALTER COLUMN result TYPE jsonb USING result::jsonb"
            ))
            log.info("Migrated jobs.result column to jsonb")
    except Exception as e:
        log.debug(f"jsonb migration skipped (already migrated or new table): {e}")
