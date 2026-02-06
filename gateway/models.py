"""
ORM models for job/batch persistence (PostgreSQL).
"""
from datetime import datetime
import enum
import uuid

from sqlalchemy import Column, String, Integer, DateTime, Enum, ForeignKey
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import declarative_base, relationship

Base = declarative_base()


class JobStatus(str, enum.Enum):
    submitted = "submitted"
    queued = "queued"
    running = "running"
    done = "done"
    failed = "failed"
    cancelled = "cancelled"


class BatchStatus(str, enum.Enum):
    submitted = "submitted"
    running = "running"
    done = "done"
    error = "error"


class Batch(Base):
    __tablename__ = "batches"
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    status = Column(Enum(BatchStatus), default=BatchStatus.submitted, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    finished_at = Column(DateTime, nullable=True)
    jobs = relationship("Job", back_populates="batch")


class Job(Base):
    __tablename__ = "jobs"
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    package = Column(String(255), nullable=False)
    version = Column(String(64), nullable=False)
    ecosystem = Column(String(32), default="pypi", nullable=False)
    status = Column(Enum(JobStatus), default=JobStatus.submitted, nullable=False)
    attempts = Column(Integer, default=0)
    result = Column(JSONB, nullable=True)
    report_url = Column(String(1024), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    started_at = Column(DateTime, nullable=True)
    finished_at = Column(DateTime, nullable=True)
    batch_id = Column(String(36), ForeignKey("batches.id"), nullable=True)
    batch = relationship("Batch", back_populates="jobs")
