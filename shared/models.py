from pydantic import BaseModel, Field, HttpUrl, ConfigDict
from typing import List, Optional, Dict, Any
from datetime import datetime
from uuid import UUID
from sqlalchemy.orm import DeclarativeBase, relationship, Mapped, mapped_column
from sqlalchemy import Column, String, DateTime, JSON, Enum as SAEnum, ForeignKey, func
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
import enum

Base = DeclarativeBase

class ScanStatus(str, enum.Enum):
    pending = "pending"
    running = "running"
    completed = "completed"
    failed = "failed"

# Pydantic v2 Models
class ScanStepResponse(BaseModel):
    tool: str
    status: str
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None

class ScanCreateRequest(BaseModel):
    model_config = ConfigDict(json_schema_extra={"example": {"target_url": "https://example.com", "auth_session_id": None, "tools": ["katana", "nuclei"]}})
    target_url: HttpUrl
    auth_session_id: Optional[UUID] = None
    tools: List[str] = Field(default=["katana", "nuclei"])

class ScanResponse(BaseModel):
    id: UUID
    target_url: str
    status: str
    created_at: datetime
    updated_at: datetime
    config: Dict[str, Any]
    steps: List[ScanStepResponse]

# SQLAlchemy ORM Models
class ScanORM(Base):
    __tablename__ = "scans"
    id = Column(PG_UUID(as_uuid=True), primary_key=True, default=func.gen_random_uuid)
    target_url = Column(String(2048), nullable=False)
    status = Column(SAEnum(ScanStatus), default=ScanStatus.pending)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    config = Column(JSON, default=dict, nullable=False)
    steps = relationship("ScanStepORM", back_populates="scan", lazy="selectin")

class ScanStepORM(Base):
    __tablename__ = "scan_steps"
    id = Column(PG_UUID(as_uuid=True), primary_key=True, default=func.gen_random_uuid)
    scan_id = Column(PG_UUID(as_uuid=True), ForeignKey("scans.id"), nullable=False)
    tool = Column(String(50), nullable=False)
    status = Column(SAEnum(ScanStatus), default=ScanStatus.pending)
    started_at = Column(DateTime(timezone=True), nullable=True)
    finished_at = Column(DateTime(timezone=True), nullable=True)
    scan = relationship("ScanORM", back_populates="steps")