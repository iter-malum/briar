import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))

from fastapi import FastAPI, Depends, HTTPException, BackgroundTasks
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import selectinload
from sqlalchemy import select
from shared.config import settings
from shared.models import Base, ScanORM, ScanStepORM, ScanStatus, ScanCreateRequest, ScanResponse
from shared.rabbitmq import RabbitMQPublisher
from shared.logger import setup_logger

logger = setup_logger("orchestrator")
app = FastAPI(title="Briar Orchestrator", version="0.1.0", root_path="/api/v1")

engine = create_async_engine(settings.db_url, echo=False, pool_size=10, max_overflow=20)
async_session = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
publisher = RabbitMQPublisher()

@app.on_event("startup")
async def startup():
    logger.info("Initializing PostgreSQL tables...")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    await publisher.connect()
    logger.info("Orchestrator service ready.")

@app.on_event("shutdown")
async def shutdown():
    await publisher.close()

async def get_db():
    async with async_session() as session:
        try:
            yield session
        finally:
            await session.close()

@app.post("/scans", response_model=ScanResponse, status_code=201)
async def create_scan(payload: ScanCreateRequest, session: AsyncSession = Depends(get_db)):
    logger.info(f"Received scan request for {payload.target_url}")
    
    scan = ScanORM(
        target_url=str(payload.target_url),
        config={"tools": payload.tools, "auth_session_id": str(payload.auth_session_id) if payload.auth_session_id else None}
    )
    session.add(scan)
    await session.flush()

    for tool in payload.tools:
        step = ScanStepORM(scan_id=scan.id, tool=tool, status=ScanStatus.pending)
        session.add(step)
    
    await session.commit()
    await session.refresh(scan, [ScanORM.steps])

    # Publish event to RabbitMQ
    await publisher.publish("scan.created", {
        "event": "scan.created",
        "scan_id": str(scan.id),
        "target_url": scan.target_url,
        "tools": payload.tools,
        "auth_session_id": payload.auth_session_id
    })
    
    logger.info(f"Scan {scan.id} created and queued for execution.")
    return scan

@app.get("/scans/{scan_id}", response_model=ScanResponse)
async def get_scan(scan_id: str, session: AsyncSession = Depends(get_db)):
    stmt = select(ScanORM).options(selectinload(ScanORM.steps)).where(ScanORM.id == scan_id)
    res = await session.execute(stmt)
    scan = res.scalars().first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan

@app.get("/health")
async def healthcheck():
    return {"status": "healthy", "service": "orchestrator"}