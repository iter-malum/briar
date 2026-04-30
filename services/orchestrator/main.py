# FILE: services/orchestrator/main.py (FULLY FIXED)
import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))

from fastapi import FastAPI, Depends, HTTPException
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import selectinload
from sqlalchemy import select
from uuid import uuid4
import json

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
    
    try:
        scan_id = uuid4()
        scan = ScanORM(
            id=scan_id,
            target_url=str(payload.target_url).rstrip('/'),
            config={"tools": payload.tools, "auth_session_id": str(payload.auth_session_id) if payload.auth_session_id else None}
        )
        session.add(scan)
        await session.flush()

        for tool in payload.tools:
            step = ScanStepORM(scan_id=scan.id, tool=tool, status=ScanStatus.pending)
            session.add(step)
        
        await session.commit()
        await session.refresh(scan, [ScanORM.steps])
        
        # 🚀 ЗАПУСК ПЕРВОГО ЭТАПА ПЛАЙПЛАЙНА
        # Если запрошен Katana, отправляем задачу на краулинг
        # В будущем здесь может быть более сложный планировщик
        if "katana" in payload.tools:
            await publisher.publish("scan.crawl.katana", {
                "event": "scan.crawl.katana",
                "scan_id": str(scan.id),
                "target": str(payload.target_url).rstrip('/'),
                "auth_session_id": str(payload.auth_session_id) if payload.auth_session_id else None,
                "tools_remaining": [t for t in payload.tools if t != "katana"]
            })
            logger.info(f"Published scan.crawl.katana for scan {scan.id}")
        elif "nuclei" in payload.tools:
            # Если Katana не нужна, сразу сканируем ядром
            await publisher.publish("scan.dast.nuclei", {
                "event": "scan.dast.nuclei",
                "scan_id": str(scan.id),
                "target": str(payload.target_url).rstrip('/'),
                "auth_session_id": str(payload.auth_session_id) if payload.auth_session_id else None,
                "tools_remaining": [t for t in payload.tools if t != "nuclei"]
            })
            logger.info(f"Published scan.dast.nuclei for scan {scan.id}")
        
        logger.info(f"Scan {scan.id} created and pipeline initiated.")
        return scan
        
    except Exception as e:
        await session.rollback()
        logger.error(f"Failed to create scan: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Scan creation failed: {str(e)}")

@app.get("/scans/{scan_id}", response_model=ScanResponse)
async def get_scan(scan_id: str, session: AsyncSession = Depends(get_db)):
    try:
        stmt = select(ScanORM).options(selectinload(ScanORM.steps)).where(ScanORM.id == scan_id)
        res = await session.execute(stmt)
        scan = res.scalars().first()
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
        return scan
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get scan {scan_id}: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Failed to retrieve scan: {str(e)}")

@app.get("/health")
async def healthcheck():
    return {"status": "healthy", "service": "orchestrator"}