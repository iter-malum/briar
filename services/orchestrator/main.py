# FILE: services/orchestrator/main.py (COMPLETE PRODUCTION VERSION)
import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))

from fastapi import FastAPI, Depends, HTTPException
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import selectinload
from sqlalchemy import select
from uuid import uuid4, UUID  # ✅ ИМПОРТ UUID - КРИТИЧЕСКИ ВАЖНО!
import json
import logging

from shared.config import settings
from shared.models import Base, ScanORM, ScanStepORM, ScanStatus, ScanCreateRequest, ScanResponse, ScanResultORM
from shared.rabbitmq import RabbitMQPublisher

# Настройка логгера
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s | %(levelname)-8s | %(name)s | %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger("orchestrator")

app = FastAPI(title="Briar Orchestrator", version="0.1.0", root_path="/api/v1")

# Инициализация БД
engine = create_async_engine(
    settings.db_url, 
    echo=False, 
    pool_size=10, 
    max_overflow=20,
    pool_recycle=3600
)
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
    await engine.dispose()

async def get_db():
    async with async_session() as session:
        try:
            yield session
        finally:
            await session.close()


# ============================================================================
# ВСПОМОГАТЕЛЬНАЯ ФУНКЦИЯ: Публикация задач с учётом зависимостей
# ============================================================================
async def _publish_chained_tasks(scan_id: UUID, payload: ScanCreateRequest, pub: RabbitMQPublisher):
    """
    Публикует задачи для воркеров с учётом зависимостей:
    - katana: независимая, запускается сразу
    - httpx/nuclei/ffuf: зависимые, получают эндпоинты от katana
    """
    queue_map = {
        "katana": "scan.crawl.katana",
        "nuclei": "scan.dast.nuclei", 
        "ffuf": "scan.fuzz.ffuf",
        "httpx": "scan.probe.httpx",
        "zap": "scan.dast.zap"
    }
    
    source_tools = {"katana"}
    dependent_tools = {"httpx", "nuclei", "ffuf", "zap"}
    
    base_payload = {
        "event": "scan.task.created",
        "scan_id": str(scan_id),
        "target": str(payload.target_url).rstrip('/'),
        "auth_session_id": str(payload.auth_session_id) if payload.auth_session_id else None,
    }
    
    for tool in payload.tools:
        queue_name = queue_map.get(tool)
        if not queue_name:
            logger.warning(f"No queue mapped for tool: {tool}")
            continue
        
        task_payload = base_payload.copy()
        
        if tool in dependent_tools:
            task_payload["payload"] = {
                "wait_for_tools": list(source_tools & set(payload.tools)),
                "source_tool": "katana" if "katana" in payload.tools else None
            }
            logger.info(f"Queued DEPENDENT task for {tool} on {queue_name}")
        else:
            task_payload["payload"] = {}
            logger.info(f"Queued INDEPENDENT task for {tool} on {queue_name}")
        
        await pub.publish(queue_name, task_payload)


# ============================================================================
# ОСНОВНОЙ ЭНДПОИНТ: Создание сканирования
# ============================================================================
@app.post("/scans", response_model=ScanResponse, status_code=201)
async def create_scan(payload: ScanCreateRequest, session: AsyncSession = Depends(get_db)):
    logger.info(f"Received scan request for {payload.target_url}")
    
    try:
        scan_id = uuid4()
        
        scan = ScanORM(
            id=scan_id,
            target_url=str(payload.target_url).rstrip('/'),
            config={
                "tools": payload.tools, 
                "auth_session_id": str(payload.auth_session_id) if payload.auth_session_id else None
            }
        )
        session.add(scan)
        await session.flush()
        
        for tool in payload.tools:
            step = ScanStepORM(
                scan_id=scan.id,
                tool=tool,
                status=ScanStatus.pending
            )
            session.add(step)
        
        await session.commit()
        
        # Загружаем скан с шагами для ответа
        stmt = select(ScanORM).options(
            selectinload(ScanORM.steps)
        ).where(ScanORM.id == scan_id)
        result = await session.execute(stmt)
        scan_with_steps = result.scalars().first()
        
        if not scan_with_steps:
            raise HTTPException(status_code=500, detail="Failed to retrieve created scan")
        
        # Публикуем задачи для воркеров
        await _publish_chained_tasks(scan_id, payload, publisher)
        
        logger.info(f"Scan {scan_id} created and queued for execution.")
        return scan_with_steps
        
    except HTTPException:
        raise
    except Exception as e:
        await session.rollback()
        logger.error(f"Failed to create scan: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Scan creation failed: {str(e)}")


# ============================================================================
# ЭНДПОИНТ: Получение сканирования по ID
# ============================================================================
@app.get("/scans/{scan_id}", response_model=ScanResponse)
async def get_scan(scan_id: str, session: AsyncSession = Depends(get_db)):
    try:
        stmt = select(ScanORM).options(
            selectinload(ScanORM.steps)
        ).where(ScanORM.id == scan_id)
        result = await session.execute(stmt)
        scan = result.scalars().first()
        
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
        return scan
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get scan {scan_id}: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Failed to retrieve scan: {str(e)}")


# ============================================================================
# HEALTH CHECK
# ============================================================================
@app.get("/health")
async def healthcheck():
    return {"status": "healthy", "service": "orchestrator"}