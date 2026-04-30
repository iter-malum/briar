# FILE: shared/worker_base.py (COMPLETE PRODUCTION VERSION)
import asyncio
import json
import os
import sys
import logging
import signal
from typing import Dict, Any, List, Optional
from uuid import UUID
from abc import ABC, abstractmethod
from datetime import datetime

import aio_pika
import httpx
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy import select

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))

from shared.config import settings
from shared.models import ScanResultORM, SeverityLevel, ScanStatus, ScanStepORM

logger = logging.getLogger("worker-base")


class BaseWorker(ABC):
    """Базовый класс для всех сканер-воркеров"""
    
    def __init__(self, tool_name: str, queue_name: str):
        self.tool_name = tool_name
        self.queue_name = queue_name
        self.connection = None
        self.channel = None
        self.queue = None
        self.running = False
        
        self._init_db()
        self._init_http_client()
        self.auth_service_url = os.getenv("AUTH_SERVICE_URL", "http://auth-service:8000")

    def _init_db(self):
        self.engine = create_async_engine(
            settings.db_url, 
            pool_size=10, 
            max_overflow=20,
            pool_recycle=3600
        )
        self.session_factory = async_sessionmaker(self.engine, class_=AsyncSession, expire_on_commit=False)

    def _init_http_client(self):
        self.http_client = httpx.AsyncClient(
            timeout=30.0,
            follow_redirects=True,
            limits=httpx.Limits(max_connections=50)
        )

    async def start(self):
        logger.info(f"Starting {self.tool_name} worker...")
        await self._connect_rabbitmq()
        await self._start_consuming()
        self.running = True
        logger.info(f"Worker {self.tool_name} is ready and listening on queue: {self.queue_name}")

    async def _connect_rabbitmq(self):
        retry_count = 0
        max_retries = 10
        
        while retry_count < max_retries:
            try:
                self.connection = await aio_pika.connect_robust(
                    settings.rabbitmq_url,
                    heartbeat=600,
                    blocked_connection_timeout=300,
                )
                self.channel = await self.connection.channel()
                await self.channel.set_qos(prefetch_count=1)
                
                exchange = await self.channel.declare_exchange(
                    "briar.scan",
                    aio_pika.ExchangeType.DIRECT,
                    durable=True
                )
                
                self.queue = await self.channel.declare_queue(
                    self.queue_name,
                    durable=True,
                    arguments={"x-message-ttl": 86400000}
                )
                
                # ✅ КЛЮЧЕВОЙ ФИКС: явный биндинг
                await self.queue.bind(exchange, routing_key=self.queue_name)
                
                logger.info(f"Queue '{self.queue_name}' bound to exchange 'briar.scan'")
                return
            except Exception as e:
                retry_count += 1
                wait_time = min(2 ** retry_count, 30)
                logger.error(f"RabbitMQ attempt {retry_count}/{max_retries} failed: {e}")
                await asyncio.sleep(wait_time)
        
        raise ConnectionError(f"Failed to connect to RabbitMQ after {max_retries} attempts")

    async def _start_consuming(self):
        await self.queue.consume(self._on_message)
        loop = asyncio.get_event_loop()
        for sig in (signal.SIGTERM, signal.SIGINT):
            loop.add_signal_handler(sig, lambda: asyncio.create_task(self.shutdown()))

    async def _on_message(self, message: aio_pika.IncomingMessage):
        async with message.process(ignore_processed=True):
            try:
                body = json.loads(message.body.decode())
                scan_id = body.get("scan_id")
                logger.info(f"[{self.tool_name}] Processing task for scan: {scan_id}")
                
                timeout = int(os.getenv("WORKER_TIMEOUT", "300"))
                await asyncio.wait_for(self._process_task(body), timeout=timeout)
                
                await message.ack()
                logger.info(f"[{self.tool_name}] Task completed for scan: {scan_id}")
                
            except asyncio.TimeoutError:
                logger.error(f"[{self.tool_name}] Task timed out for scan: {body.get('scan_id')}")
                await self._update_scan_step_status(body.get("scan_id"), ScanStatus.failed)
            except Exception as e:
                logger.error(f"[{self.tool_name}] Error: {e}", exc_info=True)

    async def _process_task(self, payload: Dict[str, Any]):
        """Основная логика с поддержкой цепочек"""
        scan_id = payload["scan_id"]
        target = payload.get("target", "")
        auth_session_id = payload.get("auth_session_id")
        task_payload = payload.get("payload", {})
        
        try:
            # ✅ 1. Ждём зависимости если указано
            wait_for = task_payload.get("wait_for_tools", [])
            if wait_for:
                logger.info(f"[{self.tool_name}] Waiting for tools: {wait_for}")
                await self._wait_for_dependencies(scan_id, wait_for, max_wait=30)
            
            # ✅ 2. Загружаем эндпоинты от источника (КАТАНА → ХТТПХ)
            source_tool = task_payload.get("source_tool")
            endpoints = []
            
            if source_tool:
                endpoints = await self._get_endpoints_from_db(scan_id, source_tool)
                logger.info(f"[{self.tool_name}] Loaded {len(endpoints)} endpoints from {source_tool}")
                if endpoints:
                    task_payload["endpoints"] = endpoints
            
            # ✅ 3. Если всё ещё нет эндпоинтов — используем target
            if not task_payload.get("endpoints") and target:
                task_payload["endpoints"] = [target]
                logger.info(f"[{self.tool_name}] Using target as fallback: {target}")
            
            # ✅ 4. Обновляем статус
            await self._update_scan_step_status(scan_id, ScanStatus.running)
            
            # ✅ 5. Выполняем инструмент
            auth_context = await self._get_auth_context(auth_session_id)
            results = await self.execute_tool(target, auth_context, task_payload)
            
            # ✅ 6. Сохраняем результаты
            await self._save_results(scan_id, results)
            
            # ✅ 7. Обновляем статус
            await self._update_scan_step_status(scan_id, ScanStatus.completed)
            
            logger.info(f"[{self.tool_name}] Done: {len(results)} results")
            
        except Exception as e:
            logger.error(f"[{self.tool_name}] Task failed: {e}", exc_info=True)
            await self._update_scan_step_status(scan_id, ScanStatus.failed)

    async def _wait_for_dependencies(self, scan_id: str, wait_for_tools: List[str], max_wait: int = 30) -> bool:
        """Ждёт завершения указанных инструментов"""
        if not wait_for_tools:
            return True
        
        for attempt in range(max_wait // 5):
            async with self.session_factory() as session:
                stmt = select(ScanStepORM.tool, ScanStepORM.status).where(
                    ScanStepORM.scan_id == UUID(scan_id),
                    ScanStepORM.tool.in_(wait_for_tools)
                )
                result = await session.execute(stmt)
                steps = {row.tool: row.status for row in result.all()}
                
                if all(s in [ScanStatus.completed, ScanStatus.failed] for s in steps.values()) and len(steps) >= len(wait_for_tools):
                    logger.info(f"[{self.tool_name}] Dependencies ready: {steps}")
                    return True
            await asyncio.sleep(5)
        
        logger.warning(f"[{self.tool_name}] Timeout waiting for {wait_for_tools}")
        return False

    async def _get_endpoints_from_db(self, scan_id: str, source_tool: str) -> List[str]:
        """Получает эндпоинты из БД от указанного инструмента"""
        try:
            async with self.session_factory() as session:
                stmt = select(ScanResultORM.url).where(
                    ScanResultORM.scan_id == UUID(scan_id),
                    ScanResultORM.tool == source_tool,
                    ScanResultORM.url.isnot(None),
                    ScanResultORM.url != ''
                )
                result = await session.execute(stmt)
                endpoints = [url for url in result.scalars().all() if url and url.startswith('http')]
                return endpoints
        except Exception as e:
            logger.error(f"[{self.tool_name}] Failed to get endpoints: {e}")
            return []

    async def _get_auth_context(self, session_id: Optional[str]) -> Dict[str, Any]:
        if not session_id:
            return {"cookies": [], "headers": {}}
        try:
            async with self.http_client as client:
                resp = await client.get(f"{self.auth_service_url}/api/v1/auth/sessions/{session_id}")
                if resp.status_code == 200:
                    data = resp.json()
                    return {
                        "cookies": data.get("cookies", []),
                        "headers": data.get("headers", {}),
                        "storage_state": data.get("storage_state", "")
                    }
        except Exception as e:
            logger.warning(f"Failed to get auth context: {e}")
        return {"cookies": [], "headers": {}}

    async def _update_scan_step_status(self, scan_id: str, status: ScanStatus):
        try:
            async with self.session_factory() as session:
                stmt = select(ScanStepORM).where(
                    ScanStepORM.scan_id == UUID(scan_id),
                    ScanStepORM.tool == self.tool_name
                )
                result = await session.execute(stmt)
                step = result.scalars().first()
                if step:
                    step.status = status
                    now = datetime.utcnow()
                    if status == ScanStatus.running and not step.started_at:
                        step.started_at = now
                    elif status in [ScanStatus.completed, ScanStatus.failed] and not step.finished_at:
                        step.finished_at = now
                    await session.commit()
        except Exception as e:
            logger.error(f"Failed to update step status: {e}")

    async def _save_results(self, scan_id: str, results: List[Dict[str, Any]]):
        if not results:
            return
        async with self.session_factory() as session:
            items = []
            for res in results:
                item = ScanResultORM(
                    scan_id=UUID(scan_id),
                    tool=self.tool_name,
                    severity=res.get("severity", SeverityLevel.info),
                    url=res.get("url"),
                    vulnerability_type=res.get("type"),
                    description=res.get("description", ""),
                    raw_output=res.get("raw_output", {})
                )
                items.append(item)
            session.add_all(items)
            await session.commit()
            logger.info(f"[{self.tool_name}] Saved {len(items)} results")

    @abstractmethod
    async def execute_tool(self, target: str, auth_context: Dict[str, Any], task_payload: Dict[str, Any]) -> List[Dict[str, Any]]:
        pass

    async def shutdown(self):
        logger.info(f"Shutting down {self.tool_name}...")
        self.running = False
        if self.connection and not self.connection.is_closed:
            await self.connection.close()
        await self.http_client.aclose()
        await self.engine.dispose()