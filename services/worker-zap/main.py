"""OWASP ZAP Scanner Worker"""

import asyncio
import json
import logging
import sys
import os
import subprocess
from typing import Dict, Any, List
from datetime import datetime

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))

from shared.worker_base import BaseWorker
from shared.models import SeverityLevel

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s | %(levelname)-8s | %(name)s | %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger("zap-worker")

class ZAPWorker(BaseWorker):
    def __init__(self):
        super().__init__(
            tool_name="zap",
            queue_name="scan.dast.zap"
        )
        self.timeout = int(os.getenv("ZAP_TIMEOUT", "3600"))  # 1 час
        self.zap_port = int(os.getenv("ZAP_PORT", "8090"))
        self.zap_api_key = os.getenv("ZAP_API_KEY", "changeme")
        self.max_duration = int(os.getenv("ZAP_MAX_DURATION", "30"))  # минут на active scan

    async def execute_tool(self, target: str, auth_context: Dict[str, Any], task_payload: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Запуск OWASP ZAP сканера"""
        zap_results = []
        zap_process = None
        
        try:
            # 1. Запускаем ZAP в режиме демона
            cmd_start = [
                "/zap/zap.sh",
                "-daemon",
                "-port", str(self.zap_port),
                "-host", "0.0.0.0",
                "-config", f"api.key={self.zap_api_key}",
                "-config", "api.disablekey=false",
                "-config", "spider.maxDuration=5",
                "-config", "scanner.maxDuration=10"
            ]
            
            logger.info(f"Starting ZAP daemon: {' '.join(cmd_start)}")
            zap_process = await asyncio.create_subprocess_exec(
                *cmd_start,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            # Ждем запуска ZAP
            await asyncio.sleep(15)
            
            # 2. Загружаем сессию аутентификации если есть
            if auth_context.get("cookies") or auth_context.get("headers"):
                await self._load_auth_context(target, auth_context)
            
            # 3. Запускаем Spider
            spider_scan_id = await self._start_spider(target)
            await self._wait_for_scan_completion(spider_scan_id, "spider")
            
            # 4. Запускаем Active Scan
            active_scan_id = await self._start_active_scan(target)
            await self._wait_for_scan_completion(active_scan_id, "active_scan")
            
            # 5. Получаем результаты
            zap_results = await self._get_alerts(target)
            
            logger.info(f"ZAP scan completed, found {len(zap_results)} alerts")
            return zap_results
            
        except Exception as e:
            logger.error(f"ZAP execution failed: {e}", exc_info=True)
            return []
        finally:
            # Останавливаем ZAP
            if zap_process:
                zap_process.terminate()
                try:
                    await asyncio.wait_for(zap_process.wait(), timeout=10)
                except asyncio.TimeoutError:
                    zap_process.kill()

    async def _load_auth_context(self, target: str, auth_context: Dict[str, Any]):
        """Загрузка контекста аутентификации в ZAP"""
        try:
            # Сохраняем cookies в файл
            cookies_file = "/tmp/zap/cookies.txt"
            os.makedirs(os.path.dirname(cookies_file), exist_ok=True)
            
            cookies = auth_context.get("cookies", [])
            if cookies:
                with open(cookies_file, 'w') as f:
                    for cookie in cookies:
                        f.write(f"{cookie['domain']}\tTRUE\t{cookie.get('path', '/')}\tFALSE\t0\t{cookie['name']}\t{cookie['value']}\n")
                
                # Импортируем cookies
                import httpx
                async with httpx.AsyncClient() as client:
                    resp = await client.post(
                        f"http://localhost:{self.zap_port}/JSON/core/action/importCookies/",
                        params={
                            "apikey": self.zap_api_key,
                            "cookieFile": cookies_file
                        }
                    )
                    logger.info(f"ZAP cookies import response: {resp.json()}")
            
            # Добавляем заголовки
            headers = auth_context.get("headers", {})
            if headers:
                async with httpx.AsyncClient() as client:
                    for name, value in headers.items():
                        await client.post(
                            f"http://localhost:{self.zap_port}/JSON/core/action/addGlobalHeader/",
                            params={
                                "apikey": self.zap_api_key,
                                "name": name,
                                "value": value,
                                "enabled": "true"
                            }
                        )
        except Exception as e:
            logger.warning(f"Failed to load auth context into ZAP: {e}")

    async def _start_spider(self, target: str) -> str:
        """Запуск Spider сканирования"""
        import httpx
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                f"http://localhost:{self.zap_port}/JSON/spider/action/scan/",
                params={
                    "apikey": self.zap_api_key,
                    "url": target
                }
            )
            data = resp.json()
            return data.get("scan", "")

    async def _start_active_scan(self, target: str) -> str:
        """Запуск Active сканирования"""
        import httpx
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                f"http://localhost:{self.zap_port}/JSON/ascan/action/scan/",
                params={
                    "apikey": self.zap_api_key,
                    "url": target
                }
            )
            data = resp.json()
            return data.get("scan", "")

    async def _wait_for_scan_completion(self, scan_id: str, scan_type: str):
        """Ожидание завершения сканирования"""
        import httpx
        max_wait = self.timeout
        waited = 0
        
        while waited < max_wait:
            await asyncio.sleep(30)
            waited += 30
            
            async with httpx.AsyncClient() as client:
                resp = await client.get(
                    f"http://localhost:{self.zap_port}/JSON/{scan_type}/view/status/",
                    params={"apikey": self.zap_api_key, "scanId": scan_id}
                )
                status = resp.json().get("status", "100")
                
                if status == "100":
                    logger.info(f"{scan_type} scan completed")
                    return
                
                logger.info(f"{scan_type} scan progress: {status}%")
        
        logger.warning(f"{scan_type} scan timed out after {max_wait} seconds")

    async def _get_alerts(self, target: str) -> List[Dict[str, Any]]:
        """Получение алертов из ZAP"""
        import httpx
        alerts = []
        
        try:
            async with httpx.AsyncClient() as client:
                resp = await client.get(
                    f"http://localhost:{self.zap_port}/JSON/core/view/alerts/",
                    params={
                        "apikey": self.zap_api_key,
                        "baseurl": target
                    }
                )
                data = resp.json()
                
                for alert in data.get("alerts", []):
                    risk = alert.get("risk", "Informational")
                    severity_map = {
                        "High": SeverityLevel.high,
                        "Medium": SeverityLevel.medium,
                        "Low": SeverityLevel.low,
                        "Informational": SeverityLevel.info
                    }
                    
                    alerts.append({
                        "url": alert.get("url", target),
                        "type": alert.get("pluginId", ""),
                        "description": alert.get("description", ""),
                        "severity": severity_map.get(risk, SeverityLevel.info),
                        "solution": alert.get("solution", ""),
                        "reference": alert.get("reference", ""),
                        "cwe_id": alert.get("cweid", ""),
                        "wasc_id": alert.get("wascid", ""),
                        "raw_output": alert
                    })
        except Exception as e:
            logger.error(f"Failed to get ZAP alerts: {e}")
        
        return alerts

async def main():
    worker = ZAPWorker()
    await worker.start()
    
    try:
        while worker.running:
            await asyncio.sleep(1)
    except KeyboardInterrupt:
        logger.info("Received shutdown signal")
    finally:
        await worker.shutdown()

if __name__ == "__main__":
    asyncio.run(main())