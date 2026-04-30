"""Nuclei Vulnerability Scanner Worker"""

import asyncio
import json
import logging
import sys
import os
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
logger = logging.getLogger("nuclei-worker")

SEVERITY_MAP = {
    "critical": SeverityLevel.critical,
    "high": SeverityLevel.high,
    "medium": SeverityLevel.medium,
    "low": SeverityLevel.low,
    "info": SeverityLevel.info
}

class NucleiWorker(BaseWorker):
    def __init__(self):
        super().__init__(
            tool_name="nuclei",
            queue_name="scan.dast.nuclei"
        )
        self.timeout = int(os.getenv("NUCLEI_TIMEOUT", "1800"))  # 30 минут
        self.rate_limit = int(os.getenv("NUCLEI_RATE_LIMIT", "100"))
        self.concurrency = int(os.getenv("NUCLEI_CONCURRENCY", "25"))

    async def execute_tool(self, target: str, auth_context: Dict[str, Any], task_payload: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Запуск Nuclei сканера"""
        cmd = [
            "nuclei",
            "-u", target,
            "-jsonl",
            "-silent",
            "-rate-limit", str(self.rate_limit),
            "-c", str(self.concurrency),
            "-timeout", "30"
        ]
        
        # Добавляем заголовки аутентификации
        headers = auth_context.get("headers", {})
        if headers:
            for key, value in headers.items():
                cmd.extend(["-H", f"{key}: {value}"])
        
        # Cookies
        cookies = auth_context.get("cookies", [])
        if cookies:
            cookie_header = "; ".join([f"{c['name']}={c['value']}" for c in cookies])
            cmd.extend(["-H", f"Cookie: {cookie_header}"])
        
        # Дополнительные параметры
        if task_payload.get("templates"):
            templates = ",".join(task_payload["templates"])
            cmd.extend(["-t", templates])
        
        if task_payload.get("severity_filter"):
            cmd.extend(["-s", task_payload["severity_filter"]])
        
        if task_payload.get("tags"):
            cmd.extend(["-tags", ",".join(task_payload["tags"])])
            
        if task_payload.get("exclude_tags"):
            cmd.extend(["-exclude-tags", ",".join(task_payload["exclude_tags"])])
        
        logger.info(f"Starting Nuclei scan: {' '.join(cmd[:10])}...")
        
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd="/tmp/nuclei"
            )
            
            results = []
            stdout_future = self._read_stream(process.stdout, results)
            stderr_future = self._read_stream(process.stderr, None, is_stderr=True)
            
            await asyncio.wait_for(
                asyncio.gather(stdout_future, stderr_future, process.wait()),
                timeout=self.timeout
            )
            
            if process.returncode != 0:
                logger.warning(f"Nuclei exited with code {process.returncode}")
            
            logger.info(f"Nuclei found {len(results)} vulnerabilities")
            return results
            
        except asyncio.TimeoutError:
            logger.error(f"Nuclei timed out after {self.timeout} seconds")
            process.kill()
            await process.wait()
            return []
        except Exception as e:
            logger.error(f"Nuclei execution failed: {e}")
            return []

    async def _read_stream(self, stream, results_list, is_stderr=False):
        """Чтение потока вывода Nuclei"""
        while True:
            line = await stream.readline()
            if not line:
                break
            
            line_str = line.decode('utf-8').strip()
            if not line_str:
                continue
                
            if is_stderr:
                logger.debug(f"Nuclei stderr: {line_str}")
                continue
                
            try:
                data = json.loads(line_str)
                info = data.get("info", {})
                severity_str = info.get("severity", "info").lower()
                
                result = {
                    "url": data.get("matched-at", ""),
                    "type": data.get("template-id", ""),
                    "description": info.get("name", ""),
                    "severity": SEVERITY_MAP.get(severity_str, SeverityLevel.info),
                    "matcher_name": data.get("matcher-name", ""),
                    "extracted_results": data.get("extracted-results", []),
                    "raw_output": {
                        "template-id": data.get("template-id"),
                        "template-path": data.get("template-path"),
                        "info": info,
                        "matcher-name": data.get("matcher-name"),
                        "extracted-results": data.get("extracted-results"),
                        "curl-command": data.get("curl-command"),
                        "timestamp": data.get("timestamp", datetime.utcnow().isoformat())
                    }
                }
                results_list.append(result)
                
            except json.JSONDecodeError:
                logger.debug(f"Failed to parse Nuclei output: {line_str}")
                continue

async def main():
    worker = NucleiWorker()
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