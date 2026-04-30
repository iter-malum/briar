# FILE: services/worker-katana/main.py
import sys
import os
import asyncio
import json
import subprocess
import logging

# Путь к shared
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))

from shared.worker import BaseWorker
from shared.config import settings
from shared.models import SeverityLevel

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("katana-worker")

class KatanaWorker(BaseWorker):
    def __init__(self):
        super().__init__(tool_name="katana", queue_name="scan.crawl.katana")

    async def execute_tool(self, target: str, auth_headers: Dict[str, str], task_payload: Dict[str, Any]) -> List[Dict]:
        cmd = [
            "katana", "-u", target, 
            "-json", "-o", "stdout",
            "-depth", "3" # Глубина краулинга
        ]
        
        # Добавляем заголовки если есть
        for k, v in auth_headers.items():
            cmd.extend(["-H", f"{k}: {v}"])
            
        logger.info(f"Running Katana: {' '.join(cmd)}")
        
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        results = []
        stdout, stderr = await process.communicate()
        
        if process.returncode == 0:
            for line in stdout.decode().splitlines():
                try:
                    data = json.loads(line)
                    # Нормализация результата Katana
                    results.append({
                        "url": data.get("request", {}).get("url"),
                        "type": "endpoint",
                        "description": f"Discovered endpoint via {data.get('request', {}).get('method', 'GET')}",
                        "severity": SeverityLevel.info,
                        "method": data.get("request", {}).get("method")
                    })
                except json.JSONDecodeError:
                    continue
        else:
            logger.error(f"Katana failed: {stderr.decode()}")
            
        return results

async def main():
    worker = KatanaWorker()
    await worker.start()
    try:
        await asyncio.Future() # Блокировка навсегда
    except asyncio.CancelledError:
        logger.info("Worker shutting down...")

if __name__ == "__main__":
    asyncio.run(main())