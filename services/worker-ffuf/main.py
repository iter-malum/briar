"""FFUF Fuzzer Worker"""

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
logger = logging.getLogger("ffuf-worker")

class FFUFWorker(BaseWorker):
    def __init__(self):
        super().__init__(
            tool_name="ffuf",
            queue_name="scan.fuzz.ffuf"
        )
        self.timeout = int(os.getenv("FFUF_TIMEOUT", "1200"))  # 20 минут
        self.rate = int(os.getenv("FFUF_RATE", "1000"))
        self.threads = int(os.getenv("FFUF_THREADS", "40"))
        self.wordlist = os.getenv("FFUF_WORDLIST", "/usr/share/seclists/Discovery/Web-Content/common.txt")

    async def execute_tool(self, target: str, auth_context: Dict[str, Any], task_payload: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Запуск FFUF фаззера"""
        # Базовая команда
        cmd = [
            "ffuf",
            "-u", f"{target}/FUZZ",
            "-w", self.wordlist,
            "-json",
            "-rate", str(self.rate),
            "-t", str(self.threads),
            "-maxtime", str(self.timeout),
            "-recursion",
            "-recursion-depth", "2",
            "-s"
        ]
        
        # Заголовки аутентификации
        headers = auth_context.get("headers", {})
        if headers:
            for key, value in headers.items():
                cmd.extend(["-H", f"{key}: {value}"])
        
        # Cookies
        cookies = auth_context.get("cookies", [])
        if cookies:
            cookie_header = "; ".join([f"{c['name']}={c['value']}" for c in cookies])
            cmd.extend(["-H", f"Cookie: {cookie_header}"])
        
        # Фильтры из payload
        if task_payload.get("filter_size"):
            cmd.extend(["-fs", task_payload["filter_size"]])
        if task_payload.get("filter_words"):
            cmd.extend(["-fw", task_payload["filter_words"]])
        if task_payload.get("filter_status"):
            cmd.extend(["-fc", task_payload["filter_status"]])
        
        # Match условия
        if task_payload.get("match_status"):
            cmd.extend(["-mc", task_payload["match_status"]])
        else:
            cmd.extend(["-mc", "200,204,301,302,307,401,403,500"])
        
        logger.info(f"Starting FFUF fuzz: {' '.join(cmd[:10])}...")
        
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd="/tmp/ffuf"
            )
            
            results = []
            stdout_future = self._read_stream(process.stdout, results)
            stderr_future = self._read_stream(process.stderr, None, is_stderr=True)
            
            await asyncio.wait_for(
                asyncio.gather(stdout_future, stderr_future, process.wait()),
                timeout=self.timeout
            )
            
            if process.returncode != 0:
                logger.warning(f"FFUF exited with code {process.returncode}")
            
            logger.info(f"FFUF found {len(results)} interesting paths")
            return results
            
        except asyncio.TimeoutError:
            logger.error(f"FFUF timed out after {self.timeout} seconds")
            process.kill()
            await process.wait()
            return []
        except Exception as e:
            logger.error(f"FFUF execution failed: {e}")
            return []

    async def _read_stream(self, stream, results_list, is_stderr=False):
        """Чтение потока вывода FFUF"""
        while True:
            line = await stream.readline()
            if not line:
                break
            
            line_str = line.decode('utf-8').strip()
            if not line_str:
                continue
                
            if is_stderr:
                logger.debug(f"FFUF stderr: {line_str}")
                continue
                
            try:
                data = json.loads(line_str)
                
                # FFUF возвращает результаты в формате JSONL
                if "input" in data and "status" in data:
                    status_code = data.get("status", 0)
                    url = data.get("input", {}).get("FUZZ", "")
                    full_url = f"{data.get('input', {}).get('FUZZ', '')}"
                    
                    # Определяем severity на основе статуса ответа
                    severity = SeverityLevel.info
                    if status_code in [403, 401]:
                        severity = SeverityLevel.low
                    elif status_code == 500:
                        severity = SeverityLevel.medium
                    elif status_code in [200, 204]:
                        severity = SeverityLevel.info
                    
                    result = {
                        "url": f"{data.get('input', {}).get('FUZZ', '')}",
                        "type": "directory_file",
                        "description": f"Found path with status {status_code}, size {data.get('length', 0)} bytes",
                        "severity": severity,
                        "status_code": status_code,
                        "content_length": data.get("length", 0),
                        "word": data.get("input", {}).get("FUZZ", ""),
                        "raw_output": {
                            "status": status_code,
                            "length": data.get("length"),
                            "content_type": data.get("content_type"),
                            "redirectlocation": data.get("redirectlocation"),
                            "url": data.get("url"),
                            "duration": data.get("duration"),
                            "resultfile": data.get("resultfile"),
                            "host": data.get("host")
                        }
                    }
                    results_list.append(result)
                
            except json.JSONDecodeError:
                logger.debug(f"Failed to parse FFUF output: {line_str}")
                continue

async def main():
    worker = FFUFWorker()
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