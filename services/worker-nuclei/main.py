# FILE: services/worker-nuclei/main.py
import sys
import os
import asyncio
import json
import subprocess
import logging

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))

from shared.worker import BaseWorker
from shared.models import SeverityLevel

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("nuclei-worker")

class NucleiWorker(BaseWorker):
    def __init__(self):
        super().__init__(tool_name="nuclei", queue_name="scan.dast.nuclei")

    async def execute_tool(self, target: str, auth_headers: Dict[str, str], task_payload: Dict[str, Any]) -> List[Dict]:
        cmd = ["nuclei", "-u", target, "-jsonl", "-silent"]
        
        # Nuclei принимает заголовки через -H
        for k, v in auth_headers.items():
            cmd.extend(["-H", f"{k}: {v}"])
            
        # Опционально: указание конкретных темплейтов
        if "templates" in task_payload:
            cmd.extend(["-t", ",".join(task_payload["templates"])])
            
        logger.info(f"Running Nuclei: {' '.join(cmd)}")
        
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        results = []
        stdout, stderr = await process.communicate()
        
        # Nuclei jsonl output
        for line in stdout.decode().splitlines():
            try:
                data = json.loads(line)
                # Mapping Nuclei severity to our enum
                sev_str = data.get("info", {}).get("severity", "info").lower()
                sev_map = {"critical": SeverityLevel.critical, "high": SeverityLevel.high, "medium": SeverityLevel.medium, "low": SeverityLevel.low}
                
                results.append({
                    "url": data.get("matched-at", target),
                    "type": data.get("template-id"),
                    "description": data.get("info", {}).get("name"),
                    "severity": sev_map.get(sev_str, SeverityLevel.info),
                    "matcher_name": data.get("matcher-name"),
                    "extracted_results": data.get("extracted-results")
                })
            except json.JSONDecodeError:
                continue
                
        return results

async def main():
    worker = NucleiWorker()
    await worker.start()
    try:
        await asyncio.Future()
    except asyncio.CancelledError:
        pass

if __name__ == "__main__":
    asyncio.run(main())