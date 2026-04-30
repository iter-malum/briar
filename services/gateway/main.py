import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))

from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse
from jose import jwt, JWTError
import httpx
import time
from collections import defaultdict
from shared.config import settings
from shared.logger import setup_logger

logger = setup_logger("api-gateway")
app = FastAPI(title="Briar API Gateway", version="0.1.0")

# Simple in-memory rate limiter
RATE_LIMIT_PER_MIN = 120
rate_limit_store = defaultdict(list)

async def verify_token(request: Request):
    if request.url.path == "/health" or request.url.path == "/docs" or request.url.path == "/openapi.json":
        return
    auth_header = request.headers.get("Authorization")
    if not auth_header:
        raise HTTPException(status_code=401, detail="Missing Authorization header")
    try:
        scheme, token = auth_header.split(" ", 1)
        if scheme.lower() != "bearer":
            raise HTTPException(status_code=401, detail="Invalid auth scheme")
        jwt.decode(token, settings.JWT_SECRET, algorithms=[settings.JWT_ALGORITHM])
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    except ValueError:
        raise HTTPException(status_code=401, detail="Invalid Authorization header format")

@app.middleware("http")
async def gateway_middleware(request: Request, call_next):
    # Skip auth/rate limit for health/docs
    if request.url.path in ("/health", "/docs", "/openapi.json", "/redoc"):
        response = await call_next(request)
        return response

    # Rate Limiting
    client_ip = request.client.host
    now = time.time()
    rate_limit_store[client_ip] = [t for t in rate_limit_store[client_ip] if now - t < 60]
    if len(rate_limit_store[client_ip]) >= RATE_LIMIT_PER_MIN:
        return JSONResponse(status_code=429, content={"detail": "Too Many Requests. Try again in a minute."})
    rate_limit_store[client_ip].append(now)

    await verify_token(request)

    # Proxy to Orchestrator
    target_path = request.url.path.replace("/api/v1", "/api/v1", 1)
    target_url = f"{settings.ORCHESTRATOR_URL}{target_path}"
    if request.url.query:
        target_url += f"?{request.url.query}"

    headers = {k: v for k, v in request.headers.items() if k.lower() not in ("host", "content-length", "transfer-encoding")}
    body = await request.body()

    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.request(
                method=request.method,
                url=target_url,
                headers=headers,
                content=body,
            )
        return JSONResponse(status_code=resp.status_code, content=resp.json())
    except httpx.RequestError as e:
        logger.error(f"Proxy error to {target_url}: {e}")
        return JSONResponse(status_code=502, content={"detail": "Upstream service unreachable"})
    except Exception as e:
        logger.error(f"Unexpected gateway error: {e}")
        return JSONResponse(status_code=500, content={"detail": "Internal Gateway Error"})

@app.get("/health")
async def health():
    return {"status": "healthy", "service": "gateway"}
