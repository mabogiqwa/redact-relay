from __future__ import annotations

import hashlib
import json
import logging
import os
import secrets
import time
import uuid
from collections import defaultdict, deque
from dataclasses import dataclass, field, asdict
from datetime import datetime, date
from enum import Enum
from typing import Any, Dict, List, Optional

import uvicorn
from fastapi import FastAPI, HTTPException, Depends, Request, Security
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.openapi.utils import get_openapi
from fastapi.responses import JSONResponse
from fastapi.security import APIKeyHeader
from pydantic import BaseModel, Field
from starlette.middleware.base import BaseHTTPMiddleware

from differential_engine import PromptRedactor

logging.basicConfig(
    level=logging.INFO,
    format='{\"time\":\"%(asctime)s\",\"level\":\"%(levelname)s\",\"msg\":\"%(message)s\"}',
)
log = logging.getLogger("redact.api")

ENV = os.getenv("APP_ENV", "development")
MASTER_KEY = os.getenv("APP_MASTER_KEY", "dev-master-key-change-in-prod")

if ENV == "production" and MASTER_KEY == "dev-master-key-change-in-prod":
    raise RuntimeError("APP_MASTER_KEY must be set to a secure value in production.")


class Tier(str, Enum):
    STARTER    = "starter"
    PRO        = "pro"
    ENTERPRISE = "enterprise"

TIER_CONFIG = {
    Tier.STARTER:    {"daily_limit": 1_000,       "rpm": 10,  "price_usd": 0},
    Tier.PRO:        {"daily_limit": 50_000,       "rpm": 120, "price_usd": 99},
    Tier.ENTERPRISE: {"daily_limit": 999_999_999,  "rpm": 600, "price_usd": 0},
}


@dataclass
class APIKey:
    key_hash: str
    tenant_id: str
    tenant_name: str
    tier: Tier
    created_at: float = field(default_factory=time.time)
    active: bool = True
    total_calls: int = 0
    total_entities: int = 0
    daily_calls: Dict[str, int] = field(default_factory=dict)
    _minute_window: deque = field(default_factory=lambda: deque(maxlen=600))

    def today_calls(self) -> int:
        return self.daily_calls.get(str(date.today()), 0)

    def increment(self, entities: int = 0) -> None:
        today = str(date.today())
        self.daily_calls[today] = self.daily_calls.get(today, 0) + 1
        self.total_calls += 1
        self.total_entities += entities
        self._minute_window.append(time.time())

    def check_rate_limit(self) -> tuple[bool, int]:
        now = time.time()
        cutoff = now - 60
        while self._minute_window and self._minute_window[0] < cutoff:
            self._minute_window.popleft()
        rpm_limit = TIER_CONFIG[self.tier]["rpm"]
        current_rpm = len(self._minute_window)
        return current_rpm < rpm_limit, current_rpm

    def check_daily_limit(self) -> tuple[bool, int]:
        limit = TIER_CONFIG[self.tier]["daily_limit"]
        used = self.today_calls()
        return used < limit, used


_KEY_STORE: Dict[str, APIKey] = {}

def _seed_demo_key() -> str:
    raw = "demo-key-replace-in-production"
    h = hashlib.sha256(raw.encode()).hexdigest()
    _KEY_STORE[h] = APIKey(
        key_hash=h,
        tenant_id="demo-tenant",
        tenant_name="Demo",
        tier=Tier.STARTER,
    )
    return raw

DEMO_KEY = _seed_demo_key()

_redactor = PromptRedactor(
    spacy_model=os.getenv("SPACY_MODEL"),
    min_confidence=0.7,
    redact_locations=False,
)

API_KEY_HEADER = APIKeyHeader(name="X-API-Key", auto_error=False)

def get_api_key(raw_key: Optional[str] = Security(API_KEY_HEADER)) -> APIKey:
    if not raw_key:
        raise HTTPException(401, detail={
            "error": "missing_api_key",
            "message": "Include your API key in the X-API-Key header.",
            "docs": "/docs",
        })
    h = hashlib.sha256(raw_key.encode()).hexdigest()
    key = _KEY_STORE.get(h)
    if not key or not key.active:
        raise HTTPException(403, detail={
            "error": "invalid_api_key",
            "message": "API key not recognised or has been revoked.",
        })
    return key


class RateLimitMiddleware(BaseHTTPMiddleware):
    EXEMPT_PATHS = {"/health", "/ready", "/docs", "/openapi.json", "/redoc"}

    async def dispatch(self, request: Request, call_next):
        if request.url.path in self.EXEMPT_PATHS:
            return await call_next(request)

        raw_key = request.headers.get("X-API-Key", "")
        if not raw_key:
            return await call_next(request)

        h = hashlib.sha256(raw_key.encode()).hexdigest()
        key = _KEY_STORE.get(h)
        if not key:
            return await call_next(request)

        daily_ok, daily_used = key.check_daily_limit()
        if not daily_ok:
            limit = TIER_CONFIG[key.tier]["daily_limit"]
            return JSONResponse(status_code=429, content={
                "error": "daily_limit_exceeded",
                "message": f"Daily limit of {limit:,} calls reached for tier '{key.tier}'.",
                "used_today": daily_used,
                "resets": "midnight UTC",
            })

        rpm_ok, current_rpm = key.check_rate_limit()
        if not rpm_ok:
            rpm_limit = TIER_CONFIG[key.tier]["rpm"]
            return JSONResponse(status_code=429, content={
                "error": "rate_limit_exceeded",
                "message": f"Rate limit of {rpm_limit} req/min exceeded.",
                "current_rpm": current_rpm,
                "retry_after_seconds": 60,
            }, headers={"Retry-After": "60"})

        return await call_next(request)


class RedactRequest(BaseModel):
    text: str = Field(..., max_length=50_000)
    session_id: Optional[str] = None
    options: Optional[Dict[str, Any]] = None


class RedactResponse(BaseModel):
    redacted: str
    session_id: str
    entities: Dict[str, int]
    total_entities: int
    placeholders: Dict[str, str]
    latency_ms: float
    tier4_hits: int


class RestoreRequest(BaseModel):
    text: str = Field(..., max_length=100_000)
    session_id: str


class RestoreResponse(BaseModel):
    restored: str
    session_id: str
    unreplaced_placeholders: List[str]


class MessagesRedactRequest(BaseModel):
    messages: List[Dict[str, Any]]
    session_id: Optional[str] = None


class UsageResponse(BaseModel):
    tenant_id: str
    tenant_name: str
    tier: str
    total_calls: int
    total_entities_caught: int
    calls_today: int
    daily_limit: int
    rpm_limit: int
    daily_limit_remaining: int


class AuditLogResponse(BaseModel):
    tenant_id: str
    session_count: int
    note: str


def create_app() -> FastAPI:
    app = FastAPI(
        title="PII Redaction API",
        version="1.0.0",
        docs_url="/docs",
        redoc_url="/redoc",
    )

    app.add_middleware(RateLimitMiddleware)
    app.add_middleware(GZipMiddleware, minimum_size=1000)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"] if ENV != "production" else os.getenv("CORS_ORIGINS", "").split(","),
        allow_methods=["GET", "POST", "DELETE"],
        allow_headers=["X-API-Key", "Content-Type"],
    )

    @app.middleware("http")
    async def log_requests(request: Request, call_next):
        t0 = time.perf_counter()
        response = await call_next(request)
        ms = round((time.perf_counter() - t0) * 1000, 1)
        if request.url.path not in ("/health", "/ready"):
            log.info(f"{request.method} {request.url.path} {response.status_code} {ms}ms")
        return response

    return app


app = create_app()


@app.post("/redact", response_model=RedactResponse, tags=["Redaction"])
async def redact(req: RedactRequest, key: APIKey = Depends(get_api_key)):
    t0 = time.perf_counter()

    session = None
    if req.session_id:
        session = _redactor.get_session(req.session_id)
        if not session:
            raise HTTPException(404, detail={
                "error": "session_not_found",
                "message": f"Session '{req.session_id}' not found or expired.",
            })

    result = _redactor.redact(req.text, session=session)
    ms = round((time.perf_counter() - t0) * 1000, 2)

    tier4 = sum(1 for s in result.spans if s.confidence < 1.0)
    key.increment(entities=sum(result.stats.values()))

    log.info(json.dumps({
        "event": "redact",
        "tenant": key.tenant_id,
        "tier": key.tier,
        "entities": dict(result.stats),
        "latency_ms": ms,
    }))

    return RedactResponse(
        redacted=result.redacted,
        session_id=result.session_id,
        entities=dict(result.stats),
        total_entities=sum(result.stats.values()),
        placeholders=result.replacements,
        latency_ms=ms,
        tier4_hits=tier4,
    )


@app.post("/restore", response_model=RestoreResponse, tags=["Redaction"])
async def restore(req: RestoreRequest, key: APIKey = Depends(get_api_key)):
    import re
    restored = _redactor.restore(req.text, req.session_id)
    unreplaced = re.findall(r'\[[A-Z_]+_\d+\]', restored)

    return RestoreResponse(
        restored=restored,
        session_id=req.session_id,
        unreplaced_placeholders=unreplaced,
    )


@app.post("/redact/messages", response_model=RedactResponse, tags=["Redaction"])
async def redact_messages(req: MessagesRedactRequest, key: APIKey = Depends(get_api_key)):
    t0 = time.perf_counter()
    session = None
    if req.session_id:
        session = _redactor.get_session(req.session_id)

    from collections import Counter
    total_stats: Counter = Counter()
    tier4 = 0
    for msg in req.messages:
        if msg.get("content") and isinstance(msg["content"], str):
            r = _redactor.redact(msg["content"], session=session)
            total_stats.update(r.stats)
            tier4 += sum(1 for s in r.spans if s.confidence < 1.0)

    redacted_msgs, session = _redactor.redact_messages(req.messages, session=session)
    ms = round((time.perf_counter() - t0) * 1000, 2)

    key.increment(entities=sum(total_stats.values()))

    return RedactResponse(
        redacted=json.dumps(redacted_msgs),
        session_id=session.session_id,
        entities=dict(total_stats),
        total_entities=sum(total_stats.values()),
        placeholders=session.vault_snapshot(),
        latency_ms=ms,
        tier4_hits=tier4,
    )


@app.delete("/sessions/{session_id}", tags=["Sessions"])
async def close_session(session_id: str, key: APIKey = Depends(get_api_key)):
    _redactor.close_session(session_id)
    return {"deleted": session_id}


@app.get("/usage", response_model=UsageResponse, tags=["Usage & Audit"])
async def usage(key: APIKey = Depends(get_api_key)):
    cfg = TIER_CONFIG[key.tier]
    return UsageResponse(
        tenant_id=key.tenant_id,
        tenant_name=key.tenant_name,
        tier=key.tier,
        total_calls=key.total_calls,
        total_entities_caught=key.total_entities,
        calls_today=key.today_calls(),
        daily_limit=cfg["daily_limit"],
        rpm_limit=cfg["rpm"],
        daily_limit_remaining=max(0, cfg["daily_limit"] - key.today_calls()),
    )


@app.get("/audit", response_model=AuditLogResponse, tags=["Usage & Audit"])
async def audit(key: APIKey = Depends(get_api_key)):
    active_sessions = sum(
        1 for sid, s in _redactor._sessions.items()
        if hasattr(s, "session_id")
    )
    return AuditLogResponse(
        tenant_id=key.tenant_id,
        session_count=active_sessions,
        note=(
            "Entity types and call metadata are logged only. "
            "Original PII values are held in-memory for the session lifetime only and "
            "never persisted to disk or logs."
        ),
    )


ADMIN_KEY_HEADER = APIKeyHeader(name="X-Admin-Key", auto_error=False)

def require_admin(admin_key: Optional[str] = Security(ADMIN_KEY_HEADER)):
    if admin_key != MASTER_KEY:
        raise HTTPException(403, detail={"error": "invalid_admin_key"})

class CreateKeyRequest(BaseModel):
    tenant_name: str
    tier: Tier = Tier.STARTER
    tenant_id: Optional[str] = None


class CreateKeyResponse(BaseModel):
    api_key: str
    tenant_id: str
    tenant_name: str
    tier: str
    warning: str = "Store this key securely. It cannot be retrieved again."


@app.post(
    "/admin/keys",
    response_model=CreateKeyResponse,
    tags=["Admin"],
    include_in_schema=(ENV != "production"),
)
async def create_key(req: CreateKeyRequest, _=Depends(require_admin)):
    raw_key = f"rdk-{secrets.token_urlsafe(32)}"
    h = hashlib.sha256(raw_key.encode()).hexdigest()
    tid = req.tenant_id or f"tenant-{str(uuid.uuid4())[:8]}"
    _KEY_STORE[h] = APIKey(
        key_hash=h,
        tenant_id=tid,
        tenant_name=req.tenant_name,
        tier=req.tier,
    )
    log.info(f"New API key created for tenant '{req.tenant_name}' tier={req.tier}")
    return CreateKeyResponse(
        api_key=raw_key,
        tenant_id=tid,
        tenant_name=req.tenant_name,
        tier=req.tier,
    )


@app.delete(
    "/admin/keys/{tenant_id}",
    tags=["Admin"],
    include_in_schema=(ENV != "production"),
)
async def revoke_key(tenant_id: str, _=Depends(require_admin)):
    revoked = 0
    for key in _KEY_STORE.values():
        if key.tenant_id == tenant_id:
            key.active = False
            revoked += 1
    return {"revoked": revoked, "tenant_id": tenant_id}


@app.get("/health", tags=["Ops"])
async def health():
    return {"status": "ok", "env": ENV}


@app.get("/ready", tags=["Ops"])
async def ready():
    ner_mode = "heuristic" if _redactor._ner._heuristic_only else "spacy_model"
    return {
        "status": "ready",
        "redactor": "loaded",
        "ner_mode": ner_mode,
        "active_sessions": len(_redactor._sessions),
    }


if __name__ == "__main__":
    print(f"\nDemo API key: {DEMO_KEY}")
    print(f"Swagger UI:   http://localhost:8080/docs\n")
    uvicorn.run("api_server:app", host="0.0.0.0", port=8080, reload=True)
