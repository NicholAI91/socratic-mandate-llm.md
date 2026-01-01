"""
Socratic Mandate LLM Application - Production Ready
HTTP API wrapper around the five pillar shell.

Endpoints:
- POST /v1/chat              - Run a guarded LLM interaction
- GET  /v1/audit/tail        - Read the last N audit records (operators)
- GET  /v1/audit/search      - Search audit records (operators)
- GET  /v1/audit/intake/{id} - Get all records for an intake (operators)
- POST /v1/consent           - Set user consent level
- GET  /v1/consent/{user_id} - Get user consent status
- DELETE /v1/consent/{user_id} - Revoke user consent
- GET  /health               - Health check
- GET  /ready                - Readiness check
"""

import os
import time
import uuid
import logging
from typing import Any, Dict, List, Optional
from contextlib import asynccontextmanager

from fastapi import FastAPI, Header, HTTPException, Depends, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from socratic_shell import (
    UserRequest,
    ConsentLevel,
    ConsentGateway,
    ZeroTrustFilter,
    CognitiveIntegrityGuard,
    PolicyEngine,
    SimpleInMemoryWORMStorage,
    ImmutableAuditLogger,
    SimpleNotifierBackend,
    EscalationEngine,
    SocraticLLMSystem,
    StubLLM,
    BaseLLM,
)

from auth import (
    Role,
    AuthenticatedUser,
    APIKeyStore,
    JWTConfig,
    JWTValidator,
    AuthManager,
    RateLimitMiddleware,
    TimeoutMiddleware,
    AuditMiddleware,
)


# =========================
# Configuration
# =========================

class Config:
    # Auth
    AUTH_ENABLED = os.getenv("AUTH_ENABLED", "true").lower() == "true"
    JWT_SECRET = os.getenv("JWT_SECRET", "change-me-in-production")
    JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
    JWT_EXPIRY_SECONDS = int(os.getenv("JWT_EXPIRY_SECONDS", "3600"))
    
    # Rate limiting
    RATE_LIMIT_REQUESTS_PER_MINUTE = int(os.getenv("RATE_LIMIT_RPM", "60"))
    
    # Timeouts
    REQUEST_TIMEOUT_SECONDS = float(os.getenv("REQUEST_TIMEOUT", "30.0"))
    MODEL_TIMEOUT_SECONDS = float(os.getenv("MODEL_TIMEOUT", "25.0"))
    
    # LLM Provider
    LLM_PROVIDER = os.getenv("LLM_PROVIDER", "stub")  # stub, openai, anthropic, ollama
    OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
    OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-4o")
    ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")
    ANTHROPIC_MODEL = os.getenv("ANTHROPIC_MODEL", "claude-sonnet-4-20250514")
    OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
    OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3.2")
    
    # Storage
    STORAGE_BACKEND = os.getenv("STORAGE_BACKEND", "memory")  # memory, postgres
    POSTGRES_DSN = os.getenv("POSTGRES_DSN", "")
    
    # CORS
    CORS_ORIGINS = os.getenv("CORS_ORIGINS", "*").split(",")
    
    # Logging
    LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")


# Configure logging
logging.basicConfig(
    level=getattr(logging, Config.LOG_LEVEL),
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("socratic")


# =========================
# LLM Provider Factory
# =========================

def create_llm_provider() -> BaseLLM:
    provider = Config.LLM_PROVIDER.lower()
    
    if provider == "stub":
        return StubLLM()
    
    elif provider == "openai":
        from models.openai_provider import OpenAIProvider
        return OpenAIProvider(
            api_key=Config.OPENAI_API_KEY,
            model=Config.OPENAI_MODEL,
        )
    
    elif provider == "anthropic":
        from models.anthropic_provider import AnthropicProvider
        return AnthropicProvider(
            api_key=Config.ANTHROPIC_API_KEY,
            model=Config.ANTHROPIC_MODEL,
        )
    
    elif provider == "ollama":
        from models.local_provider import OllamaProvider
        return OllamaProvider(
            model=Config.OLLAMA_MODEL,
            base_url=Config.OLLAMA_BASE_URL,
        )
    
    else:
        logger.warning(f"Unknown LLM provider '{provider}', falling back to stub")
        return StubLLM()


# =========================
# Global State
# =========================

# These will be initialized in the lifespan handler
_storage_backend = None
_audit_logger = None
_socratic_system = None
_auth_manager = None
_api_key_store = None


async def initialize_system():
    """Initialize all system components."""
    global _storage_backend, _audit_logger, _socratic_system, _auth_manager, _api_key_store
    
    # Storage backend
    if Config.STORAGE_BACKEND == "postgres" and Config.POSTGRES_DSN:
        from storage.postgres import PostgresWORMStorage
        _storage_backend = PostgresWORMStorage(dsn=Config.POSTGRES_DSN)
        await _storage_backend.connect()
        await _storage_backend.initialize_schema()
        logger.info("PostgreSQL storage initialized")
    else:
        _storage_backend = SimpleInMemoryWORMStorage()
        logger.info("In-memory storage initialized")
    
    # Audit logger
    _audit_logger = ImmutableAuditLogger(storage_backend=_storage_backend)
    
    # Notifier (stub for now)
    notifier_backend = SimpleNotifierBackend()
    
    # Escalation engine
    escalation_engine = EscalationEngine(
        severity_thresholds={"security": 2, "legal": 3},
        notifier_backend=notifier_backend,
    )
    
    # Policy modules
    consent_gateway = ConsentGateway(policy_version="v1.0")
    zero_trust_filter = ZeroTrustFilter(allow_location=False)
    cognitive_guard = CognitiveIntegrityGuard(patterns={"manipulate": "manipulation_risk"})
    
    policy_engine = PolicyEngine(
        consent_gateway=consent_gateway,
        zero_trust_filter=zero_trust_filter,
        cognitive_guard=cognitive_guard,
    )
    
    # LLM provider
    model = create_llm_provider()
    logger.info(f"LLM provider initialized: {model.model_id}")
    
    # Full system
    _socratic_system = SocraticLLMSystem(
        model=model,
        policy_engine=policy_engine,
        audit_logger=_audit_logger,
        escalation_engine=escalation_engine,
        timeout_seconds=Config.MODEL_TIMEOUT_SECONDS,
    )
    
    # Auth
    _api_key_store = APIKeyStore()
    
    jwt_validator = None
    if Config.JWT_SECRET != "change-me-in-production":
        jwt_validator = JWTValidator(JWTConfig(
            secret_key=Config.JWT_SECRET,
            algorithm=Config.JWT_ALGORITHM,
            expiry_seconds=Config.JWT_EXPIRY_SECONDS,
        ))
    
    _auth_manager = AuthManager(
        api_key_store=_api_key_store,
        jwt_validator=jwt_validator,
        allow_anonymous=not Config.AUTH_ENABLED,
    )
    
    # Create default API keys for development
    if not Config.AUTH_ENABLED:
        logger.warning("Authentication is DISABLED - do not use in production")
    else:
        # Create a default admin key
        admin_key = _api_key_store.create_key(
            name="default-admin",
            roles={Role.ADMIN, Role.OPERATOR, Role.USER},
            rate_limit=1000,
        )
        logger.info(f"Created default admin API key: {admin_key}")


async def shutdown_system():
    """Cleanup system resources."""
    if hasattr(_storage_backend, "close"):
        await _storage_backend.close()
    logger.info("System shutdown complete")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan handler."""
    await initialize_system()
    yield
    await shutdown_system()


# =========================
# FastAPI App
# =========================

app = FastAPI(
    title="Socratic Mandate LLM Shell",
    description="Production-ready five pillar AI safety guardrail service",
    version="1.0.0",
    lifespan=lifespan,
)

# Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=Config.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.add_middleware(TimeoutMiddleware, timeout_seconds=Config.REQUEST_TIMEOUT_SECONDS)
app.add_middleware(RateLimitMiddleware, requests_per_minute=Config.RATE_LIMIT_REQUESTS_PER_MINUTE)
app.add_middleware(AuditMiddleware, log_func=lambda x: logger.debug(x))


# =========================
# API Models
# =========================

class ChatRequest(BaseModel):
    text: str = Field(..., description="User input text", min_length=1, max_length=32000)
    user_id: Optional[str] = Field(None, description="Stable user identifier")
    session_id: Optional[str] = Field(None, description="Session identifier")
    client_metadata: Dict[str, Any] = Field(default_factory=dict)


class ChatResponse(BaseModel):
    content: str
    metadata: Dict[str, Any]


class AuditRecord(BaseModel):
    record: Dict[str, Any]
    hash: str


class AuditTailResponse(BaseModel):
    records: List[AuditRecord]
    total: int


class AuditSearchRequest(BaseModel):
    record_type: Optional[str] = None
    user_id: Optional[str] = None
    session_id: Optional[str] = None
    start_time: Optional[float] = None
    end_time: Optional[float] = None
    limit: int = Field(default=100, ge=1, le=1000)


class ConsentRequest(BaseModel):
    user_id: str = Field(..., min_length=1)
    level: str = Field(..., description="Consent level: DEFAULT, SENSITIVE, RESEARCH, FORENSIC")
    acknowledged: bool = Field(default=True)


class ConsentResponse(BaseModel):
    user_id: str
    level: str
    obtained_at: float
    policy_version: str
    flags: Dict[str, bool]


class HealthResponse(BaseModel):
    status: str
    timestamp: float
    components: Dict[str, Any]


# =========================
# Dependencies
# =========================

def get_socratic_system() -> SocraticLLMSystem:
    return _socratic_system


def get_auth_manager() -> AuthManager:
    return _auth_manager


# =========================
# Endpoints
# =========================

@app.get("/health", response_model=HealthResponse)
async def health():
    """Health check endpoint."""
    health_status = await _socratic_system.health_check()
    return HealthResponse(
        status=health_status["status"],
        timestamp=time.time(),
        components={
            "model": health_status["model"],
            "storage": "healthy",
        }
    )


@app.get("/ready")
async def ready():
    """Readiness check for load balancers."""
    if _socratic_system is None:
        raise HTTPException(status_code=503, detail="System not initialized")
    
    health_status = await _socratic_system.health_check()
    if health_status["status"] != "healthy":
        raise HTTPException(status_code=503, detail="System not ready")
    
    return {"status": "ready"}


@app.post("/v1/chat", response_model=ChatResponse)
async def chat(
    payload: ChatRequest,
    x_request_id: Optional[str] = Header(default=None, alias="X-Request-ID"),
    user: AuthenticatedUser = Depends(lambda: _auth_manager.require_auth()),
):
    """
    Main interaction endpoint with full five pillar protection.
    """
    session_id = payload.session_id or f"session-{uuid.uuid4()}"
    
    user_req = UserRequest(
        user_id=payload.user_id or user.user_id,
        session_id=session_id,
        text=payload.text,
        timestamp=time.time(),
        client_metadata={
            **payload.client_metadata,
            "x_request_id": x_request_id,
            "auth_method": user.auth_method,
        },
        request_id=x_request_id or str(uuid.uuid4()),
    )
    
    try:
        system_resp = await _socratic_system.handle_request(user_req)
        
        return ChatResponse(
            content=system_resp.content,
            metadata=system_resp.metadata,
        )
    except Exception as e:
        logger.error(f"Chat error: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Internal processing error")


@app.get("/v1/audit/tail", response_model=AuditTailResponse)
async def audit_tail(
    limit: int = Query(default=10, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
    user: AuthenticatedUser = Depends(lambda: _auth_manager.require_roles(Role.OPERATOR, Role.ADMIN)),
):
    """
    Get the latest audit records (requires operator role).
    """
    records = await _storage_backend.get_records(limit=limit, offset=offset)
    
    return AuditTailResponse(
        records=[
            AuditRecord(record=r["record"], hash=r["hash"])
            for r in records
        ],
        total=len(records),
    )


@app.post("/v1/audit/search", response_model=AuditTailResponse)
async def audit_search(
    query: AuditSearchRequest,
    user: AuthenticatedUser = Depends(lambda: _auth_manager.require_roles(Role.OPERATOR, Role.ADMIN)),
):
    """
    Search audit records with filters (requires operator role).
    """
    records = await _storage_backend.search_records(
        record_type=query.record_type,
        user_id=query.user_id,
        session_id=query.session_id,
        start_time=query.start_time,
        end_time=query.end_time,
        limit=query.limit,
    )
    
    return AuditTailResponse(
        records=[
            AuditRecord(record=r["record"], hash=r["hash"])
            for r in records
        ],
        total=len(records),
    )


@app.get("/v1/audit/intake/{intake_id}", response_model=AuditTailResponse)
async def audit_intake(
    intake_id: str,
    user: AuthenticatedUser = Depends(lambda: _auth_manager.require_roles(Role.OPERATOR, Role.ADMIN)),
):
    """
    Get all audit records for a specific intake (requires operator role).
    """
    if hasattr(_storage_backend, "get_records_by_intake"):
        records = await _storage_backend.get_records_by_intake(intake_id)
    else:
        # Fallback for in-memory storage
        records = await _storage_backend.search_records(limit=1000)
        records = [
            r for r in records
            if r["record"].get("id") == intake_id or r["record"].get("intake_id") == intake_id
        ]
    
    return AuditTailResponse(
        records=[
            AuditRecord(record=r["record"], hash=r["hash"])
            for r in records
        ],
        total=len(records),
    )


@app.post("/v1/consent", response_model=ConsentResponse)
async def set_consent(
    payload: ConsentRequest,
    user: AuthenticatedUser = Depends(lambda: _auth_manager.require_auth()),
):
    """
    Set consent level for a user.
    Users can only set consent for themselves unless they're admin.
    """
    # Only admins can set consent for other users
    if payload.user_id != user.user_id and Role.ADMIN not in user.roles:
        raise HTTPException(status_code=403, detail="Cannot set consent for other users")
    
    try:
        level = ConsentLevel[payload.level.upper()]
    except KeyError:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid consent level. Must be one of: {[l.name for l in ConsentLevel]}"
        )
    
    consent = await _socratic_system.policy_engine.consent_gateway.set_user_consent(
        user_id=payload.user_id,
        level=level,
        acknowledged=payload.acknowledged,
    )
    
    return ConsentResponse(
        user_id=payload.user_id,
        level=consent.level.name,
        obtained_at=consent.obtained_at,
        policy_version=consent.version,
        flags=consent.flags,
    )


@app.get("/v1/consent/{user_id}", response_model=Optional[ConsentResponse])
async def get_consent(
    user_id: str,
    user: AuthenticatedUser = Depends(lambda: _auth_manager.require_auth()),
):
    """
    Get consent status for a user.
    Users can only view their own consent unless they're operator/admin.
    """
    if user_id != user.user_id and not user.roles.intersection({Role.OPERATOR, Role.ADMIN}):
        raise HTTPException(status_code=403, detail="Cannot view consent for other users")
    
    consent = await _socratic_system.policy_engine.consent_gateway.get_user_consent(user_id)
    
    if not consent:
        return None
    
    return ConsentResponse(
        user_id=user_id,
        level=consent.level.name,
        obtained_at=consent.obtained_at,
        policy_version=consent.version,
        flags=consent.flags,
    )


@app.delete("/v1/consent/{user_id}")
async def revoke_consent(
    user_id: str,
    user: AuthenticatedUser = Depends(lambda: _auth_manager.require_auth()),
):
    """
    Revoke consent for a user.
    Users can only revoke their own consent unless they're admin.
    """
    if user_id != user.user_id and Role.ADMIN not in user.roles:
        raise HTTPException(status_code=403, detail="Cannot revoke consent for other users")
    
    revoked = await _socratic_system.policy_engine.consent_gateway.revoke_consent(user_id)
    
    return {"revoked": revoked}


# =========================
# Admin Endpoints
# =========================

@app.post("/admin/api-keys")
async def create_api_key(
    name: str,
    roles: List[str] = ["user"],
    rate_limit: int = 60,
    expires_in_days: Optional[int] = None,
    user: AuthenticatedUser = Depends(lambda: _auth_manager.require_roles(Role.ADMIN)),
):
    """
    Create a new API key (admin only).
    """
    try:
        role_set = {Role(r) for r in roles}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=f"Invalid role: {e}")
    
    key = _api_key_store.create_key(
        name=name,
        roles=role_set,
        rate_limit=rate_limit,
        expires_in_days=expires_in_days,
    )
    
    return {"api_key": key, "name": name, "roles": roles}


@app.get("/admin/api-keys")
async def list_api_keys(
    user: AuthenticatedUser = Depends(lambda: _auth_manager.require_roles(Role.ADMIN)),
):
    """
    List all API keys (admin only).
    """
    return {"keys": _api_key_store.list_keys()}


@app.delete("/admin/api-keys/{key}")
async def revoke_api_key(
    key: str,
    user: AuthenticatedUser = Depends(lambda: _auth_manager.require_roles(Role.ADMIN)),
):
    """
    Revoke an API key (admin only).
    """
    revoked = _api_key_store.revoke_key(key)
    return {"revoked": revoked}


# =========================
# Run with uvicorn
# =========================

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "socratic_app:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
    )
