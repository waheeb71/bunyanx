"""
Enterprise bunyanx - REST API Entry Point
=========================================
This is the ONLY file that assembles the application.
All actual endpoints live in api/routers/v1/.
Adding a new endpoint group = create a new file in routers/v1/ and register it here.
"""
import logging
import os
from pathlib import Path
from contextlib import asynccontextmanager

# Load environment variables from .env if present
try:
    import dotenv
    dotenv.load_dotenv(Path(__file__).parent.parent / ".env")
except ImportError:
    pass

# Bi-directional env var bridging to support both NGFW_ and bunyanx_ prefixes
def bridge_env_vars():
    mappings = {
        "NGFW_SECRET_KEY": "bunyanx_SECRET_KEY",
        "NGFW_ADMIN_PASSWORD": "bunyanx_ADMIN_PASSWORD",
        "NGFW_OPERATOR_PASSWORD": "bunyanx_OPERATOR_PASSWORD",
        "NGFW_ENV": "bunyanx_ENV",
        "NGFW_GEOIP_PATH": "bunyanx_GEOIP_PATH",
        "NGFW_DATA_DIR": "bunyanx_DATA_DIR",
        "NGFW_ALLOWED_ORIGINS": "bunyanx_ALLOWED_ORIGINS",
    }
    for k1, k2 in mappings.items():
        v1 = os.getenv(k1)
        v2 = os.getenv(k2)
        if v1 and not v2:
            os.environ[k2] = v1
        elif v2 and not v1:
            os.environ[k1] = v2

bridge_env_vars()
from datetime import datetime
from pathlib import Path
import importlib
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

# ── Core App Routers ──────────────────────────────────────────────────────────
from api.routers.v1.auth import router as auth_router
from api.routers.v1.status import router as status_router
from api.routers.v1.config import router as config_router
from api.routers.v1.users import router as users_router
from api.routers.v1.networking import router as networking_router
from api.routers.v1.update import router as update_router
from api.routers.v1.response import router as response_router
from api.routers.v1.ha import router as ha_router
from api.routers.v1.system import router as system_router
from api.routers.v1.telemetry import router as telemetry_router
from api.routers.v1.traffic import router as traffic_router
from api.routers.v1.ws import router as ws_router
from api.routers.v1.netops import router as netops_router
from api.routers.v1.dashboard import router as dashboard_router
from api.routers.v1.certificates import router as certificates_router
from api.audio_alerts import router as audio_alerts_router
from api.routers.v1.cvas import router as cvas_router
from api.routers.v1.policy import router as policy_router
from api.routers.v1.siem import router as siem_router
from api.routers.v1.security import router as security_router
from api.routers.v1.threat_intel import router as threat_intel_router
from api.routers.v1.captive_portal import router as captive_portal_router

# ── Ensure module models are imported so Base.metadata knows their tables ────
# This must happen BEFORE DatabaseManager.initialize() → create_all()
try:
    from modules.malware_av.models import MalwareAVConfig, MalwareNetworkScanLog  # noqa: F401
except Exception as _e:
    pass  # будет logged при инициализации модуля

try:
    from modules.predictive_ai.models import (  # noqa: F401
        PredictiveAIConfig,
        AttackIntentLog,
        RLSafetyAuditLog,
        AEGISDecisionLog,
        AEGISDecoyLog,
    )
except Exception as _e:
    pass  # logged at module init time

try:
    from modules.dlp.models import DLPConfig, DLPRule  # noqa: F401
except Exception as _e:
    pass

try:
    from modules.ids_ips.models import IPSConfig, IPSSignature  # noqa: F401
except Exception as _e:
    pass

try:
    from modules.firewall.models import FirewallRule  # noqa: F401
except Exception as _e:
    pass

try:
    from modules.ssl_inspection.models import SSLPolicy, SSLCertificateConfig  # noqa: F401
except Exception as _e:
    pass



logger = logging.getLogger(__name__)

# ── Rate Limiter ──────────────────────────────────────────────────────────────
limiter = Limiter(key_func=get_remote_address, default_limits=["200/minute"])

# ── Default-user seeding ──────────────────────────────────────────────────────
async def _seed_default_users(app: FastAPI) -> None:
    try:
        bunyanx = getattr(app.state, "bunyanx", None)
        if bunyanx is None or not hasattr(bunyanx, "db"):
            logger.warning("⚠️  bunyanx state not ready – skipping user seeding.")
            return

        from api.core.auth import _hash_password
        from system.database.database import User, Incident
        from sqlalchemy.future import select

        admin_pw   = os.getenv("bunyanx_ADMIN_PASSWORD",    "Admin@1234")
        operator_pw = os.getenv("bunyanx_OPERATOR_PASSWORD", "Operator@1234")

        db = bunyanx.db
        async with db.session() as session:
            result = await session.execute(select(User))
            users = result.scalars().all()
            user_count = len(users)

            if user_count == 0:
                await db.add_default_users(
                    admin_hash=_hash_password(admin_pw),
                    operator_hash=_hash_password(operator_pw),
                )
                logger.info("═" * 65)
                logger.info("  ✅ First-run detected — default users created")
                logger.info("═" * 65)
            else:
                logger.info(f"✔  Users already seeded ({user_count} accounts found) — skipping.")

            # Seed default incidents
            pass

    except Exception as exc:
        logger.error(f"❌ Failed to seed default data: {exc}", exc_info=True)


# ── Lifespan ──────────────────────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("🚀 Enterprise bunyanx API starting…")
    try:
        from system.database.database import Base, _db_manager_ref, DatabaseManager
        import system.database.model_registry  # noqa: F401
        if _db_manager_ref is None:
            _db_mgr = DatabaseManager()
            await _db_mgr.initialize()
            logger.info("✅ DatabaseManager initialized in lifespan")
        elif _db_manager_ref.sync_engine:
            Base.metadata.create_all(_db_manager_ref.sync_engine)
            logger.info("✅ NM-MDE tables verified/created")
    except Exception as _e:
        logger.debug(f"DB table sync skipped: {_e}")
    await _seed_default_users(app)
    
    try:
        from api.websocket.background import start_background_tasks
        await start_background_tasks()
    except Exception as e:
        logger.error(f"Failed to start SIEM WebSocket tasks: {e}")
        
    yield
    logger.info("🛑 Enterprise bunyanx API shut down.")

# ── Application Factory ───────────────────────────────────────────────────────
def create_app() -> FastAPI:
    application = FastAPI(
        title="Enterprise bunyanx API",
        description="Clean Architecture Next-Gen Firewall API",
        version="3.0.0",
        lifespan=lifespan,
        docs_url="/api/docs",
        redoc_url="/api/redoc",
        openapi_url="/api/openapi.json",
    )

    application.state.limiter = limiter
    application.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

    # ── CORS — read from environment, never hardcode wildcard in production ─────
    _raw_origins = os.getenv("NGFW_ALLOWED_ORIGINS", "http://localhost:5173,http://localhost:8080")
    _allowed_origins: list[str] = [o.strip() for o in _raw_origins.split(",") if o.strip()]
    if "*" in _allowed_origins:
        logger.warning(
            "⚠️  CORS: NGFW_ALLOWED_ORIGINS contains '*' — wildcard CORS is INSECURE. "
            "Set explicit origins for production deployments."
        )
    logger.info(f"🔒 CORS allowed origins: {_allowed_origins}")

    application.add_middleware(
        CORSMiddleware,
        allow_origins=_allowed_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type", "X-Request-ID"],
    )

    @application.middleware("http")
    async def add_trace_id(request: Request, call_next):
        import uuid
        request_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())
        request.state.trace_id = request_id
        response = await call_next(request)
        response.headers["X-Request-ID"] = request_id
        return response

    # ── Register Core Routers (v1) ───────────────────────────────────────────
    application.include_router(auth_router)
    application.include_router(status_router)
    application.include_router(config_router)
    application.include_router(users_router)
    application.include_router(networking_router)
    application.include_router(update_router)
    application.include_router(response_router)
    application.include_router(ha_router)
    application.include_router(system_router)
    application.include_router(telemetry_router)
    application.include_router(traffic_router)
    application.include_router(ws_router)
    application.include_router(netops_router)   # Network Operations Terminal
    application.include_router(dashboard_router)
    application.include_router(certificates_router)   # PKI Certificate Management
    application.include_router(audio_alerts_router)
    application.include_router(cvas_router)           # bunyanx Voice Alert Service (CVAS)
    application.include_router(policy_router)
    application.include_router(siem_router)
    application.include_router(security_router)
    application.include_router(threat_intel_router)
    application.include_router(captive_portal_router)  # Guest / BYOD portal

    @application.get("/metrics", include_in_schema=False)
    async def prometheus_metrics():
        from fastapi.responses import Response
        from system.telemetry.prometheus_exporter import MetricsExporter
        exp = MetricsExporter.instance()
        return Response(content=exp.generate_latest(), media_type=exp.content_type())
    
    _load_module_routers(application)

    @application.exception_handler(HTTPException)
    async def http_exc_handler(request: Request, exc: HTTPException):
        return JSONResponse(
            status_code=exc.status_code,
            content={"error": exc.detail, "timestamp": datetime.utcnow().isoformat() + "Z"},
        )

    @application.exception_handler(Exception)
    async def general_exc_handler(request: Request, exc: Exception):
        logger.error(f"Unhandled exception: {exc}", exc_info=True)
        return JSONResponse(
            status_code=500,
            content={"error": "Internal server error", "timestamp": datetime.utcnow().isoformat() + "Z"},
        )

    return application

def _load_module_routers(app: FastAPI):
    base_dir = Path(__file__).parent.parent
    for search_dir in ("modules",):
        dir_path = base_dir / search_dir
        if not dir_path.exists():
            continue
        for component_dir in sorted(dir_path.iterdir()):
            if component_dir.is_dir() and not component_dir.name.startswith("__"):
                router_file = component_dir / "api" / "router.py"
                if router_file.exists():
                    module_path = f"{search_dir}.{component_dir.name}.api.router"
                    try:
                        mod = importlib.import_module(module_path)
                        if hasattr(mod, "router"):
                            app.include_router(mod.router)
                    except Exception as exc:
                        logger.error(
                            f"❌ Failed to load module router '{module_path}': {exc}",
                            exc_info=True,
                        )

app = create_app()

if __name__ == "__main__":
    import uvicorn

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)8s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    uvicorn.run(
        "api.main:app",
        host="0.0.0.0",
        port=8000,
        reload=os.getenv("bunyanx_ENV", "production") == "development",
        log_level="info",
    )