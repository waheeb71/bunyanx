#!/usr/bin/env python3
"""
Enterprise bunyanx - Database Layer

SQLAlchemy models for persistent storage:
- User: user accounts with hashed passwords
- Rule: firewall rules
- Event: security events log
- AuditLog: admin action audit trail

Supports SQLite (dev) and PostgreSQL (production).
"""
from datetime import timezone
import logging
import asyncio
from datetime import datetime
from typing import Optional, AsyncGenerator, Generator
from sqlalchemy import (
    Column, Integer, String, Float, Boolean, DateTime, Text, JSON,
    ForeignKey, event, create_engine
)

from sqlalchemy.orm import (
    DeclarativeBase, sessionmaker, Session
)
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
logger = logging.getLogger(__name__)
# ==================== Base ====================
class Base(DeclarativeBase):
    """SQLAlchemy declarative base — shared by system models and all module models."""
    pass

# ==================== System Models ====================
# Models defined here are SYSTEM-LEVEL: shared infrastructure used by multiple
# modules or the core framework (auth, audit, security events, incidents, etc.).
#
# Module-specific models (e.g., IPSSignature, WebFilterCategory, WAFTrainingData)
# should live in modules/<name>/models.py and extend this same Base.
# Alembic discovers them via system/database/model_registry.py.
#
# Migration path for models currently here:
#   EmailSecurityConfig → modules/email_security/models.py    [TODO Phase 6+]
#   QoSConfig           → modules/qos/models.py              [TODO Phase 6+]
#   VPNConfig/VPNPeer   → modules/vpn/models.py              [TODO Phase 6+]
#   UBAUserProfile etc  → modules/uba/models.py              [TODO Phase 6+]



class User(Base):
    """User account"""
    __tablename__ = 'users'

    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String(64), unique=True, nullable=False, index=True)
    password_hash = Column(String(256), nullable=False)
    role = Column(String(32), nullable=False, default='viewer')
    email = Column(String(128), nullable=True)
    display_name = Column(String(128), nullable=True)
    is_active = Column(Boolean, default=True)
    is_ldap = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    last_login = Column(DateTime, nullable=True)

    def __repr__(self):
        return f"<User {self.username} ({self.role})>"


class Rule(Base):
    """Firewall rule / user resource-permission rule"""
    __tablename__ = 'rules'

    id = Column(Integer, primary_key=True, autoincrement=True)
    # ── User-permission fields (used by RBAC in auth.py / users_routes.py) ──
    # FIX C2: Added proper ForeignKey with cascade delete so orphaned rules
    # are automatically removed when a user is deleted.
    user_id = Column(
        Integer,
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )   # FK → users.id
    resource = Column(String(64), nullable=True, index=True)  # e.g. 'firewall', 'vpn'
    # ── Firewall-rule fields ─────────────────────────────────────────────────
    name = Column(String(128), nullable=True)
    src_ip = Column(String(64), nullable=True)
    dst_ip = Column(String(64), nullable=True)
    src_port = Column(Integer, nullable=True)
    dst_port = Column(Integer, nullable=True)
    protocol = Column(String(10), nullable=True)
    action = Column(String(20), nullable=False, default='BLOCK')
    priority = Column(Integer, default=50)
    enabled = Column(Boolean, default=True)
    description = Column(Text, nullable=True)
    created_by = Column(String(64), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'src_ip': self.src_ip,
            'dst_ip': self.dst_ip,
            'src_port': self.src_port,
            'dst_port': self.dst_port,
            'protocol': self.protocol,
            'action': self.action,
            'priority': self.priority,
            'enabled': self.enabled,
            'description': self.description,
            'created_by': self.created_by,
            'created_at': self.created_at.isoformat() if self.created_at else None,
        }

    def __repr__(self):
        return f"<Rule #{self.id} {self.action} {self.src_ip}→{self.dst_port}>"


class SecurityEvent(Base):
    """Security event log"""
    __tablename__ = 'security_events'

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    event_type = Column(String(32), nullable=False, index=True)
    severity = Column(String(16), nullable=False, default='info')
    source_ip = Column(String(64), nullable=True, index=True)
    destination_ip = Column(String(64), nullable=True)
    source_port = Column(Integer, nullable=True)
    destination_port = Column(Integer, nullable=True)
    protocol = Column(String(10), nullable=True)
    action = Column(String(20), nullable=True)
    description = Column(Text, nullable=True)
    anomaly_score = Column(Float, nullable=True)
    event_metadata = Column(JSON, nullable=True)

    def to_dict(self):
        return {
            'id': self.id,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'event_type': self.event_type,
            'severity': self.severity,
            'source_ip': self.source_ip,
            'destination_ip': self.destination_ip,
            'action': self.action,
            'description': self.description,
            'anomaly_score': self.anomaly_score,
        }


class AuditLog(Base):
    """Admin action audit trail"""
    __tablename__ = 'audit_log'

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    username = Column(String(64), nullable=False, index=True)
    action = Column(String(64), nullable=False)
    resource = Column(String(128), nullable=True)
    details = Column(JSON, nullable=True)
    ip_address = Column(String(64), nullable=True)


class Incident(Base):
    """Security Incident for Response Center"""
    __tablename__ = 'incidents'

    id = Column(Integer, primary_key=True, autoincrement=True)
    title = Column(String(256), nullable=False)
    severity = Column(String(32), nullable=False, default='medium') # critical|high|medium|low|info
    status = Column(String(32), nullable=False, default='open') # open|investigating|contained|closed
    source_ip = Column(String(64), nullable=True)
    destination_ip = Column(String(64), nullable=True)
    module = Column(String(64), nullable=False) # WAF, IDS/IPS, DLP, etc.
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    events_count = Column(Integer, default=1)
    description = Column(Text, nullable=True)

    def to_dict(self):
        return {
            'id': f"INC-{self.id:04d}",
            'title': self.title,
            'severity': self.severity,
            'status': self.status,
            'src_ip': self.source_ip,
            'dst_ip': self.destination_ip,
            'module': self.module,
            'ts': self.timestamp.isoformat() + 'Z' if self.timestamp else None,
            'events': self.events_count,
            'description': self.description
        }


class TokenBlacklist(Base):
    """Revoked JWT tokens"""
    __tablename__ = 'token_blacklist'
    id = Column(Integer, primary_key=True, autoincrement=True)
    token = Column(String(512), unique=True, nullable=False, index=True)
    expires_at = Column(DateTime, nullable=False)


class RateLimit(Base):
    """Distributed rate limiting and brute-force protection"""
    __tablename__ = 'rate_limits'
    ip_address = Column(String(64), primary_key=True)
    count = Column(Integer, default=0)
    locked_until = Column(DateTime, nullable=True)


class EmailSecurityConfig(Base):
    """Email Security Profile Settings"""
    __tablename__ = 'email_security_config'

    id = Column(Integer, primary_key=True, autoincrement=True)
    enabled = Column(Boolean, default=True)
    mode = Column(String(32), default='enforce')
    monitored_ports = Column(JSON, default=[25, 587, 465, 143, 993, 110, 995])
    
    preprocessing = Column(JSON, default={})
    phishing = Column(JSON, default={})
    url_scanner = Column(JSON, default={})
    attachment_guard = Column(JSON, default={})
    sender_reputation = Column(JSON, default={})
    spam_filter = Column(JSON, default={})
    smtp_commands = Column(JSON, default={})
    thresholds = Column(JSON, default={})
    logging = Column(JSON, default={})
    whitelist = Column(JSON, default={})
    plsf_config = Column(JSON, default={})
    vsde_config = Column(JSON, default={})


# ==================== QoS Model ====================

class QoSConfig(Base):
    """Quality of Service — global rate-limit configuration."""
    __tablename__ = 'qos_config'
    

    id = Column(Integer, primary_key=True, autoincrement=True)
    enabled = Column(Boolean, default=False)
    mode = Column(String(20), default="monitor")

    # Per-IP defaults (Token Bucket)
    default_user_rate_bytes = Column(Integer, default=1_250_000)   # ~10 Mbps
    default_user_burst_bytes = Column(Integer, default=2_500_000)  # ~20 Mbps burst

    # Global ceiling (optional, 0 = unlimited)
    global_rate_bytes = Column(Integer, default=0)

    # Traffic class priorities (JSON list of dicts: {dscp, priority, rate_bytes})
    traffic_classes = Column(JSON, default=[])
    
    # Missing YAML fields added
    max_buckets = Column(Integer, default=50000)
    gc_idle_timeout_sec = Column(Integer, default=300)
    gc_interval_sec = Column(Integer, default=60)
    enable_ebpf_tc = Column(Boolean, default=True)
    enable_app_priority_boost = Column(Boolean, default=True)

    updated_at = Column(DateTime, default=lambda: datetime.now(tz=__import__('datetime').timezone.utc),
                        onupdate=lambda: datetime.now(tz=__import__('datetime').timezone.utc))


# ── DB session helpers (FastAPI Depends compatible) ───────────────────────────

_db_manager_ref = None  # Set by DatabaseManager.initialize() for global access


def _ensure_db_manager():
    global _db_manager_ref
    if _db_manager_ref is None:
        mgr = DatabaseManager()
        is_sqlite = mgr.sync_url.startswith("sqlite")
        connect_args = {"check_same_thread": False} if is_sqlite else {}
        mgr.sync_engine = create_engine(mgr.sync_url, connect_args=connect_args)
        if is_sqlite:
            @event.listens_for(mgr.sync_engine, "connect")
            def _set_pragmas(dbapi_connection, connection_record):
                cursor = dbapi_connection.cursor()
                cursor.execute("PRAGMA journal_mode=WAL")
                cursor.execute("PRAGMA foreign_keys=ON")
                cursor.execute("PRAGMA synchronous=NORMAL")
                cursor.close()
        Base.metadata.create_all(mgr.sync_engine)
        mgr._auto_migrate_sqlite_columns()
        mgr._sync_session_factory = sessionmaker(
            bind=mgr.sync_engine,
            class_=Session,
            autocommit=False,
            autoflush=False
        )
        _db_manager_ref = mgr
    return _db_manager_ref


def get_db() -> Generator[Session, None, None]:
    """
    FastAPI dependency that yields a SYNC SQLAlchemy session (for legacy modules).
    """
    mgr = _db_manager_ref or _ensure_db_manager()
    session = mgr.sync_session()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


async def get_async_db() -> AsyncGenerator[AsyncSession, None]:
    """
    FastAPI dependency that yields an ASYNC SQLAlchemy session (for API Core).
    """
    if _db_manager_ref is None:
        mgr = _ensure_db_manager()
    else:
        mgr = _db_manager_ref
    if not hasattr(mgr, '_session_factory') or mgr._session_factory is None:
        session = mgr.sync_session()
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()
        return
    session = mgr.session()
    try:
        yield session
        await session.commit()
    except Exception:
        await session.rollback()
        raise
    finally:
        await session.close()


def SessionLocal() -> Session:
    """Returns a sync session."""
    mgr = _db_manager_ref or _ensure_db_manager()
    return mgr.sync_session()


def AsyncSessionLocal() -> AsyncSession:
    """Returns an async session."""
    mgr = _db_manager_ref or _ensure_db_manager()
    if hasattr(mgr, '_session_factory') and mgr._session_factory:
        return mgr.session()
    return mgr.sync_session()


# ==================== VPN Models ====================

class VPNConfig(Base):
    """WireGuard interface configuration — one row per interface.

    SECURITY NOTE: The WireGuard private key is NEVER stored in the database.
    It is generated at runtime by WireGuardManager and used only in-memory
    (written temporarily to /tmp during interface setup, then deleted).
    Only the public key is persisted here for peer distribution.
    """
    __tablename__ = 'vpn_config'

    id              = Column(Integer, primary_key=True, autoincrement=True)
    enabled         = Column(Boolean, default=False)
    interface       = Column(String(32), default='wg0', unique=True)
    listen_port     = Column(Integer, default=51820)
    server_ip       = Column(String(50), default='10.99.0.1/24')
    public_key      = Column(String(256), default='')   # Safe to store — public only
    # private_key is intentionally ABSENT — never persist WireGuard private keys in DB
    dns             = Column(String(128), default='')
    mtu             = Column(Integer, default=1420)
    updated_at      = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class VPNPeer(Base):
    """Registered WireGuard peer — persisted across restarts."""
    __tablename__ = 'vpn_peers'

    id                   = Column(Integer, primary_key=True, autoincrement=True)
    name                 = Column(String(128), default='')          # friendly label
    public_key           = Column(String(256), unique=True, nullable=False)
    preshared_key        = Column(String(256), default='')
    allowed_ips          = Column(JSON, default=list)                 # List[str]
    endpoint             = Column(String(256), default='')          # "IP:PORT"
    persistent_keepalive = Column(Integer, default=25)
    enabled              = Column(Boolean, default=True)
    created_at           = Column(DateTime, default=datetime.utcnow)
    updated_at           = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def to_dict(self) -> dict:
        return {
            "id":                    self.id,
            "name":                  self.name,
            "public_key":            self.public_key,
            "allowed_ips":           self.allowed_ips or [],
            "endpoint":              self.endpoint,
            "persistent_keepalive":  self.persistent_keepalive,
            "enabled":               self.enabled,
            "created_at":            self.created_at.isoformat() if self.created_at else None,
        }


# ==================== UBA Models ====================



class UBAUserProfile(Base):
    """Per-user behavioral baseline for UBA engine."""
    __tablename__ = 'uba_user_profiles'

    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String(64), unique=True, nullable=False, index=True)
    user_id = Column(Integer, nullable=True, index=True)   # FK → users.id (soft ref)
    peer_group = Column(String(64), nullable=True, index=True)  # e.g., "IT", "Finance"

    # ── Time baseline ──────────────────────────────────────────────────────────
    typical_hours_start = Column(Integer, default=0)   # learned work-start hour (0-23)
    typical_hours_end = Column(Integer, default=23)    # learned work-end hour  (0-23)
    hour_histogram = Column(JSON, default={})          # {0..23: event_count} for 3-sigma

    # ── Location baseline ──────────────────────────────────────────────────────
    known_ips = Column(JSON, default=[])               # up to 30 most recent IPs

    # ── Services baseline ──────────────────────────────────────────────────────
    known_services = Column(JSON, default=[])          # up to 100 services/ports

    # ── Volume baseline (EMA) ──────────────────────────────────────────────────
    avg_daily_bytes = Column(Float, default=0.0)
    daily_bytes_stddev = Column(Float, default=0.0)
    max_observed_bytes = Column(Float, default=0.0)

    # ── Session baseline ───────────────────────────────────────────────────────
    avg_session_duration = Column(Float, default=0.0)   # seconds
    avg_failed_logins = Column(Float, default=0.0)

    # ── Risk state ─────────────────────────────────────────────────────────────
    risk_score = Column(Float, default=0.0)            # 0–100 (EMA-smoothed)
    risk_level = Column(String(16), default='low')     # low|medium|high|critical

    # ── Learning state ─────────────────────────────────────────────────────────
    event_count = Column(Integer, default=0)
    baseline_locked = Column(Boolean, default=False)   # True = enough data to trust
    baseline_min_events = Column(Integer, default=50)

    last_seen = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def __repr__(self):
        return f"<UBAUserProfile {self.username} risk={self.risk_level}>"


class UBAEvent(Base):
    """Single observed behavior event with anomaly scoring."""
    __tablename__ = 'uba_events'

    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String(64), nullable=False, index=True)
    source_ip = Column(String(64), nullable=True)
    target_service = Column(String(128), nullable=True)
    bytes_transferred = Column(Float, default=0.0)
    session_duration = Column(Float, default=0.0)    # seconds

    event_time = Column(DateTime, default=datetime.utcnow, index=True)

    # ── Analysis results ────────────────────────────────────────────────────────
    anomaly_score = Column(Float, default=0.0)        # 0.0–1.0
    risk_contribution = Column(Float, default=0.0)    # score delta applied to profile
    detectors_triggered = Column(JSON, default=[])    # e.g. ["time_detector", "location_detector"]
    action_taken = Column(String(16), default='allow')  # allow|alert|block
    details = Column(JSON, default={})

    # ── Context ─────────────────────────────────────────────────────────────────
    peer_group = Column(String(64), nullable=True)

    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'source_ip': self.source_ip,
            'target_service': self.target_service,
            'bytes_transferred': self.bytes_transferred,
            'event_time': self.event_time.isoformat() if self.event_time else None,
            'anomaly_score': self.anomaly_score,
            'risk_contribution': self.risk_contribution,
            'detectors_triggered': self.detectors_triggered or [],
            'action_taken': self.action_taken,
            'details': self.details or {},
        }

    def __repr__(self):
        return f"<UBAEvent {self.username} score={self.anomaly_score:.2f}>"


class UBAConfig(Base):
    """UBA module global configuration."""
    __tablename__ = 'uba_config'

    id = Column(Integer, primary_key=True, autoincrement=True)
    enabled = Column(Boolean, default=True)
    deception_enabled = Column(Boolean, default=True) # Patent PoC
    mode = Column(String(16), default='monitor')      # monitor|enforce|learning

    enable_auto_quarantine = Column(Boolean, default=True)
    auto_quarantine_risk_score = Column(Integer, default=85)
    baseline_min_events = Column(Integer, default=50)
    max_known_ips = Column(Integer, default=30)
    max_known_services = Column(Integer, default=100)
    ema_alpha = Column(Float, default=0.1)            # EMA smoothing: 0=slow, 1=instant

    # Per-detector weights (JSON) — sum should be ≤ 1.0
    detector_weights = Column(JSON, default={
        "time": 0.20,
        "location": 0.30,
        "exfil": 0.25,
        "privilege": 0.15,
        "peer": 0.10,
    })
    # Risk thresholds
    thresholds = Column(JSON, default={
        "medium": 25.0,
        "high": 55.0,
        "critical": 80.0,
    })
    # Alert on risk level
    alert_on_risk_level = Column(String(16), default='high')

    # High-privilege services list for PrivilegeDetector
    privileged_services = Column(JSON, default=[
        "ssh", "rdp", "winrm", "admin", "root", "sudo",
        "3389", "22", "5985", "5986", "445",
    ])


class DatabaseManager:

    """
    Database connection and session management.

    The database URL is resolved automatically (no argument needed in most cases):
        Priority: caller arg > bunyanx_DATABASE_URL env > bunyanx_DB_PATH env > data/bunyanx.db

    Usage (SQLite — default dev setup):
        db = DatabaseManager()          # → data/bunyanx.db
        await db.initialize()
        with db.session() as session:
            user = session.query(User).filter_by(username='admin').first()

    Usage (PostgreSQL — production):
        db = DatabaseManager('postgresql+asyncpg://user:pass@host:5432/bunyanx')
        await db.initialize()
    """


    def __init__(self, database_url: str = ''):
        # ── Default URL: data/bunyanx.db relative to project root ────────────
        # Priority: caller arg > bunyanx_DATABASE_URL env > bunyanx_DB_PATH env > default
        if not database_url:
            import os as _os
            database_url = _os.environ.get('bunyanx_DATABASE_URL', '').strip()
        if not database_url:
            import os as _os
            from pathlib import Path as _Path
            _db_path_str = _os.environ.get('bunyanx_DB_PATH', '').strip()
            if _db_path_str:
                _db_path = _Path(_db_path_str)
            else:
                # Two levels up from system/database/ → enterprise_ngfw/
                _project_root = _Path(__file__).resolve().parent.parent.parent
                _db_path = _project_root / 'data' / 'bunyanx.db'
            _db_path.parent.mkdir(parents=True, exist_ok=True)
            database_url = f'sqlite+aiosqlite:///{_db_path.resolve()}'

        # Ensure async driver is specified in the async URL
        if database_url.startswith("sqlite://"):
            database_url = database_url.replace("sqlite://", "sqlite+aiosqlite://")
        elif database_url.startswith("postgresql://"):
            database_url = database_url.replace("postgresql://", "postgresql+asyncpg://")
            
        self.database_url = database_url
        self.sync_url = database_url.replace("+aiosqlite", "").replace("+asyncpg", "+psycopg2")
        self.engine = None
        self._session_factory = None
        self.sync_engine = None
        self._sync_session_factory = None
        logger.info(f"DatabaseManager initialized (Dual-Engine): {self.sync_url}")

    async def initialize(self):
        """Create engine, tables, and session factory"""
        is_memory = ":memory:" in self.database_url
        is_sqlite = "sqlite" in self.database_url
        engine_opts = {"echo": False, "pool_pre_ping": True}
        if is_memory:
            from sqlalchemy.pool import StaticPool
            engine_opts["poolclass"] = StaticPool
            engine_opts["connect_args"] = {"check_same_thread": False}
        elif is_sqlite:
            from sqlalchemy.pool import NullPool
            engine_opts["poolclass"] = NullPool
            engine_opts["connect_args"] = {"check_same_thread": False, "timeout": 30}
        else:
            engine_opts.update({
                "pool_size": 30,
                "max_overflow": 50,
                "pool_timeout": 60.0,
            })

        self.engine = create_async_engine(self.database_url, **engine_opts)
        self.sync_engine = create_engine(self.sync_url, **engine_opts)

        # FIX C2: Enable WAL journal mode and FK enforcement for SQLite.
        # WAL allows concurrent reads while writing; FK enforcement prevents orphaned rows.
        is_sqlite = self.database_url.startswith("sqlite")

        if is_sqlite:
            # Async engine: WAL + FK pragma via connection event
            @event.listens_for(self.engine.sync_engine, "connect")
            def _set_sqlite_pragmas_async(dbapi_connection, connection_record):
                cursor = dbapi_connection.cursor()
                cursor.execute("PRAGMA journal_mode=WAL")
                cursor.execute("PRAGMA foreign_keys=ON")
                cursor.execute("PRAGMA synchronous=NORMAL")
                cursor.close()

            # Sync engine: same pragmas
            @event.listens_for(self.sync_engine, "connect")
            def _set_sqlite_pragmas_sync(dbapi_connection, connection_record):
                cursor = dbapi_connection.cursor()
                cursor.execute("PRAGMA journal_mode=WAL")
                cursor.execute("PRAGMA foreign_keys=ON")
                cursor.execute("PRAGMA synchronous=NORMAL")
                cursor.close()

        # Create all tables & auto-migrate missing columns for existing SQLite tables
        async with self.engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        Base.metadata.create_all(self.sync_engine)
        self._auto_migrate_sqlite_columns()

        self._session_factory = async_sessionmaker(
            bind=self.engine,
            class_=AsyncSession,
            expire_on_commit=False
        )
        self._sync_session_factory = sessionmaker(
            bind=self.sync_engine,
            class_=Session,
            autocommit=False,
            autoflush=False
        )

        # Wire the global get_db / SessionLocal helpers
        global _db_manager_ref
        _db_manager_ref = self

        logger.info("Database tables created")

        # Start background cleanup task for expired tokens and rate limits
        import asyncio
        asyncio.create_task(self._cleanup_loop())
        logger.info("[DB] Background cleanup task started (token blacklist + rate limits)")

    async def _cleanup_loop(self):
        """Periodic background task: purge expired TokenBlacklist and RateLimit entries."""
        from sqlalchemy import delete
        INTERVAL_HOURS = 1
        while True:
            try:
                await asyncio.sleep(INTERVAL_HOURS * 3600)
                now = datetime.now(timezone.utc).replace(tzinfo=None)  # naive UTC for comparison
                async with self.session() as session:
                    # Purge expired revoked JWT tokens
                    result = await session.execute(
                        delete(TokenBlacklist).where(TokenBlacklist.expires_at < now)
                    )
                    token_count = result.rowcount

                    # Purge expired rate limit locks
                    result = await session.execute(
                        delete(RateLimit).where(
                            RateLimit.locked_until != None,  # noqa: E711
                            RateLimit.locked_until < now
                        )
                    )
                    rate_count = result.rowcount
                    await session.commit()

                if token_count or rate_count:
                    logger.info(
                        f"[DB-Cleanup] Pruned {token_count} expired tokens, "
                        f"{rate_count} expired rate-limit locks"
                    )
            except asyncio.CancelledError:
                break
            except Exception as _exc:
                logger.warning(f"[DB-Cleanup] Error during cleanup: {_exc}")

    def _auto_migrate_sqlite_columns(self):
        """Auto-add any missing columns to existing SQLite tables based on Base.metadata."""
        if not self.sync_engine:
            return
        try:
            with self.sync_engine.connect() as conn:
                for table_name, table in Base.metadata.tables.items():
                    try:
                        res = conn.exec_driver_sql(f"PRAGMA table_info('{table_name}')")
                        existing_cols = {row[1] for row in res.fetchall()}
                        if not existing_cols:
                            continue
                        for col in table.columns:
                            if col.name not in existing_cols:
                                col_type = col.type.compile(self.sync_engine.dialect)
                                logger.info(f"[DB Auto-Migrate] Adding missing column '{col.name}' ({col_type}) to table '{table_name}'")
                                conn.exec_driver_sql(f"ALTER TABLE '{table_name}' ADD COLUMN '{col.name}' {col_type}")
                    except Exception as t_err:
                        logger.debug(f"[DB Auto-Migrate] Table {table_name} check: {t_err}")
                conn.commit()
        except Exception as exc:
            logger.warning(f"[DB Auto-Migrate] Migration warning: {exc}")

    def session(self) -> AsyncSession:
        """Get an async database session"""
        if not self._session_factory:
            raise RuntimeError("Must call await initialize() first")
        return self._session_factory()

    def sync_session(self) -> Session:
        """Get a sync database session"""
        if not self._sync_session_factory:
            raise RuntimeError("Must call await initialize() first")
        return self._sync_session_factory()

    async def add_default_users(self, admin_hash: str, operator_hash: str):
        """Add default users if they don't exist"""
        from sqlalchemy.future import select
        async with self.session() as session:
            result = await session.execute(select(User).filter_by(username='admin'))
            if not result.scalars().first():
                session.add(User(
                    username='admin',
                    password_hash=admin_hash,
                    role='admin',
                    display_name='Administrator'
                ))
            result = await session.execute(select(User).filter_by(username='operator'))
            if not result.scalars().first():
                session.add(User(
                    username='operator',
                    password_hash=operator_hash,
                    role='operator',
                    display_name='Operator'
                ))
            await session.commit()
        logger.info("Default users ensured")

    async def close(self):
        """Close database connections gracefully.

        FIX: aiosqlite.close() internally does `await future` which raises
        asyncio.CancelledError if the event loop is being torn down concurrently.
        We catch CancelledError explicitly so shutdown logs stay clean.
        """
        if self.engine:
            try:
                await self.engine.dispose()
            except Exception as exc:
                # CancelledError subclasses BaseException in Python 3.8+
                logger.debug("Database async engine dispose: %s (non-fatal on shutdown)", exc)
        if self.sync_engine:
            try:
                self.sync_engine.dispose()
            except Exception as exc:
                logger.debug("Database sync engine dispose: %s (non-fatal on shutdown)", exc)
        logger.info("Database connections closed")


# ── Model registration ────────────────────────────────────────────────────────
# Import module-specific models so they register in Base.metadata and are
# auto-created by DatabaseManager.initialize() → Base.metadata.create_all().
# Delayed import avoids circular dependencies.

def _register_module_models():
    """
    Auto-discover models/ in each module directory to ensure they are
    registered in Base.metadata for automatic table creation.
    """
    import os
    from pathlib import Path
    import importlib

    base_dir = Path(__file__).parent.parent.parent
    modules_dir = base_dir / "modules"

    if not modules_dir.exists():
        return

    for entry in os.listdir(modules_dir):
        mod_path = modules_dir / entry
        if mod_path.is_dir() and (mod_path / "models").exists():
            # Try to import modules.<entry>.models
            try:
                full_module_name = f"modules.{entry}.models"
                importlib.import_module(full_module_name)
                # logger.debug(f"  ✅ Registered models for module: {entry}")
            except Exception as e:
                # Some modules might have models dir but no __init__.py or other issues
                logger.warning(f"Failed to register models for module '{entry}': {e}")


_register_module_models()

