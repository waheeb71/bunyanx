from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from typing import List, Literal, Optional
from pydantic import BaseModel, Field
from datetime import datetime
from sqlalchemy.orm import Session
from system.database.database import get_db, AuditLog
from api.core.auth import require_admin, make_permission_checker
from modules.http_inspection.models import (
    HTTPSuspiciousPattern as DBPattern,
    HTTPInspectionConfig as DBConfig,
    HTTPInspectionLog as DBLog
)

router = APIRouter(prefix="/api/v1/http_inspection", tags=["http_inspection"])

require_http = make_permission_checker("http_inspection")

# --- Pydantic Schemas ---
class PatternBase(BaseModel):
    # P1-R4: Literal validation — only valid targets accepted
    target: Literal['url', 'header', 'body'] = Field(..., description="'url', 'header', or 'body'")
    target_key: Optional[str] = Field(None, description="Specific header name if target is 'header'", max_length=50)
    pattern: str = Field(..., description="Regex pattern", max_length=200)
    description: Optional[str] = Field(None, max_length=255)
    # P1-R2: Literal validation — only valid severities accepted
    severity: Literal['HIGH', 'MEDIUM', 'LOW'] = Field('MEDIUM', description="HIGH, MEDIUM, LOW")
    enabled: bool = True


class PatternCreate(PatternBase):
    pass


class PatternResponse(PatternBase):
    id: int
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class ConfigSchema(BaseModel):
    is_active: bool = True
    # P1-R3: Literal validation — only valid modes accepted
    mode: Literal['enforce', 'monitor'] = Field('enforce', description="'enforce' or 'monitor'")
    block_dangerous_methods: bool = True
    scan_headers: bool = True
    scan_body: bool = True
    # P1-R1 + H-4: Default reduced from 100 to 10 MB; bounded between 1 and 500
    max_upload_size_mb: int = Field(10, ge=1, le=500, description="Max upload size in MB (1-500)")
    cache_ttl_seconds: int = Field(5, ge=1, le=300, description="Pattern cache TTL in seconds")
    
    # Missing YAML fields added
    log_pool_max_workers: int = Field(2, description="Max workers for logging")
    max_pattern_length: int = Field(500, description="Max length of inspection pattern")
    payload_max_bytes: int = Field(1048576, description="Max payload bytes to inspect")
    url_max_length: int = Field(4096, description="Max length of URL")

    class Config:
        from_attributes = True



class LogResponse(BaseModel):
    id: int
    timestamp: datetime
    source_ip: str
    target_host: Optional[str]
    url_path: Optional[str]
    request_method: Optional[str]
    user_agent_hash: Optional[str]
    flow_id: Optional[str]
    pattern_matched: Optional[str]
    severity: str
    action: str
    details: Optional[str]

    class Config:
        from_attributes = True


# --- API Endpoints: System Status & Config ---
@router.get("/status")
async def get_status(token: dict = Depends(require_http)):
    return {"status": "active", "module": "http_inspection"}


@router.get("/config", response_model=ConfigSchema)
async def get_config(db: Session = Depends(get_db), token: dict = Depends(require_http)):
    config = db.query(DBConfig).first()
    if not config:
        config = DBConfig()
        db.add(config)
        db.commit()
        db.refresh(config)
    return config


@router.put("/config", response_model=ConfigSchema)
async def update_config(
    new_config: ConfigSchema,
    db: Session = Depends(get_db),
    token: dict = Depends(require_admin)
):
    config = db.query(DBConfig).first()
    if not config:
        config = DBConfig()
        db.add(config)

    for key, value in new_config.dict().items():
        setattr(config, key, value)

    db.commit()
    db.refresh(config)

    audit = AuditLog(
        action="update",
        resource="http_inspection",
        username=token.get("sub", "system") if isinstance(token, dict) else "system",
        details={"info": f"Updated HTTP WAF Config: Active={config.is_active}, Mode={config.mode}, Max Upload={config.max_upload_size_mb}MB"}
    )
    db.add(audit)
    db.commit()

    return config


# --- API Endpoints: Patterns ---
@router.get("/patterns", response_model=List[PatternResponse])
async def list_patterns(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    db: Session = Depends(get_db),
    token: dict = Depends(require_http)
):
    return db.query(DBPattern).offset(skip).limit(limit).all()


@router.post("/patterns", response_model=PatternResponse, status_code=status.HTTP_201_CREATED)
async def create_pattern(
    pattern: PatternCreate,
    db: Session = Depends(get_db),
    token: dict = Depends(require_admin)
):
    db_pattern = DBPattern(**pattern.dict())
    db.add(db_pattern)
    db.commit()
    db.refresh(db_pattern)

    audit = AuditLog(
        action="create",
        resource="http_pattern",
        username=token.get("sub", "system") if isinstance(token, dict) else "system",
        details={"info": f"Created custom HTTP Attack Pattern: {db_pattern.description} (Target: {db_pattern.target})"}
    )
    db.add(audit)
    db.commit()

    return db_pattern


@router.put("/patterns/{pattern_id}", response_model=PatternResponse)
async def update_pattern(
    pattern_id: int,
    updated: PatternCreate,
    db: Session = Depends(get_db),
    token: dict = Depends(require_admin)
):
    db_pattern = db.query(DBPattern).filter(DBPattern.id == pattern_id).first()
    if not db_pattern:
        raise HTTPException(status_code=404, detail="Pattern not found")

    for key, value in updated.dict().items():
        setattr(db_pattern, key, value)

    db.commit()
    db.refresh(db_pattern)

    audit = AuditLog(
        action="update",
        resource="http_pattern",
        username=token.get("sub", "system") if isinstance(token, dict) else "system",
        details={"info": f"Updated custom HTTP Attack Pattern ID: {pattern_id} (Enabled: {db_pattern.enabled})"}
    )
    db.add(audit)
    db.commit()

    return db_pattern


@router.delete("/patterns/{pattern_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_pattern(
    pattern_id: int,
    db: Session = Depends(get_db),
    token: dict = Depends(require_admin)
):
    db_pattern = db.query(DBPattern).filter(DBPattern.id == pattern_id).first()
    if not db_pattern:
        raise HTTPException(status_code=404, detail="Pattern not found")

    db.delete(db_pattern)
    db.commit()

    audit = AuditLog(
        action="delete",
        resource="http_pattern",
        username=token.get("sub", "system") if isinstance(token, dict) else "system",
        details={"info": f"Deleted custom HTTP Attack Pattern ID: {pattern_id}"}
    )
    db.add(audit)
    db.commit()

    return None


# --- API Endpoints: Attack Logs ---
@router.get("/logs", response_model=List[LogResponse])
async def get_attack_logs(
    limit: int = Query(100, ge=1, le=1000),
    db: Session = Depends(get_db),
    token: dict = Depends(require_http)
):
    """Fetch the most recent HTTP attacks blocked by the Inspector Engine."""
    logs = db.query(DBLog).order_by(DBLog.timestamp.desc()).limit(limit).all()
    return logs
