from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, status
from sqlalchemy.orm import Session
from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional
import threading

from api.core.auth import make_permission_checker, require_admin
from system.database.database import get_db
from modules.web_filter.models import WebFilterConfig, WebFilterCategory, WebFilterDomain

class ConfigUpdateSchema(BaseModel):
    enabled: Optional[bool] = None
    mode: Optional[str] = None
    safe_search_enabled: Optional[bool] = None
    default_action: Optional[str] = None
    ai_holofilter: Optional[Dict[str, Any]] = None
    cache: Optional[Dict[str, Any]] = None
    dns_sinkhole: Optional[Dict[str, Any]] = None
    logging: Optional[Dict[str, Any]] = None
    safe_search: Optional[Dict[str, Any]] = None
    builtin_categories: Optional[List[Dict[str, Any]]] = None
    custom_rules: Optional[List[Dict[str, Any]]] = None

class CategoryCreateSchema(BaseModel):
    name: str
    description: Optional[str] = ""
    action: Optional[str] = "BLOCK"
    risk_score: Optional[int] = 50

class CategoryUpdateSchema(BaseModel):
    description: Optional[str] = None
    action: Optional[str] = None
    risk_score: Optional[int] = None

class DomainCreateSchema(BaseModel):
    domain_pattern: str
    category_name: Optional[str] = None
    action: Optional[str] = "BLOCK"

class DomainUpdateSchema(BaseModel):
    category_name: Optional[str] = None
    action: Optional[str] = None

router = APIRouter(prefix="/api/v1/web_filter", tags=["web_filter"])
require_web_filter = make_permission_checker("web_filter")

# --- INITIALIZATION ---
def get_or_create_config(db: Session) -> WebFilterConfig:
    config = db.query(WebFilterConfig).first()
    if not config:
        config = WebFilterConfig()
        db.add(config)
        db.commit()
        db.refresh(config)
    return config

import os
from datetime import datetime
from modules.web_filter.config.loader import config as file_config

# --- STATUS ---
@router.get("/status")
def get_status(db: Session = Depends(get_db), token: dict = Depends(require_web_filter)):
    db_config = get_or_create_config(db)
    domain_count = db.query(WebFilterDomain).count()
    category_count = db.query(WebFilterCategory).count()
    
    # ML Analytics Introspection
    ai_cfg = file_config.holofilter
    model_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "evaluation", "datasets", "offline_hv.npz"))
    if not os.path.exists(model_path):
        fallback_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "evaluation", "offline_hv.npz"))
        if os.path.exists(fallback_path):
            model_path = fallback_path
            
    last_trained = "Never"
    if os.path.exists(model_path):
        mtime = os.path.getmtime(model_path)
        last_trained = datetime.fromtimestamp(mtime).strftime("%Y-%m-%d %H:%M:%S")
        
    return {
        "status": "active" if db_config.enabled else "disabled", 
        "mode": db_config.mode,
        "module": "web_filter",
        "stats": {
            "domains": domain_count,
            "categories": category_count
        },
        "ml_analytics": {
            "engine_status": "ONLINE" if ai_cfg.get("enabled", True) else "OFFLINE",
            "last_trained": last_trained,
            "block_threshold": f"{ai_cfg.get('action_threshold_score', 70)}%",
            "vector_dimensions": ai_cfg.get("vector_dimensions", 10048)
        }
    }

# --- CONFIG ---
@router.get("/config")
def get_config(db: Session = Depends(get_db), token: dict = Depends(require_web_filter)):
    return get_or_create_config(db).to_dict()

@router.put("/config")
def update_config(payload: ConfigUpdateSchema, db: Session = Depends(get_db), token: dict = Depends(require_web_filter)):
    config = get_or_create_config(db)
    data = payload.model_dump(exclude_unset=True)
    if "enabled" in data: config.enabled = data["enabled"]
    if "mode" in data: config.mode = data["mode"]
    if "safe_search_enabled" in data: config.safe_search_enabled = data["safe_search_enabled"]
    if "default_action" in data: config.default_action = data["default_action"]
    
    if "ai_holofilter" in data: config.ai_holofilter = data["ai_holofilter"]
    if "cache" in data: config.cache = data["cache"]
    if "dns_sinkhole" in data: config.dns_sinkhole = data["dns_sinkhole"]
    if "logging" in data: config.logging = data["logging"]
    if "safe_search" in data: config.safe_search = data["safe_search"]
    if "builtin_categories" in data: config.builtin_categories = data["builtin_categories"]
    if "custom_rules" in data: config.custom_rules = data["custom_rules"]
        
    db.commit()
    db.refresh(config)
    try:
        from modules.web_filter.policy.engine import WebFilterEngine
        WebFilterEngine().reload()
    except Exception as e:
        import logging
        logging.getLogger(__name__).error(f"Failed to reload WebFilterEngine after config update: {e}")
    return config.to_dict()

# --- CATEGORIES ---
@router.get("/categories")
def list_categories(db: Session = Depends(get_db), token: dict = Depends(require_web_filter)):
    categories = db.query(WebFilterCategory).all()
    return [c.to_dict() for c in categories]

@router.post("/categories")
def create_category(payload: CategoryCreateSchema, db: Session = Depends(get_db), token: dict = Depends(require_web_filter)):
    name = payload.name.strip()
    if not name:
        raise HTTPException(status_code=400, detail="Name is required")
        
    if db.query(WebFilterCategory).filter_by(name=name).first():
        raise HTTPException(status_code=400, detail="Category already exists")
        
    category = WebFilterCategory(
        name=name,
        description=payload.description or "",
        action=payload.action or "BLOCK",
        risk_score=payload.risk_score if payload.risk_score is not None else 50,
        is_custom=True
    )
    db.add(category)
    db.commit()
    db.refresh(category)
    try:
        from modules.web_filter.policy.engine import WebFilterEngine
        WebFilterEngine().reload()
    except Exception as e:
        import logging
        logging.getLogger(__name__).error(f"Failed to reload WebFilterEngine after category creation: {e}")
    return category.to_dict()

@router.put("/categories/{cat_id}")
def update_category(cat_id: int, payload: CategoryUpdateSchema, db: Session = Depends(get_db), token: dict = Depends(require_web_filter)):
    """Update an existing category (e.g. change action or risk_score)"""
    cat = db.query(WebFilterCategory).filter(WebFilterCategory.id == cat_id).first()
    if not cat:
        raise HTTPException(status_code=404, detail="Category not found")
        
    data = payload.model_dump(exclude_unset=True)
    if "description" in data:
        cat.description = data["description"]
    if "action" in data:
        cat.action = data["action"]
    if "risk_score" in data:
        cat.risk_score = data["risk_score"]
        
    db.commit()
    db.refresh(cat)
    try:
        from modules.web_filter.policy.engine import WebFilterEngine
        WebFilterEngine().reload()
    except Exception as e:
        import logging
        logging.getLogger(__name__).error(f"Failed to reload WebFilterEngine after category update: {e}")
    return cat.to_dict()

@router.delete("/categories/{cat_id}")
def delete_category(cat_id: int, db: Session = Depends(get_db), token: dict = Depends(require_web_filter)):
    cat = db.query(WebFilterCategory).filter(WebFilterCategory.id == cat_id).first()
    if not cat:
        raise HTTPException(status_code=404, detail="Category not found")
        
    # Prevent deletion of builtin categories
    if not cat.is_custom:
        raise HTTPException(status_code=400, detail="Cannot delete built-in categories")
        
    db.delete(cat)
    db.commit()
    try:
        from modules.web_filter.policy.engine import WebFilterEngine
        WebFilterEngine().reload()
    except Exception as e:
        import logging
        logging.getLogger(__name__).error(f"Failed to reload WebFilterEngine after category deletion: {e}")
    return {"message": "Category deleted"}

# --- DOMAINS ---
@router.get("/domains")
def list_domains(db: Session = Depends(get_db), token: dict = Depends(require_web_filter)):
    domains = db.query(WebFilterDomain).all()
    return [d.to_dict() for d in domains]

@router.post("/domains")
def add_domain(payload: DomainCreateSchema, db: Session = Depends(get_db), token: dict = Depends(require_web_filter)):
    domain_pattern = payload.domain_pattern.strip()
    if not domain_pattern:
        raise HTTPException(status_code=400, detail="domain_pattern is required")
        
    # Validate pattern format
    import re
    if not re.match(r'^[a-zA-Z0-9\.\-\_\*\?]+$', domain_pattern):
        raise HTTPException(status_code=400, detail="Domain pattern contains invalid characters")
    if not any(c.isalnum() for c in domain_pattern):
        raise HTTPException(status_code=400, detail="Domain pattern must contain at least one alphanumeric character")
        
    if db.query(WebFilterDomain).filter_by(domain_pattern=domain_pattern).first():
        raise HTTPException(status_code=400, detail="Domain pattern already exists")
        
    domain = WebFilterDomain(
        domain_pattern=domain_pattern,
        category_name=payload.category_name,
        action=payload.action or "BLOCK"
    )
    db.add(domain)
    db.commit()
    db.refresh(domain)
    try:
        from modules.web_filter.policy.engine import WebFilterEngine
        WebFilterEngine().reload()
    except Exception as e:
        import logging
        logging.getLogger(__name__).error(f"Failed to reload WebFilterEngine after domain addition: {e}")
    return domain.to_dict()

@router.put("/domains/{domain_id}")
def update_domain(domain_id: int, payload: DomainUpdateSchema, db: Session = Depends(get_db), token: dict = Depends(require_web_filter)):
    domain = db.query(WebFilterDomain).filter(WebFilterDomain.id == domain_id).first()
    if not domain:
        raise HTTPException(status_code=404, detail="Domain not found")
        
    data = payload.model_dump(exclude_unset=True)
    if "category_name" in data:
        domain.category_name = data["category_name"]
    if "action" in data:
        domain.action = data["action"]
        
    db.commit()
    db.refresh(domain)
    try:
        from modules.web_filter.policy.engine import WebFilterEngine
        WebFilterEngine().reload()
    except Exception as e:
        import logging
        logging.getLogger(__name__).error(f"Failed to reload WebFilterEngine after domain update: {e}")
    return domain.to_dict()

@router.delete("/domains/{domain_id}")
def delete_domain(domain_id: int, db: Session = Depends(get_db), token: dict = Depends(require_web_filter)):
    domain = db.query(WebFilterDomain).filter(WebFilterDomain.id == domain_id).first()
    if not domain:
        raise HTTPException(status_code=404, detail="Domain not found")
        
    db.delete(domain)
    db.commit()
    try:
        from modules.web_filter.policy.engine import WebFilterEngine
        WebFilterEngine().reload()
    except Exception as e:
        import logging
        logging.getLogger(__name__).error(f"Failed to reload WebFilterEngine after domain deletion: {e}")
    return {"message": "Domain deleted"}

from fastapi import BackgroundTasks

_training_lock = threading.Lock()
_training_status = {
    "status": "idle",
    "last_run": None,
    "error": None
}

def run_training():
    global _training_status
    if not _training_lock.acquire(blocking=False):
        return
    try:
        _training_status["status"] = "running"
        _training_status["error"] = None
        from modules.web_filter.evaluation.trainer import build_academic_model
        data_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "evaluation", "datasets"))
        build_academic_model(data_dir=data_dir)
        _training_status["status"] = "completed"
        _training_status["last_run"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    except Exception as e:
        import logging
        _training_status["status"] = "failed"
        _training_status["error"] = str(e)
        logging.getLogger(__name__).error(f"HoloFilter background training failed: {e}")
    finally:
        _training_lock.release()

@router.post("/train")
def trigger_training(background_tasks: BackgroundTasks, token: dict = Depends(require_web_filter)):
    if _training_status["status"] == "running":
        raise HTTPException(status_code=409, detail="Model training is already in progress")
    background_tasks.add_task(run_training)
    return {"message": "Model training started in background", "status": "running"}

@router.get("/train/status")
def get_training_status(token: dict = Depends(require_web_filter)):
    return _training_status

