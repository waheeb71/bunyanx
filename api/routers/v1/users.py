"""
Enterprise bunyanx - User & Rules Management Endpoints  (Admin only)
GET    /api/v1/users             — List users
POST   /api/v1/users             — Create user
DELETE /api/v1/users/{username}  — Remove user
GET    /api/v1/users/{username}/rules  — List user rules
POST   /api/v1/users/{username}/rules  — Add resource rule
DELETE /api/v1/users/{username}/rules/{rule_id} — Remove rule
"""
import logging
from fastapi import APIRouter, HTTPException, Depends, Request, status
from pydantic import BaseModel, Field
from typing import Optional

from api.core.auth import require_admin, _hash_password
from system.database.database import User, Rule

router = APIRouter(prefix="/api/v1/users", tags=["User Management"])
logger = logging.getLogger(__name__)


# ── Schemas ───────────────────────────────────────────────────────────────────

class UserCreate(BaseModel):
    username: str = Field(..., min_length=3, max_length=64)
    password: str = Field(..., min_length=8)
    role: str = Field("operator", description="'admin', 'operator', or 'viewer'")


class RuleCreate(BaseModel):
    resource: str = Field(..., description="Resource name: 'firewall', 'vpn', 'waf', 'qos', etc.")
    description: Optional[str] = None


# ── Helpers ───────────────────────────────────────────────────────────────────

def _db(request: Request):
    if not hasattr(request.app.state, "bunyanx") or not request.app.state.bunyanx:
        raise HTTPException(status_code=503, detail="bunyanx not initialized")
    return request.app.state.bunyanx.db


# ── User CRUD ─────────────────────────────────────────────────────────────────

@router.get("/")
async def list_users(request: Request, token: dict = Depends(require_admin)):
    """Return all users (admin only)."""
    from sqlalchemy.future import select
    async with _db(request).session() as session:
        result = await session.execute(select(User))
        users = result.scalars().all()
        return [{"id": u.id, "username": u.username, "role": u.role, "last_login": u.last_login} for u in users]


@router.post("/", status_code=status.HTTP_201_CREATED)
async def create_user(request: Request, payload: UserCreate, token: dict = Depends(require_admin)):
    """Create a new system user (admin only)."""
    VALID_ROLES = {"admin", "operator", "viewer"}
    if payload.role not in VALID_ROLES:
        raise HTTPException(status_code=400, detail=f"Invalid role. Must be one of: {VALID_ROLES}")

    from sqlalchemy.future import select
    from system.database.database import AuditLog
    db = _db(request)
    async with db.session() as session:
        result = await session.execute(select(User).filter(User.username == payload.username))
        existing = result.scalars().first()
        if existing:
            raise HTTPException(status_code=409, detail="Username already exists")
        user = User(
            username=payload.username,
            password_hash=_hash_password(payload.password),
            role=payload.role
        )
        session.add(user)
        # ── AuditLog ──────────────────────────────────────────────────────────
        session.add(AuditLog(
            username=token.get("sub", "unknown"),
            action=f"user_create:{payload.username}",
            resource="users",
            details={"new_user": payload.username, "role": payload.role},
            ip_address=request.client.host if request.client else None,
        ))
        await session.commit()
        await session.refresh(user)
        return {"status": "created", "username": user.username, "role": user.role}


@router.delete("/{username}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_user(request: Request, username: str, token: dict = Depends(require_admin)):
    """Delete a user (admin only). Cannot delete yourself."""
    if token.get("sub") == username:
        raise HTTPException(status_code=400, detail="You cannot delete your own account.")

    from sqlalchemy.future import select
    from system.database.database import AuditLog
    db = _db(request)
    async with db.session() as session:
        result = await session.execute(select(User).filter(User.username == username))
        user = result.scalars().first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        # ── AuditLog ──────────────────────────────────────────────────────────
        session.add(AuditLog(
            username=token.get("sub", "unknown"),
            action=f"user_delete:{username}",
            resource="users",
            details={"deleted_user": username, "role": user.role},
            ip_address=request.client.host if request.client else None,
        ))
        await session.delete(user)
        await session.commit()


# ── Rules (Resource-Level Permissions) ────────────────────────────────────────

@router.get("/{username}/rules")
async def list_user_rules(request: Request, username: str, token: dict = Depends(require_admin)):
    """
    List all resource access rules assigned to a user.
    Rules are checked by make_permission_checker() in auth.py.
    """
    from sqlalchemy.future import select
    db = _db(request)
    async with db.session() as session:
        user_res = await session.execute(select(User).filter(User.username == username))
        user = user_res.scalars().first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        rules_res = await session.execute(select(Rule).filter(Rule.user_id == user.id))
        rules = rules_res.scalars().all()
        return [{"id": r.id, "resource": r.resource, "enabled": r.enabled, "description": getattr(r, "description", "")} for r in rules]


@router.post("/{username}/rules", status_code=status.HTTP_201_CREATED)
async def add_user_rule(request: Request, username: str, rule: RuleCreate, token: dict = Depends(require_admin)):
    """Grant a user access to a specific resource/module (admin only)."""
    from sqlalchemy.future import select
    db = _db(request)
    async with db.session() as session:
        user_res = await session.execute(select(User).filter(User.username == username))
        user = user_res.scalars().first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
            
        existing_res = await session.execute(select(Rule).filter(Rule.user_id == user.id, Rule.resource == rule.resource))
        existing = existing_res.scalars().first()
        if existing:
            existing.enabled = True
            await session.commit()
            return {"status": "updated", "resource": rule.resource, "enabled": True}
            
        new_rule = Rule(user_id=user.id, resource=rule.resource, enabled=True)
        session.add(new_rule)
        await session.commit()
        await session.refresh(new_rule)
        return {"status": "created", "id": new_rule.id, "resource": rule.resource}


@router.delete("/{username}/rules/{rule_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_user_rule(request: Request, username: str, rule_id: int, token: dict = Depends(require_admin)):
    """Revoke a resource rule from a user (admin only)."""
    from sqlalchemy.future import select
    db = _db(request)
    async with db.session() as session:
        user_res = await session.execute(select(User).filter(User.username == username))
        user = user_res.scalars().first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
            
        rule_res = await session.execute(select(Rule).filter(Rule.id == rule_id, Rule.user_id == user.id))
        rule = rule_res.scalars().first()
        if not rule:
            raise HTTPException(status_code=404, detail="Rule not found")
            
        await session.delete(rule)
        await session.commit()
