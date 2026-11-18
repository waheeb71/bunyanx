"""
Enterprise bunyanx - Authentication & Authorization Layer
Handles JWT token creation, verification, and role-based access control (RBAC).
"""
import os
import secrets
import logging
from datetime import datetime, timedelta
from typing import Optional, List

import bcrypt
import jwt
from fastapi import HTTPException, Depends, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel

logger = logging.getLogger(__name__)

# ==================== JWT Configuration ====================
_env_secret = os.getenv("bunyanx_SECRET_KEY", "")

SECRET_KEY = _env_secret if _env_secret else secrets.token_hex(32)
if not _env_secret:
    logger.warning("⚠️ bunyanx_SECRET_KEY not set! Using auto-generated key. Set for production.")

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("bunyanx_TOKEN_EXPIRE_MINUTES", "30"))
# ==================== Pydantic Models ====================
class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"
    role: str = ""
    expires_in: int = ACCESS_TOKEN_EXPIRE_MINUTES * 60


class LoginRequest(BaseModel):
    username: str
    password: str
# ==================== Password Utilities ====================
def _hash_password(password: str) -> str:
    """Hash a password using bcrypt"""
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def _verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against its bcrypt hash"""
    return bcrypt.checkpw(plain_password.encode("utf-8"), hashed_password.encode("utf-8"))


# ==================== Token Utilities ====================
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """Create a signed JWT access token."""
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


# ==================== FastAPI Security Dependencies ====================

security = HTTPBearer()


async def verify_token(request: Request, credentials: HTTPAuthorizationCredentials = Depends(security)) -> dict:
    """Verify JWT token and check against blacklist."""
    try:
        token = credentials.credentials
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        if payload.get("sub") is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
            
        # Check TokenBlacklist
        bunyanx = getattr(request.app.state, "bunyanx", None)
        if bunyanx and bunyanx.db:
            from sqlalchemy.future import select
            from system.database.database import TokenBlacklist
            async with bunyanx.db.session() as session:
                res = await session.execute(select(TokenBlacklist).filter_by(token=token))
                if res.scalars().first():
                    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token has been revoked")
                    
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token expired")
    except jwt.PyJWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Could not validate credentials")


def require_admin(token_data: dict = Depends(verify_token)) -> dict:
    """Require 'admin' role. Admins bypass all resource-level permission checks."""
    if token_data.get("role") != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin privileges required")
    return token_data


def require_operator(token_data: dict = Depends(verify_token)) -> dict:
    """Require 'admin' or 'operator' role."""
    if token_data.get("role") not in ("admin", "operator"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Operator or Admin privileges required")
    return token_data


def make_permission_checker(resource: str):
    """
    Factory that returns a FastAPI dependency verifying a user has the given resource rule.
    Admins bypass all checks.
    Usage:  token = Depends(make_permission_checker("firewall"))
    """
    async def check(request: Request, token_data: dict = Depends(verify_token)) -> dict:
        role = token_data.get("role", "")
        if role == "admin":
            return token_data

        # Read allowed resources from DB
        try:
            db = request.app.state.bunyanx.db
            from sqlalchemy.future import select
            async with db.session() as session:
                from system.database.database import Rule, User
                user_res = await session.execute(select(User).filter(User.username == token_data["sub"]))
                user = user_res.scalars().first()
                if user:
                    rules_res = await session.execute(
                        select(Rule).filter(
                            Rule.user_id == user.id,
                            Rule.resource == resource,
                            Rule.enabled == True
                        )
                    )
                    rules = rules_res.scalars().first()
                    if rules:
                        return token_data
        except Exception:
            pass

        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Access to '{resource}' requires an explicit permission rule for your account."
        )

    return check
