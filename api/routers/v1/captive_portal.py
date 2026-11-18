"""
api/routers/v1/captive_portal.py
==================================
REST API endpoints for the Captive Portal system.

Public endpoints (no auth required — accessed by guest browsers):
    GET  /captive/login          → HTML login page
    POST /captive/login          → Submit credentials / guest code
    POST /captive/logout         → Explicit logout
    GET  /captive/status/{ip}    → Check if IP is authenticated (used by firewall policy)

Admin endpoints (require admin JWT):
    GET  /api/v1/captive/sessions          → List all active sessions
    GET  /api/v1/captive/guest-passes      → List all guest passes
    POST /api/v1/captive/guest-passes      → Generate new guest pass
    DELETE /api/v1/captive/guest-passes/{code} → Revoke a guest pass
    DELETE /api/v1/captive/sessions/{ip}   → Force logout an IP
    GET  /api/v1/captive/config            → Show captive portal config
"""

from __future__ import annotations

import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, Field
from api.core.auth import require_admin

logger = logging.getLogger(__name__)

# ── Two routers: public (browser-facing) + admin (JWT-protected) ─────────────
router = APIRouter()

# ── Helpers ───────────────────────────────────────────────────────────────────

def _get_manager():
    """Lazy-load CaptivePortalManager singleton."""
    from system.auth.captive_portal_bridge import CaptivePortalManager
    mgr = CaptivePortalManager.get()
    if mgr is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Captive portal not initialized",
        )
    if not mgr.enabled:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Captive portal is disabled in configuration",
        )
    return mgr


def _client_ip(request: Request) -> str:
    """Extract real client IP (supports X-Forwarded-For)."""
    xff = request.headers.get("X-Forwarded-For")
    if xff:
        return xff.split(",")[0].strip()
    if request.client:
        return request.client.host
    return "0.0.0.0"


# ── Pydantic schemas ─────────────────────────────────────────────────────────

class LoginRequest(BaseModel):
    guest_code: str  = Field("", description="Guest pass code (for guest_pass mode)")
    username:   str  = Field("", description="Username (for ldap mode)")
    password:   str  = Field("", description="Password (for ldap mode)")
    mac_address: str = Field("", description="Client MAC address (optional)")


class GuestPassCreateRequest(BaseModel):
    valid_hours: Optional[int]  = Field(None, description="Override validity in hours")
    single_use:  Optional[bool] = Field(None, description="Override single-use setting")
    max_uses:    int             = Field(0,    description="Max number of devices (0 = unlimited)")
    created_by:  str             = Field("admin", description="Who is issuing this pass")


# ── Public endpoints ─────────────────────────────────────────────────────────

@router.get(
    "/captive/login",
    response_class=HTMLResponse,
    tags=["Captive Portal"],
    summary="Captive portal login page",
    include_in_schema=False,   # Don't expose in Swagger — it's a browser page
)
async def captive_login_page(request: Request):
    """
    The HTML login page that guests see when their browser is redirected.
    The firewall/proxy redirects unauthenticated HTTP traffic to this URL.
    """
    try:
        mgr = _get_manager()
    except HTTPException:
        return HTMLResponse("<h1>Captive Portal Unavailable</h1>", status_code=503)

    mode = mgr.auth_mode
    return HTMLResponse(_build_login_html(mode))


@router.post(
    "/captive/login",
    tags=["Captive Portal"],
    summary="Authenticate via captive portal",
)
async def captive_login(request: Request, body: LoginRequest):
    """
    Called by the guest browser when submitting the login form.
    Returns redirect URL on success or error message on failure.
    """
    mgr     = _get_manager()
    src_ip  = _client_ip(request)

    result = mgr.authenticate(
        src_ip      = src_ip,
        mac_address = body.mac_address,
        username    = body.username,
        password    = body.password,
        guest_code  = body.guest_code,
    )

    if result["success"]:
        return {
            "success":      True,
            "message":      f"Welcome, {result['username']}!",
            "redirect_url": result["redirect_url"],
            "session_id":   result["session_id"],
        }
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=result.get("error", "Authentication failed"),
    )


@router.post(
    "/captive/logout",
    tags=["Captive Portal"],
    summary="Logout from captive portal",
)
async def captive_logout(request: Request, session_id: str = ""):
    """Explicitly terminate a portal session."""
    try:
        mgr = _get_manager()
    except HTTPException:
        return {"success": False, "message": "Portal unavailable"}

    src_ip = _client_ip(request)
    ok     = mgr.logout(src_ip=src_ip, session_id=session_id)
    return {"success": ok, "message": "Logged out" if ok else "Session not found"}


@router.get(
    "/captive/status",
    tags=["Captive Portal"],
    summary="Check if calling IP is authenticated",
)
async def captive_check_status(request: Request):
    """
    Lightweight check — called by the firewall redirect rule to decide
    whether to let traffic through or redirect to /captive/login.
    """
    try:
        mgr = _get_manager()
    except HTTPException:
        return {"authenticated": False, "reason": "portal_unavailable"}

    src_ip = _client_ip(request)
    auth   = mgr.is_authenticated(src_ip)
    return {
        "authenticated": auth,
        "src_ip":        src_ip,
        "reason":        "active_session" if auth else "not_authenticated",
    }


# ── Admin endpoints ──────────────────────────────────────────────────────────

@router.get(
    "/api/v1/captive/sessions",
    tags=["Captive Portal — Admin"],
    summary="List all active captive portal sessions",
)
async def list_captive_sessions(request: Request, token: dict = Depends(require_admin)):
    """Admin: list all active guest sessions."""
    mgr = _get_manager()
    return {"sessions": mgr.active_sessions(), "count": len(mgr.active_sessions())}


@router.delete(
    "/api/v1/captive/sessions/{src_ip}",
    tags=["Captive Portal — Admin"],
    summary="Force-logout a specific IP",
)
async def force_logout_ip(src_ip: str, request: Request, token: dict = Depends(require_admin)):
    """Admin: immediately terminate a guest session by IP."""
    mgr = _get_manager()
    ok  = mgr.logout(src_ip=src_ip)
    if not ok:
        raise HTTPException(status_code=404, detail=f"No active session for {src_ip}")
    return {"success": True, "message": f"Session for {src_ip} terminated"}


@router.get(
    "/api/v1/captive/guest-passes",
    tags=["Captive Portal — Admin"],
    summary="List all guest passes",
)
async def list_guest_passes(request: Request, token: dict = Depends(require_admin)):
    """Admin: view all guest pass codes and their status."""
    mgr = _get_manager()
    return {"guest_passes": mgr.list_guest_passes()}


@router.post(
    "/api/v1/captive/guest-passes",
    tags=["Captive Portal — Admin"],
    summary="Generate a new guest pass",
    status_code=status.HTTP_201_CREATED,
)
async def create_guest_pass(body: GuestPassCreateRequest, request: Request, token: dict = Depends(require_admin)):
    """
    Admin: generate a guest pass code to give to a visitor.
    The receptionist can print this and hand it to the guest.
    """
    mgr  = _get_manager()
    gp   = mgr.generate_guest_pass(
        created_by  = body.created_by or token.get("sub", "admin"),
        valid_hours = body.valid_hours,
        single_use  = body.single_use,
        max_uses    = body.max_uses,
    )
    return {
        "code":         gp.code,
        "created_by":   gp.created_by,
        "expires_at":   gp.expires_at,
        "single_use":   gp.single_use,
        "max_uses":     gp.max_uses,
        "message":      f"Guest pass created: {gp.code}",
    }


@router.delete(
    "/api/v1/captive/guest-passes/{code}",
    tags=["Captive Portal — Admin"],
    summary="Revoke a guest pass",
)
async def revoke_guest_pass(code: str, request: Request, token: dict = Depends(require_admin)):
    """Admin: invalidate a guest pass immediately."""
    mgr = _get_manager()
    ok  = mgr.revoke_guest_pass(code.upper())
    if not ok:
        raise HTTPException(status_code=404, detail=f"Guest pass '{code}' not found")
    return {"success": True, "message": f"Guest pass {code} revoked"}


@router.get(
    "/api/v1/captive/config",
    tags=["Captive Portal — Admin"],
    summary="Get captive portal status and configuration",
)
async def captive_portal_config(request: Request, token: dict = Depends(require_admin)):
    """Admin: view current captive portal configuration and runtime status."""
    mgr = _get_manager()
    return mgr.status()


# ── HTML template ─────────────────────────────────────────────────────────────

def _build_login_html(auth_mode: str) -> str:
    """Build the captive portal login page HTML."""

    if auth_mode == "guest_pass":
        form_fields = """
        <div class="field">
            <label>Guest Access Code</label>
            <input type="text" id="guest_code" name="guest_code"
                   placeholder="e.g. ABCD1234" autocomplete="off"
                   maxlength="12" style="text-transform:uppercase">
        </div>"""
        submit_label = "Connect"
        js_body = """
            body.guest_code = document.getElementById('guest_code').value.toUpperCase();"""

    elif auth_mode == "ldap":
        form_fields = """
        <div class="field">
            <label>Username</label>
            <input type="text" id="username" name="username" placeholder="company username">
        </div>
        <div class="field">
            <label>Password</label>
            <input type="password" id="password" name="password" placeholder="••••••••">
        </div>"""
        submit_label = "Sign In"
        js_body = """
            body.username = document.getElementById('username').value;
            body.password = document.getElementById('password').value;"""

    else:  # none / open
        form_fields = """
        <div class="field">
            <p style="color:#94a3b8">Click Connect to access the network.</p>
        </div>"""
        submit_label = "Connect"
        js_body = ""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Network Access — BunyanX Gateway</title>
<style>
  *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{
    font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
    background: linear-gradient(135deg, #0f172a 0%, #1e1b4b 50%, #0f172a 100%);
    min-height: 100vh; display: flex; align-items: center; justify-content: center;
  }}
  .card {{
    background: rgba(15, 23, 42, 0.85);
    backdrop-filter: blur(20px);
    border: 1px solid rgba(99, 102, 241, 0.3);
    border-radius: 16px; padding: 2.5rem 2rem;
    width: 100%; max-width: 420px;
    box-shadow: 0 25px 50px rgba(0,0,0,0.5), 0 0 80px rgba(99,102,241,0.1);
  }}
  .logo {{
    text-align: center; margin-bottom: 1.5rem;
  }}
  .logo .icon {{
    font-size: 3rem; display: block;
  }}
  h1 {{
    color: #f1f5f9; font-size: 1.4rem; text-align: center;
    margin-bottom: 0.4rem;
  }}
  .subtitle {{
    color: #64748b; font-size: 0.85rem; text-align: center; margin-bottom: 2rem;
  }}
  .field {{ margin-bottom: 1.2rem; }}
  label {{
    display: block; color: #94a3b8; font-size: 0.8rem;
    text-transform: uppercase; letter-spacing: 0.06em; margin-bottom: 0.5rem;
  }}
  input[type=text], input[type=password] {{
    width: 100%; padding: 0.75rem 1rem;
    background: rgba(30, 41, 59, 0.8);
    border: 1px solid rgba(99,102,241,0.3); border-radius: 8px;
    color: #f1f5f9; font-size: 1rem; outline: none;
    transition: border-color 0.2s;
  }}
  input:focus {{ border-color: #6366f1; box-shadow: 0 0 0 3px rgba(99,102,241,0.15); }}
  button {{
    width: 100%; padding: 0.85rem;
    background: linear-gradient(135deg, #6366f1, #8b5cf6);
    color: #fff; border: none; border-radius: 8px;
    font-size: 1rem; font-weight: 600; cursor: pointer;
    transition: opacity 0.2s, transform 0.1s;
    margin-top: 0.5rem;
  }}
  button:hover {{ opacity: 0.9; }}
  button:active {{ transform: scale(0.98); }}
  .error {{
    background: rgba(239, 68, 68, 0.15); border: 1px solid rgba(239,68,68,0.4);
    border-radius: 8px; color: #fca5a5; padding: 0.75rem; font-size: 0.85rem;
    margin-bottom: 1rem; display: none;
  }}
  .footer {{
    text-align: center; margin-top: 1.5rem; color: #475569; font-size: 0.75rem;
  }}
</style>
</head>
<body>
<div class="card">
  <div class="logo">
    <span class="icon">🛡️</span>
  </div>
  <h1>Guest Network Access</h1>
  <p class="subtitle">Secured by BunyanX Enterprise Gateway</p>

  <div class="error" id="error-msg"></div>

  <form id="login-form">
    {form_fields}
    <button type="submit" id="submit-btn">{submit_label}</button>
  </form>

  <div class="footer">
    By connecting, you agree to the acceptable use policy.<br>
    Your device and activity may be monitored for security purposes.
  </div>
</div>

<script>
document.getElementById('login-form').addEventListener('submit', async (e) => {{
  e.preventDefault();
  const btn = document.getElementById('submit-btn');
  const err = document.getElementById('error-msg');
  btn.disabled = true;
  btn.textContent = 'Connecting…';
  err.style.display = 'none';

  const body = {{}};
  {js_body}

  try {{
    const res  = await fetch('/captive/login', {{
      method: 'POST',
      headers: {{ 'Content-Type': 'application/json' }},
      body: JSON.stringify(body),
    }});
    const data = await res.json();
    if (res.ok && data.success) {{
      window.location.href = data.redirect_url || 'https://www.google.com';
    }} else {{
      err.textContent = data.detail || data.error || 'Authentication failed';
      err.style.display = 'block';
      btn.disabled = false;
      btn.textContent = '{submit_label}';
    }}
  }} catch (ex) {{
    err.textContent = 'Network error — please try again';
    err.style.display = 'block';
    btn.disabled = false;
    btn.textContent = '{submit_label}';
  }}
}});
</script>
</body>
</html>"""
