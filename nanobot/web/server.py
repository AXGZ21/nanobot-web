"""Web gateway server — serves the dashboard and REST/WebSocket API."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import secrets
from pathlib import Path

from aiohttp import web

from loguru import logger

from nanobot.web.api import setup_routes


STATIC_DIR = Path(__file__).parent / "static"

# Session tokens (in-memory, cleared on restart)
_sessions: set[str] = set()


# =============================================================================
# Authentication helpers
# =============================================================================

def _get_password_hash_path() -> Path:
    """Path to stored password hash."""
    from nanobot.config.loader import get_data_dir
    return get_data_dir() / "auth" / "password.hash"


def _get_configured_password() -> str | None:
    """Get the dashboard password from env var or stored hash."""
    pw = os.environ.get("NANOBOT_PASSWORD")
    logger.info(f"[AUTH] NANOBOT_PASSWORD env var: {'SET (length=' + str(len(pw)) + ')' if pw else 'NOT SET'}")
    return pw


def _get_stored_hash() -> str | None:
    """Get password hash from disk (set via first-run setup)."""
    path = _get_password_hash_path()
    if path.exists():
        return path.read_text(encoding="utf-8").strip()
    return None


def _hash_password(password: str) -> str:
    """SHA-256 hash of the password."""
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


def _check_password(password: str) -> bool:
    """Check password against env var or stored hash."""
    env_pw = _get_configured_password()
    if env_pw:
        # Hash both sides so comparison is consistent regardless of how password was set
        return secrets.compare_digest(_hash_password(password), _hash_password(env_pw))

    stored = _get_stored_hash()
    if stored:
        return secrets.compare_digest(_hash_password(password), stored)

    return False


def _has_password() -> bool:
    """Check if any password is configured."""
    env_pw = _get_configured_password()
    stored_hash = _get_stored_hash()
    has_pw = bool(env_pw) or bool(stored_hash)
    logger.info(f"[AUTH] _has_password: env={bool(env_pw)}, stored={bool(stored_hash)} -> {has_pw}")
    return has_pw


def _set_password(password: str) -> None:
    """Store a new password hash to disk."""
    path = _get_password_hash_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(_hash_password(password), encoding="utf-8")
    os.chmod(path, 0o600)


def _get_session_from_request(request: web.Request) -> str | None:
    """Extract session token from cookie or Authorization header."""
    # Check cookie
    token = request.cookies.get("nanobot_session")
    if token:
        return token

    # Check Authorization header (for API calls from agent's curl)
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        return auth[7:]

    return None


# =============================================================================
# Auth middleware
# =============================================================================

@web.middleware
async def auth_middleware(request: web.Request, handler):
    """Protect all routes except /login and /api/set-password."""
    # Allow static files
    if request.path.startswith("/static/"):
        return await handler(request)

    # Allow login page
    if request.path == "/login":
        return await handler(request)

    # Allow set-password endpoint (for first-run setup)
    if request.path == "/api/set-password":
        return await handler(request)

    # Allow health check endpoint
    if request.path == "/health":
        return await handler(request)

    # If no password is configured, allow all requests (first-run)
    if not _has_password():
        logger.warning("[AUTH] No password configured - allowing unauthenticated access")
        return await handler(request)

    # Check session
    session = _get_session_from_request(request)
    if not session or session not in _sessions:
        # Return 401 for API requests, redirect to /login for browser requests
        if request.path.startswith("/api/") or request.path.startswith("/ws"):
            return web.json_response({"error": "Unauthorized"}, status=401)
        return web.HTTPFound("/login")

    return await handler(request)


# =============================================================================
# Routes
# =============================================================================

async def login_page(request: web.Request):
    """Serve the login page."""
    return web.FileResponse(STATIC_DIR / "login.html")


async def login_handler(request: web.Request):
    """Handle login POST."""
    data = await request.json()
    password = data.get("password", "")

    if _check_password(password):
        # Create session
        token = secrets.token_urlsafe(32)
        _sessions.add(token)
        
        # Set cookie
        response = web.json_response({"success": True})
        response.set_cookie(
            "nanobot_session",
            token,
            max_age=30 * 24 * 60 * 60,  # 30 days
            httponly=True,
            secure=request.scheme == "https",
            samesite="Lax"
        )
        return response
    
    return web.json_response({"error": "Invalid password"}, status=401)


async def logout_handler(request: web.Request):
    """Handle logout POST."""
    session = _get_session_from_request(request)
    if session:
        _sessions.discard(session)
    
    response = web.json_response({"success": True})
    response.del_cookie("nanobot_session")
    return response


async def set_password_handler(request: web.Request):
    """Set password on first run (only if no password exists)."""
    if _has_password():
        return web.json_response({"error": "Password already set"}, status=403)
    
    data = await request.json()
    password = data.get("password", "")
    
    if not password or len(password) < 4:
        return web.json_response({"error": "Password must be at least 4 characters"}, status=400)
    
    _set_password(password)
    logger.info("[AUTH] Password set via first-run setup")
    
    return web.json_response({"success": True})


async def check_auth_status(request: web.Request):
    """Check if password is configured."""
    return web.json_response({
        "has_password": _has_password(),
        "authenticated": bool(_get_session_from_request(request) and _get_session_from_request(request) in _sessions)
    })


async def index_handler(request: web.Request):
    """Serve the main dashboard."""
    return web.FileResponse(STATIC_DIR / "index.html")


async def health_handler(request: web.Request):
    """Health check endpoint."""
    return web.json_response({"status": "ok"})


# =============================================================================
# Server setup
# =============================================================================

def create_app() -> web.Application:
    """Create and configure the web application."""
    app = web.Application(middlewares=[auth_middleware])
    
    # Auth routes
    app.router.add_get("/login", login_page)
    app.router.add_post("/api/login", login_handler)
    app.router.add_post("/api/logout", logout_handler)
    app.router.add_post("/api/set-password", set_password_handler)
    app.router.add_get("/api/auth-status", check_auth_status)
    app.router.add_get("/health", health_handler)
    
    # Main dashboard
    app.router.add_get("/", index_handler)
    
    # API routes (tasks, websocket, etc.)
    setup_routes(app)
    
    # Static files
    app.router.add_static("/static/", STATIC_DIR)
    
    return app


async def start_server(host: str = "0.0.0.0", port: int = 8080):
    """Start the web server."""
    app = create_app()
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, host, port)
    await site.start()
    
    logger.info(f"🌐 Web server running at http://{host}:{port}")
    logger.info(f"   Dashboard: http://localhost:{port}/")
    
    # Keep running
    try:
        await asyncio.Event().wait()
    finally:
        await runner.cleanup()


if __name__ == "__main__":
    asyncio.run(start_server())
