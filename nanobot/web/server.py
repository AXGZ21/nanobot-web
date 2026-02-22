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


# ============================================================================
# Authentication helpers
# ============================================================================

def _get_password_hash_path() -> Path:
    """Path to stored password hash."""
    from nanobot.config.loader import get_data_dir
    return get_data_dir() / "auth" / "password.hash"


def _get_configured_password() -> str | None:
    """Get the dashboard password from env var or stored hash."""
    return os.environ.get("NANOBOT_PASSWORD")


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
        return password == env_pw

    stored = _get_stored_hash()
    if stored:
        return _hash_password(password) == stored

    return False


def _has_password() -> bool:
    """Check if any password is configured."""
    return bool(_get_configured_password()) or bool(_get_stored_hash())


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


# ============================================================================
# Auth middleware
# ============================================================================

PUBLIC_PATHS = {"/api/auth/login", "/api/auth/status", "/api/auth/setup"}


@web.middleware
async def auth_middleware(request: web.Request, handler):
    """Require authentication for all routes except login."""
    path = request.path

    # Public paths — always allowed
    if path in PUBLIC_PATHS:
        return await handler(request)

    # Localhost requests from the agent's self-admin skill bypass auth
    peername = request.transport.get_extra_info("peername")
    if peername and peername[0] in ("127.0.0.1", "::1"):
        return await handler(request)

    # If no password is set, allow everything (first-run state)
    if not _has_password():
        return await handler(request)

    # Check session
    token = _get_session_from_request(request)
    if token and token in _sessions:
        return await handler(request)

    # Not authenticated
    if path == "/" or path.startswith("/static"):
        # Redirect browser to login
        raise web.HTTPFound("/api/auth/login?redirect=" + path)

    return web.json_response({"error": "Unauthorized"}, status=401)


# ============================================================================
# Auth endpoints
# ============================================================================

async def auth_status(request: web.Request) -> web.Response:
    """GET /api/auth/status — check if auth is required and if session is valid."""
    has_pw = _has_password()
    token = _get_session_from_request(request)
    authenticated = bool(token and token in _sessions) if has_pw else True

    return web.json_response({
        "passwordRequired": has_pw,
        "authenticated": authenticated,
    })


async def auth_login(request: web.Request) -> web.Response:
    """POST /api/auth/login — authenticate with password.
    GET /api/auth/login — serve the login page.
    """
    if request.method == "GET":
        return web.Response(
            text=_LOGIN_PAGE_HTML,
            content_type="text/html",
        )

    try:
        body = await request.json()
    except json.JSONDecodeError:
        return web.json_response({"error": "Invalid JSON"}, status=400)

    password = body.get("password", "")
    if not password:
        return web.json_response({"error": "Password is required"}, status=400)

    if not _check_password(password):
        return web.json_response({"error": "Invalid password"}, status=401)

    # Create session
    token = secrets.token_hex(32)
    _sessions.add(token)

    resp = web.json_response({"ok": True, "token": token})
    resp.set_cookie(
        "nanobot_session", token,
        max_age=60 * 60 * 24 * 30,  # 30 days
        httponly=True,
        samesite="Lax",
    )
    return resp


async def auth_setup(request: web.Request) -> web.Response:
    """POST /api/auth/setup — set password for the first time."""
    if _has_password():
        return web.json_response({"error": "Password already set. Use login instead."}, status=400)

    try:
        body = await request.json()
    except json.JSONDecodeError:
        return web.json_response({"error": "Invalid JSON"}, status=400)

    password = body.get("password", "")
    if len(password) < 4:
        return web.json_response({"error": "Password must be at least 4 characters"}, status=400)

    _set_password(password)

    # Auto-login
    token = secrets.token_hex(32)
    _sessions.add(token)

    resp = web.json_response({"ok": True, "token": token})
    resp.set_cookie(
        "nanobot_session", token,
        max_age=60 * 60 * 24 * 30,
        httponly=True,
        samesite="Lax",
    )
    return resp


async def auth_logout(request: web.Request) -> web.Response:
    """POST /api/auth/logout — destroy session."""
    token = _get_session_from_request(request)
    if token:
        _sessions.discard(token)
    resp = web.json_response({"ok": True})
    resp.del_cookie("nanobot_session")
    return resp


# ============================================================================
# Login page HTML
# ============================================================================

_LOGIN_PAGE_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Nanobot — Login</title>
<style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
        background: #f8f9fb;
        display: flex;
        align-items: center;
        justify-content: center;
        min-height: 100vh;
        color: #1a1a2e;
    }
    .login-card {
        background: #fff;
        border: 1px solid #e2e4e9;
        border-radius: 16px;
        padding: 40px;
        width: 100%;
        max-width: 400px;
        box-shadow: 0 4px 24px rgba(0,0,0,0.06);
    }
    .login-card h1 {
        font-size: 24px;
        font-weight: 700;
        margin-bottom: 4px;
    }
    .login-card .subtitle {
        color: #6b7280;
        font-size: 14px;
        margin-bottom: 28px;
    }
    label {
        display: block;
        font-size: 11px;
        font-weight: 600;
        text-transform: uppercase;
        color: #6b7280;
        margin-bottom: 6px;
        letter-spacing: 0.5px;
    }
    input {
        width: 100%;
        padding: 10px 14px;
        border: 1px solid #e2e4e9;
        border-radius: 8px;
        font-size: 15px;
        outline: none;
        transition: border-color 0.2s;
    }
    input:focus { border-color: #6366f1; }
    .btn {
        width: 100%;
        padding: 12px;
        background: #6366f1;
        color: #fff;
        border: none;
        border-radius: 8px;
        font-size: 15px;
        font-weight: 600;
        cursor: pointer;
        margin-top: 20px;
        transition: background 0.2s;
    }
    .btn:hover { background: #4f46e5; }
    .btn:disabled { opacity: 0.6; cursor: not-allowed; }
    .error {
        color: #dc2626;
        font-size: 13px;
        margin-top: 12px;
        display: none;
    }
    .setup-note {
        font-size: 12px;
        color: #6b7280;
        margin-top: 16px;
        text-align: center;
    }
</style>
</head>
<body>
<div class="login-card">
    <h1>Nanobot</h1>
    <div class="subtitle" id="subtitle">Enter your dashboard password</div>

    <div id="loginForm">
        <label for="password">PASSWORD</label>
        <input type="password" id="password" placeholder="Enter password..." autofocus>
        <div id="confirmGroup" style="display:none;margin-top:14px;">
            <label for="confirmPassword">CONFIRM PASSWORD</label>
            <input type="password" id="confirmPassword" placeholder="Confirm password...">
        </div>
        <button class="btn" id="submitBtn" onclick="submit()">Login</button>
        <div class="error" id="errorMsg"></div>
    </div>

    <div class="setup-note" id="setupNote" style="display:none;">
        Choose a password to protect your dashboard.
    </div>
</div>
<script>
    let isSetup = false;

    async function checkStatus() {
        const res = await fetch('/api/auth/status');
        const data = await res.json();
        if (data.authenticated) {
            window.location.href = '/';
            return;
        }
        if (!data.passwordRequired) {
            isSetup = true;
            document.getElementById('subtitle').textContent = 'Create a dashboard password';
            document.getElementById('confirmGroup').style.display = '';
            document.getElementById('submitBtn').textContent = 'Set Password & Continue';
            document.getElementById('setupNote').style.display = '';
        }
    }

    async function submit() {
        const pw = document.getElementById('password').value;
        const errEl = document.getElementById('errorMsg');
        errEl.style.display = 'none';

        if (!pw) {
            errEl.textContent = 'Please enter a password';
            errEl.style.display = '';
            return;
        }

        if (isSetup) {
            const confirm = document.getElementById('confirmPassword').value;
            if (pw !== confirm) {
                errEl.textContent = 'Passwords do not match';
                errEl.style.display = '';
                return;
            }
            if (pw.length < 4) {
                errEl.textContent = 'Password must be at least 4 characters';
                errEl.style.display = '';
                return;
            }
            const res = await fetch('/api/auth/setup', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ password: pw }),
            });
            const data = await res.json();
            if (data.ok) {
                window.location.href = '/';
            } else {
                errEl.textContent = data.error || 'Setup failed';
                errEl.style.display = '';
            }
        } else {
            const res = await fetch('/api/auth/login', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ password: pw }),
            });
            const data = await res.json();
            if (data.ok) {
                window.location.href = '/';
            } else {
                errEl.textContent = data.error || 'Login failed';
                errEl.style.display = '';
            }
        }
    }

    document.getElementById('password').addEventListener('keydown', (e) => {
        if (e.key === 'Enter') {
            if (isSetup) document.getElementById('confirmPassword').focus();
            else submit();
        }
    });
    document.getElementById('confirmPassword').addEventListener('keydown', (e) => {
        if (e.key === 'Enter') submit();
    });

    checkStatus();
</script>
</body>
</html>
"""


# ============================================================================
# App lifecycle
# ============================================================================

async def on_startup(app: web.Application) -> None:
    """Initialize shared resources on server start."""
    from nanobot.config.loader import load_config, get_data_dir
    from nanobot.bus.queue import MessageBus
    from nanobot.cron.service import CronService

    config = load_config()
    app["nanobot_config"] = config
    app["data_dir"] = get_data_dir()

    # Message bus for agent communication
    bus = MessageBus()
    app["bus"] = bus

    # Cron service
    cron_store = get_data_dir() / "cron" / "jobs.json"
    cron = CronService(cron_store)
    app["cron"] = cron

    # Agent loop (lazy — only created when chat is used)
    app["agent"] = None
    app["agent_lock"] = asyncio.Lock()

    # WebSocket clients for event broadcasting
    app["ws_clients"] = set()

    pw_status = "password set" if _has_password() else "NO PASSWORD — first visitor will set one"
    logger.info("Web dashboard ready (auth: {})", pw_status)


async def on_shutdown(app: web.Application) -> None:
    """Clean up on server shutdown."""
    agent = app.get("agent")
    if agent:
        agent.stop()
        await agent.close_mcp()

    cron = app.get("cron")
    if cron:
        cron.stop()

    # Close all WebSocket connections
    for ws in set(app.get("ws_clients", [])):
        await ws.close()


async def index_handler(request: web.Request) -> web.Response:
    """Serve the dashboard HTML."""
    dashboard = STATIC_DIR / "dashboard.html"
    if not dashboard.exists():
        return web.Response(text="Dashboard not found", status=404)
    return web.FileResponse(dashboard)


def create_app() -> web.Application:
    """Create and configure the aiohttp application."""
    app = web.Application(middlewares=[auth_middleware])

    app.on_startup.append(on_startup)
    app.on_shutdown.append(on_shutdown)

    # Auth endpoints (registered before other routes)
    app.router.add_route("*", "/api/auth/login", auth_login)
    app.router.add_post("/api/auth/setup", auth_setup)
    app.router.add_get("/api/auth/status", auth_status)
    app.router.add_post("/api/auth/logout", auth_logout)

    # Dashboard
    app.router.add_get("/", index_handler)

    # Static files
    if STATIC_DIR.exists():
        app.router.add_static("/static", STATIC_DIR)

    # REST + WebSocket API
    setup_routes(app)

    return app


def run_server(host: str = "0.0.0.0", port: int = 1890) -> None:
    """Start the web server."""
    app = create_app()
    web.run_app(app, host=host, port=port, print=lambda msg: logger.info(msg))
