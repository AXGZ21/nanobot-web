"""REST and WebSocket API routes for the nanobot web dashboard."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

from aiohttp import web, WSMsgType

from loguru import logger

from nanobot.config.loader import load_config, save_config, get_config_path
from nanobot.config.schema import Config


# ============================================================================
# Helpers
# ============================================================================

def _json(data, status=200):
    return web.json_response(data, status=status)


def _err(msg, status=400):
    return web.json_response({"error": msg}, status=status)


async def _broadcast(app: web.Application, event: str, data=None):
    """Send an event to all connected WebSocket clients."""
    payload = json.dumps({"event": event, "data": data})
    dead = set()
    for ws in app.get("ws_clients", set()):
        try:
            await ws.send_str(payload)
        except Exception:
            dead.add(ws)
    app["ws_clients"] -= dead


def _reload_config(app: web.Application) -> Config:
    """Reload config from disk and update app state."""
    config = load_config()
    app["nanobot_config"] = config
    return config


# ============================================================================
# Config endpoints
# ============================================================================

async def get_config(request: web.Request) -> web.Response:
    """GET /api/config — return the full config as JSON."""
    config = _reload_config(request.app)
    data = config.model_dump(by_alias=True)
    return _json(data)


async def put_config(request: web.Request) -> web.Response:
    """PUT /api/config — replace the entire config."""
    try:
        body = await request.json()
    except json.JSONDecodeError:
        return _err("Invalid JSON")

    try:
        config = Config.model_validate(body)
    except Exception as e:
        return _err(f"Validation error: {e}")

    save_config(config)
    request.app["nanobot_config"] = config
    await _broadcast(request.app, "config:updated")
    return _json({"ok": True})


async def patch_config(request: web.Request) -> web.Response:
    """PATCH /api/config — merge partial config updates.

    Accepts a JSON object with dotted keys:
      {"providers.anthropic.apiKey": "sk-...", "agents.defaults.model": "..."}
    Or nested structure matching the config schema.
    """
    try:
        body = await request.json()
    except json.JSONDecodeError:
        return _err("Invalid JSON")

    config = _reload_config(request.app)
    data = config.model_dump(by_alias=True)

    # Deep merge
    _deep_merge(data, body)

    try:
        config = Config.model_validate(data)
    except Exception as e:
        return _err(f"Validation error: {e}")

    save_config(config)
    request.app["nanobot_config"] = config
    await _broadcast(request.app, "config:updated")
    return _json({"ok": True})


def _deep_merge(base: dict, updates: dict) -> None:
    """Recursively merge updates into base dict."""
    for key, value in updates.items():
        if isinstance(value, dict) and isinstance(base.get(key), dict):
            _deep_merge(base[key], value)
        else:
            base[key] = value


# ============================================================================
# Provider endpoints
# ============================================================================

async def get_providers(request: web.Request) -> web.Response:
    """GET /api/providers — list all providers with their config."""
    config = _reload_config(request.app)
    providers_data = config.providers.model_dump(by_alias=True)

    # Enrich with registry metadata
    from nanobot.providers.registry import PROVIDERS
    result = {}
    for spec in PROVIDERS:
        p = providers_data.get(_to_camel(spec.name), {})
        result[spec.name] = {
            "label": spec.label,
            "isGateway": spec.is_gateway,
            "isLocal": spec.is_local,
            "isOauth": spec.is_oauth,
            "config": p,
        }
    return _json(result)


async def put_provider(request: web.Request) -> web.Response:
    """PUT /api/providers/{name} — update a single provider's config."""
    name = request.match_info["name"]
    try:
        body = await request.json()
    except json.JSONDecodeError:
        return _err("Invalid JSON")

    config = _reload_config(request.app)
    providers_data = config.providers.model_dump(by_alias=True)
    camel_name = _to_camel(name)

    if camel_name not in providers_data and name not in providers_data:
        return _err(f"Unknown provider: {name}", 404)

    key = camel_name if camel_name in providers_data else name
    providers_data[key] = body

    try:
        from nanobot.config.schema import ProvidersConfig
        config.providers = ProvidersConfig.model_validate(providers_data)
    except Exception as e:
        return _err(f"Validation error: {e}")

    save_config(config)
    request.app["nanobot_config"] = config
    await _broadcast(request.app, "provider:updated", {"name": name})
    return _json({"ok": True})


# ============================================================================
# Channel endpoints
# ============================================================================

async def get_channels(request: web.Request) -> web.Response:
    """GET /api/channels — list all channels."""
    config = _reload_config(request.app)
    return _json(config.channels.model_dump(by_alias=True))


async def put_channel(request: web.Request) -> web.Response:
    """PUT /api/channels/{name} — update a single channel."""
    name = request.match_info["name"]
    try:
        body = await request.json()
    except json.JSONDecodeError:
        return _err("Invalid JSON")

    config = _reload_config(request.app)
    channels_data = config.channels.model_dump(by_alias=True)
    camel_name = _to_camel(name)

    key = camel_name if camel_name in channels_data else name
    if key not in channels_data:
        return _err(f"Unknown channel: {name}", 404)

    channels_data[key] = body

    try:
        from nanobot.config.schema import ChannelsConfig
        config.channels = ChannelsConfig.model_validate(channels_data)
    except Exception as e:
        return _err(f"Validation error: {e}")

    save_config(config)
    request.app["nanobot_config"] = config
    await _broadcast(request.app, "channel:updated", {"name": name})
    return _json({"ok": True})


# ============================================================================
# Tools endpoints
# ============================================================================

async def get_tools(request: web.Request) -> web.Response:
    """GET /api/tools — get tools config."""
    config = _reload_config(request.app)
    return _json(config.tools.model_dump(by_alias=True))


async def put_tools(request: web.Request) -> web.Response:
    """PUT /api/tools — update tools config."""
    try:
        body = await request.json()
    except json.JSONDecodeError:
        return _err("Invalid JSON")

    config = _reload_config(request.app)
    try:
        from nanobot.config.schema import ToolsConfig
        config.tools = ToolsConfig.model_validate(body)
    except Exception as e:
        return _err(f"Validation error: {e}")

    save_config(config)
    request.app["nanobot_config"] = config
    await _broadcast(request.app, "tools:updated")
    return _json({"ok": True})


# ============================================================================
# MCP Server endpoints
# ============================================================================

async def get_mcp_servers(request: web.Request) -> web.Response:
    """GET /api/tools/mcp — list MCP servers."""
    config = _reload_config(request.app)
    servers = config.tools.model_dump(by_alias=True).get("mcpServers", {})
    return _json(servers)


async def put_mcp_server(request: web.Request) -> web.Response:
    """PUT /api/tools/mcp/{name} — add or update an MCP server."""
    name = request.match_info["name"]
    try:
        body = await request.json()
    except json.JSONDecodeError:
        return _err("Invalid JSON")

    config = _reload_config(request.app)
    from nanobot.config.schema import MCPServerConfig
    try:
        server_config = MCPServerConfig.model_validate(body)
    except Exception as e:
        return _err(f"Validation error: {e}")

    config.tools.mcp_servers[name] = server_config
    save_config(config)
    request.app["nanobot_config"] = config
    await _broadcast(request.app, "mcp:updated", {"name": name})
    return _json({"ok": True})


async def delete_mcp_server(request: web.Request) -> web.Response:
    """DELETE /api/tools/mcp/{name} — remove an MCP server."""
    name = request.match_info["name"]
    config = _reload_config(request.app)

    if name not in config.tools.mcp_servers:
        return _err(f"MCP server not found: {name}", 404)

    del config.tools.mcp_servers[name]
    save_config(config)
    request.app["nanobot_config"] = config
    await _broadcast(request.app, "mcp:removed", {"name": name})
    return _json({"ok": True})


# ============================================================================
# Agent config endpoints
# ============================================================================

async def get_agent_config(request: web.Request) -> web.Response:
    """GET /api/agent — get agent defaults."""
    config = _reload_config(request.app)
    return _json(config.agents.model_dump(by_alias=True))


async def put_agent_config(request: web.Request) -> web.Response:
    """PUT /api/agent — update agent defaults."""
    try:
        body = await request.json()
    except json.JSONDecodeError:
        return _err("Invalid JSON")

    config = _reload_config(request.app)
    try:
        from nanobot.config.schema import AgentsConfig
        config.agents = AgentsConfig.model_validate(body)
    except Exception as e:
        return _err(f"Validation error: {e}")

    save_config(config)
    request.app["nanobot_config"] = config
    await _broadcast(request.app, "agent:updated")
    return _json({"ok": True})


# ============================================================================
# Skills endpoints
# ============================================================================

async def get_skills(request: web.Request) -> web.Response:
    """GET /api/skills — list all skills."""
    config = _reload_config(request.app)
    from nanobot.agent.skills import SkillsLoader
    loader = SkillsLoader(config.workspace_path)
    skills = loader.list_skills(filter_unavailable=False)

    result = []
    for s in skills:
        meta = loader.get_skill_metadata(s["name"]) or {}
        result.append({
            "name": s["name"],
            "source": s["source"],
            "path": s["path"],
            "description": meta.get("description", ""),
        })
    return _json(result)


async def get_skill(request: web.Request) -> web.Response:
    """GET /api/skills/{name} — get a single skill's content."""
    name = request.match_info["name"]
    config = _reload_config(request.app)
    from nanobot.agent.skills import SkillsLoader
    loader = SkillsLoader(config.workspace_path)
    content = loader.load_skill(name)
    if content is None:
        return _err(f"Skill not found: {name}", 404)
    return _json({"name": name, "content": content})


async def put_skill(request: web.Request) -> web.Response:
    """PUT /api/skills/{name} — create or update a workspace skill."""
    name = request.match_info["name"]
    try:
        body = await request.json()
    except json.JSONDecodeError:
        return _err("Invalid JSON")

    content = body.get("content", "")
    if not content:
        return _err("Skill content (SKILL.md body) is required")

    config = _reload_config(request.app)
    skill_dir = config.workspace_path / "skills" / name
    skill_dir.mkdir(parents=True, exist_ok=True)
    (skill_dir / "SKILL.md").write_text(content, encoding="utf-8")

    await _broadcast(request.app, "skill:updated", {"name": name})
    return _json({"ok": True})


async def delete_skill(request: web.Request) -> web.Response:
    """DELETE /api/skills/{name} — remove a workspace skill."""
    name = request.match_info["name"]
    config = _reload_config(request.app)
    skill_dir = config.workspace_path / "skills" / name

    if not skill_dir.exists():
        return _err(f"Skill not found: {name}", 404)

    import shutil
    shutil.rmtree(skill_dir)
    await _broadcast(request.app, "skill:removed", {"name": name})
    return _json({"ok": True})


# ============================================================================
# Memory endpoints
# ============================================================================

async def get_memory(request: web.Request) -> web.Response:
    """GET /api/memory — get MEMORY.md and HISTORY.md contents."""
    config = _reload_config(request.app)
    from nanobot.agent.memory import MemoryStore
    store = MemoryStore(config.workspace_path)

    memory = store.read_long_term()
    history = ""
    if store.history_file.exists():
        history = store.history_file.read_text(encoding="utf-8")

    return _json({"memory": memory, "history": history})


async def put_memory(request: web.Request) -> web.Response:
    """PUT /api/memory — update MEMORY.md content."""
    try:
        body = await request.json()
    except json.JSONDecodeError:
        return _err("Invalid JSON")

    config = _reload_config(request.app)
    from nanobot.agent.memory import MemoryStore
    store = MemoryStore(config.workspace_path)
    store.write_long_term(body.get("memory", ""))

    await _broadcast(request.app, "memory:updated")
    return _json({"ok": True})


# ============================================================================
# Cron endpoints
# ============================================================================

async def get_cron_jobs(request: web.Request) -> web.Response:
    """GET /api/cron — list all cron jobs."""
    from nanobot.cron.service import CronService
    cron: CronService = request.app["cron"]
    jobs = cron.list_jobs(include_disabled=True)

    result = []
    for job in jobs:
        result.append({
            "id": job.id,
            "name": job.name,
            "enabled": job.enabled,
            "schedule": {
                "kind": job.schedule.kind,
                "everyMs": job.schedule.every_ms,
                "expr": job.schedule.expr,
                "tz": job.schedule.tz,
                "atMs": job.schedule.at_ms,
            },
            "payload": {
                "message": job.payload.message,
                "deliver": job.payload.deliver,
                "channel": job.payload.channel,
                "to": job.payload.to,
            },
            "state": {
                "nextRunAtMs": job.state.next_run_at_ms,
                "lastRunAtMs": job.state.last_run_at_ms,
                "lastStatus": job.state.last_status,
            },
        })
    return _json(result)


async def post_cron_job(request: web.Request) -> web.Response:
    """POST /api/cron — add a new cron job."""
    try:
        body = await request.json()
    except json.JSONDecodeError:
        return _err("Invalid JSON")

    from nanobot.cron.service import CronService
    from nanobot.cron.types import CronSchedule
    cron: CronService = request.app["cron"]

    schedule_data = body.get("schedule", {})
    kind = schedule_data.get("kind", "every")

    schedule = CronSchedule(
        kind=kind,
        every_ms=schedule_data.get("everyMs"),
        expr=schedule_data.get("expr"),
        tz=schedule_data.get("tz"),
        at_ms=schedule_data.get("atMs"),
    )

    try:
        job = cron.add_job(
            name=body.get("name", "Untitled"),
            schedule=schedule,
            message=body.get("message", ""),
            deliver=body.get("deliver", False),
            to=body.get("to"),
            channel=body.get("channel"),
        )
    except ValueError as e:
        return _err(str(e))

    await _broadcast(request.app, "cron:added", {"id": job.id})
    return _json({"ok": True, "id": job.id}, status=201)


async def delete_cron_job(request: web.Request) -> web.Response:
    """DELETE /api/cron/{id} — remove a cron job."""
    job_id = request.match_info["id"]
    from nanobot.cron.service import CronService
    cron: CronService = request.app["cron"]

    if cron.remove_job(job_id):
        await _broadcast(request.app, "cron:removed", {"id": job_id})
        return _json({"ok": True})
    return _err(f"Job not found: {job_id}", 404)


async def post_cron_toggle(request: web.Request) -> web.Response:
    """POST /api/cron/{id}/toggle — enable/disable a cron job."""
    job_id = request.match_info["id"]
    try:
        body = await request.json()
    except json.JSONDecodeError:
        return _err("Invalid JSON")

    from nanobot.cron.service import CronService
    cron: CronService = request.app["cron"]

    enabled = body.get("enabled", True)
    job = cron.enable_job(job_id, enabled=enabled)
    if job:
        await _broadcast(request.app, "cron:toggled", {"id": job_id, "enabled": enabled})
        return _json({"ok": True})
    return _err(f"Job not found: {job_id}", 404)


# ============================================================================
# Status & workspace endpoints
# ============================================================================

async def get_status(request: web.Request) -> web.Response:
    """GET /api/status — overall system status."""
    from nanobot import __version__
    config = _reload_config(request.app)
    config_path = get_config_path()

    from nanobot.cron.service import CronService
    cron: CronService = request.app["cron"]
    cron_status = cron.status()

    return _json({
        "version": __version__,
        "configPath": str(config_path),
        "configExists": config_path.exists(),
        "workspacePath": str(config.workspace_path),
        "workspaceExists": config.workspace_path.exists(),
        "model": config.agents.defaults.model,
        "cronJobs": cron_status.get("jobs", 0),
        "agentRunning": request.app.get("agent") is not None,
    })


async def get_workspace_files(request: web.Request) -> web.Response:
    """GET /api/workspace — list key workspace files."""
    config = _reload_config(request.app)
    ws = config.workspace_path

    files = []
    for name in ["AGENTS.md", "SOUL.md", "USER.md"]:
        path = ws / name
        if path.exists():
            files.append({"name": name, "content": path.read_text(encoding="utf-8")})

    return _json(files)


async def put_workspace_file(request: web.Request) -> web.Response:
    """PUT /api/workspace/{name} — update a workspace file."""
    name = request.match_info["name"]
    allowed = {"AGENTS.md", "SOUL.md", "USER.md"}
    if name not in allowed:
        return _err(f"Not allowed: {name}. Allowed: {', '.join(allowed)}")

    try:
        body = await request.json()
    except json.JSONDecodeError:
        return _err("Invalid JSON")

    config = _reload_config(request.app)
    path = config.workspace_path / name
    path.write_text(body.get("content", ""), encoding="utf-8")
    return _json({"ok": True})


# ============================================================================
# Dashboard extensions (custom pages, widgets injected by the agent)
# ============================================================================

async def get_dashboard_extensions(request: web.Request) -> web.Response:
    """GET /api/dashboard/extensions — list all custom dashboard extensions."""
    ext_file = request.app["data_dir"] / "dashboard" / "extensions.json"
    if ext_file.exists():
        data = json.loads(ext_file.read_text(encoding="utf-8"))
        return _json(data)
    return _json({"pages": {}, "widgets": []})


async def put_dashboard_extension(request: web.Request) -> web.Response:
    """PUT /api/dashboard/extensions/{id} — add or update a dashboard extension.

    Body: {
        "type": "page" | "widget",
        "title": "My Page",
        "html": "<div>...</div>",
        "css": "optional CSS",
        "js": "optional JS",
        "icon": "optional emoji",
        "position": "sidebar" | "overview"  (for widgets)
    }
    """
    ext_id = request.match_info["id"]
    try:
        body = await request.json()
    except json.JSONDecodeError:
        return _err("Invalid JSON")

    ext_dir = request.app["data_dir"] / "dashboard"
    ext_dir.mkdir(parents=True, exist_ok=True)
    ext_file = ext_dir / "extensions.json"

    if ext_file.exists():
        data = json.loads(ext_file.read_text(encoding="utf-8"))
    else:
        data = {"pages": {}, "widgets": []}

    ext_type = body.get("type", "page")

    if ext_type == "page":
        data["pages"][ext_id] = {
            "title": body.get("title", ext_id),
            "html": body.get("html", ""),
            "css": body.get("css", ""),
            "js": body.get("js", ""),
            "icon": body.get("icon", ""),
        }
    elif ext_type == "widget":
        # Remove existing widget with same id
        data["widgets"] = [w for w in data["widgets"] if w.get("id") != ext_id]
        data["widgets"].append({
            "id": ext_id,
            "title": body.get("title", ext_id),
            "html": body.get("html", ""),
            "css": body.get("css", ""),
            "js": body.get("js", ""),
            "position": body.get("position", "overview"),
        })

    ext_file.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    await _broadcast(request.app, "dashboard:extension:updated", {"id": ext_id})
    return _json({"ok": True})


async def delete_dashboard_extension(request: web.Request) -> web.Response:
    """DELETE /api/dashboard/extensions/{id} — remove a dashboard extension."""
    ext_id = request.match_info["id"]
    ext_file = request.app["data_dir"] / "dashboard" / "extensions.json"

    if not ext_file.exists():
        return _err("No extensions found", 404)

    data = json.loads(ext_file.read_text(encoding="utf-8"))
    removed = False

    if ext_id in data.get("pages", {}):
        del data["pages"][ext_id]
        removed = True

    data["widgets"] = [w for w in data.get("widgets", []) if w.get("id") != ext_id]
    if not removed and len(data.get("widgets", [])) != len(json.loads(ext_file.read_text()).get("widgets", [])):
        removed = True

    if not removed:
        return _err(f"Extension not found: {ext_id}", 404)

    ext_file.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    await _broadcast(request.app, "dashboard:extension:removed", {"id": ext_id})
    return _json({"ok": True})


# ============================================================================
# Chat WebSocket
# ============================================================================

async def ws_chat(request: web.Request) -> web.WebSocketResponse:
    """WebSocket /ws/chat — interactive chat with the agent."""
    ws = web.WebSocketResponse()
    await ws.prepare(request)

    agent = await _ensure_agent(request.app)
    if not agent:
        await ws.send_json({"type": "error", "content": "Failed to create agent — check config"})
        await ws.close()
        return ws

    bus = request.app["bus"]

    # Background task to forward agent responses to WebSocket
    async def _forward_responses():
        while not ws.closed:
            try:
                msg = await asyncio.wait_for(bus.consume_outbound(), timeout=1.0)
                if msg.metadata.get("_progress"):
                    await ws.send_json({"type": "progress", "content": msg.content})
                else:
                    await ws.send_json({"type": "response", "content": msg.content})
            except asyncio.TimeoutError:
                continue
            except Exception:
                break

    forward_task = asyncio.create_task(_forward_responses())

    try:
        async for msg in ws:
            if msg.type == WSMsgType.TEXT:
                data = json.loads(msg.data)
                user_msg = data.get("content", "").strip()
                if not user_msg:
                    continue

                from nanobot.bus.events import InboundMessage
                await bus.publish_inbound(InboundMessage(
                    channel="web",
                    sender_id="user",
                    chat_id="web:direct",
                    content=user_msg,
                ))
                await ws.send_json({"type": "ack", "content": user_msg})

            elif msg.type in (WSMsgType.ERROR, WSMsgType.CLOSE):
                break
    finally:
        forward_task.cancel()
        try:
            await forward_task
        except asyncio.CancelledError:
            pass

    return ws


# ============================================================================
# Events WebSocket
# ============================================================================

async def ws_events(request: web.Request) -> web.WebSocketResponse:
    """WebSocket /ws/events — receive real-time dashboard events."""
    ws = web.WebSocketResponse()
    await ws.prepare(request)
    request.app["ws_clients"].add(ws)

    try:
        async for msg in ws:
            if msg.type in (WSMsgType.ERROR, WSMsgType.CLOSE):
                break
    finally:
        request.app["ws_clients"].discard(ws)

    return ws


# ============================================================================
# Agent lifecycle
# ============================================================================

async def _ensure_agent(app: web.Application):
    """Create the agent loop if not already running."""
    async with app["agent_lock"]:
        if app["agent"] is not None:
            return app["agent"]

        try:
            config = app["nanobot_config"]
            bus = app["bus"]

            from nanobot.cli.commands import _make_provider
            provider = _make_provider(config)

            from nanobot.agent.loop import AgentLoop
            from nanobot.session.manager import SessionManager

            session_manager = SessionManager(config.workspace_path)
            cron = app["cron"]

            agent = AgentLoop(
                bus=bus,
                provider=provider,
                workspace=config.workspace_path,
                model=config.agents.defaults.model,
                temperature=config.agents.defaults.temperature,
                max_tokens=config.agents.defaults.max_tokens,
                max_iterations=config.agents.defaults.max_tool_iterations,
                memory_window=config.agents.defaults.memory_window,
                brave_api_key=config.tools.web.search.api_key or None,
                exec_config=config.tools.exec,
                cron_service=cron,
                restrict_to_workspace=config.tools.restrict_to_workspace,
                session_manager=session_manager,
                mcp_servers=config.tools.mcp_servers,
            )

            # Start the agent loop in background
            asyncio.create_task(agent.run())
            app["agent"] = agent
            logger.info("Agent loop started for web chat")
            return agent

        except Exception as e:
            logger.error("Failed to create agent: {}", e)
            return None


async def post_agent_restart(request: web.Request) -> web.Response:
    """POST /api/agent/restart — stop and restart the agent loop."""
    async with request.app["agent_lock"]:
        old = request.app.get("agent")
        if old:
            old.stop()
            await old.close_mcp()
            request.app["agent"] = None

    agent = await _ensure_agent(request.app)
    if agent:
        await _broadcast(request.app, "agent:restarted")
        return _json({"ok": True})
    return _err("Failed to restart agent", 500)


# ============================================================================
# Export full config (download)
# ============================================================================

async def export_config(request: web.Request) -> web.Response:
    """GET /api/config/export — download config as JSON file."""
    config = _reload_config(request.app)
    data = config.model_dump(by_alias=True)
    return web.Response(
        body=json.dumps(data, indent=2, ensure_ascii=False),
        content_type="application/json",
        headers={"Content-Disposition": "attachment; filename=nanobot-config.json"},
    )


# ============================================================================
# OAuth login endpoints
# ============================================================================

# Temporary store for in-flight PKCE state (Codex auth flow)
_oauth_pending: dict[str, dict] = {}


async def get_oauth_status(request: web.Request) -> web.Response:
    """GET /api/oauth/{provider}/status — check if OAuth token exists."""
    provider = request.match_info["provider"]

    if provider == "openai_codex":
        try:
            from oauth_cli_kit import get_token
            token = get_token()
            if token and token.access:
                return _json({"authenticated": True, "accountId": token.account_id or ""})
        except Exception:
            pass
        return _json({"authenticated": False})

    elif provider == "github_copilot":
        # Check if LiteLLM has a cached Copilot token
        try:
            from pathlib import Path as _P
            cache_dir = _P.home() / ".cache" / "litellm"
            token_files = list(cache_dir.glob("*copilot*")) if cache_dir.exists() else []
            if token_files:
                return _json({"authenticated": True, "accountId": ""})
        except Exception:
            pass
        return _json({"authenticated": False})

    return _err(f"Unknown OAuth provider: {provider}", 404)


async def post_oauth_start(request: web.Request) -> web.Response:
    """POST /api/oauth/{provider}/start — begin OAuth flow, return auth URL."""
    provider = request.match_info["provider"]

    if provider == "openai_codex":
        try:
            import urllib.parse
            from oauth_cli_kit import OPENAI_CODEX_PROVIDER
            from oauth_cli_kit.pkce import _generate_pkce, _create_state

            verifier, challenge = _generate_pkce()
            state = _create_state()
            prov = OPENAI_CODEX_PROVIDER

            params = {
                "response_type": "code",
                "client_id": prov.client_id,
                "redirect_uri": prov.redirect_uri,
                "scope": prov.scope,
                "code_challenge": challenge,
                "code_challenge_method": "S256",
                "state": state,
                "id_token_add_organizations": "true",
                "codex_cli_simplified_flow": "true",
                "originator": prov.default_originator,
            }
            url = f"{prov.authorize_url}?{urllib.parse.urlencode(params)}"

            # Store PKCE verifier for the callback step
            _oauth_pending["openai_codex"] = {
                "verifier": verifier,
                "state": state,
            }

            return _json({
                "authUrl": url,
                "state": state,
                "instructions": (
                    "Open the URL in your browser, log in with OpenAI, "
                    "then paste the full callback URL or authorization code below."
                ),
            })
        except ImportError:
            return _err("oauth-cli-kit not installed on server", 500)
        except Exception as e:
            return _err(f"Failed to start OAuth flow: {e}", 500)

    elif provider == "github_copilot":
        # GitHub Copilot uses LiteLLM's device flow.
        # We trigger it in a background thread and capture stdout.
        import io
        import sys
        import threading

        captured = {"lines": [], "done": False, "error": None, "success": False}

        def _run_copilot_auth():
            old_stdout = sys.stdout
            old_stderr = sys.stderr
            buf = io.StringIO()
            sys.stdout = buf
            sys.stderr = buf
            try:
                import asyncio as _aio
                from litellm import acompletion
                _aio.run(acompletion(
                    model="github_copilot/gpt-4o",
                    messages=[{"role": "user", "content": "hi"}],
                    max_tokens=1,
                ))
                captured["success"] = True
            except Exception as e:
                captured["error"] = str(e)
            finally:
                sys.stdout = old_stdout
                sys.stderr = old_stderr
                captured["lines"] = buf.getvalue().splitlines()
                captured["done"] = True

        # Store the capture dict so /poll can check it
        _oauth_pending["github_copilot"] = captured

        thread = threading.Thread(target=_run_copilot_auth, daemon=True)
        thread.start()

        # Wait briefly for the device code to appear in output
        import time
        for _ in range(30):
            time.sleep(0.5)
            if captured["done"] or captured["lines"]:
                break

        # Extract device code URL and code from the captured output
        device_url = ""
        device_code = ""
        for line in captured["lines"]:
            if "http" in line.lower():
                import re
                urls = re.findall(r'https?://[^\s<>"\']+', line)
                if urls:
                    device_url = urls[0]
            if "code" in line.lower() or len(line.strip()) > 4:
                # Try to find the device code (usually a short alphanumeric string)
                import re
                codes = re.findall(r'\b[A-Z0-9]{4,}(?:-[A-Z0-9]{4,})?\b', line)
                if codes:
                    device_code = codes[-1]

        return _json({
            "deviceUrl": device_url,
            "deviceCode": device_code,
            "output": captured["lines"],
            "done": captured["done"],
            "instructions": (
                "Open the URL in your browser and enter the device code to authenticate."
                if device_url else
                "GitHub Copilot authentication is in progress. Check the output for instructions."
            ),
        })

    return _err(f"Unknown OAuth provider: {provider}", 404)


async def post_oauth_callback(request: web.Request) -> web.Response:
    """POST /api/oauth/{provider}/callback — complete OAuth with auth code."""
    provider = request.match_info["provider"]

    if provider == "openai_codex":
        try:
            body = await request.json()
        except json.JSONDecodeError:
            return _err("Invalid JSON")

        pending = _oauth_pending.get("openai_codex")
        if not pending:
            return _err("No pending OAuth flow — call /start first")

        raw_input = body.get("code", "").strip()
        if not raw_input:
            return _err("Authorization code or callback URL is required")

        try:
            from oauth_cli_kit import OPENAI_CODEX_PROVIDER
            from oauth_cli_kit.pkce import _parse_authorization_input, _parse_token_payload, _decode_account_id
            from oauth_cli_kit.storage import FileTokenStorage
            from oauth_cli_kit.models import OAuthToken
            import httpx
            import time

            code, parsed_state = _parse_authorization_input(raw_input)
            if parsed_state and parsed_state != pending["state"]:
                return _err("State mismatch — possible CSRF. Start a new flow.")

            if not code:
                return _err("Could not parse authorization code from input")

            # Exchange code for tokens
            prov = OPENAI_CODEX_PROVIDER
            data = {
                "grant_type": "authorization_code",
                "client_id": prov.client_id,
                "code": code,
                "code_verifier": pending["verifier"],
                "redirect_uri": prov.redirect_uri,
            }

            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.post(
                    prov.token_url,
                    data=data,
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                )

            if response.status_code != 200:
                return _err(f"Token exchange failed: {response.status_code} {response.text}")

            payload = response.json()
            access, refresh, expires_in = _parse_token_payload(
                payload, "Token response missing fields"
            )
            account_id = _decode_account_id(
                access, prov.jwt_claim_path, prov.account_id_claim
            )
            token = OAuthToken(
                access=access,
                refresh=refresh,
                expires=int(time.time() * 1000 + expires_in * 1000),
                account_id=account_id,
            )

            # Save token to disk
            storage = FileTokenStorage(token_filename=prov.token_filename)
            storage.save(token)

            # Clean up pending state
            _oauth_pending.pop("openai_codex", None)

            return _json({
                "ok": True,
                "authenticated": True,
                "accountId": account_id or "",
            })

        except Exception as e:
            logger.error("OAuth callback failed: {}", e)
            return _err(f"Token exchange failed: {e}")

    elif provider == "github_copilot":
        # For Copilot, poll the background thread status
        captured = _oauth_pending.get("github_copilot")
        if not captured:
            return _err("No pending Copilot auth flow — call /start first")

        return _json({
            "done": captured["done"],
            "success": captured.get("success", False),
            "error": captured.get("error"),
            "output": captured.get("lines", []),
        })

    return _err(f"Unknown OAuth provider: {provider}", 404)


# ============================================================================
# Helper
# ============================================================================

def _to_camel(snake: str) -> str:
    """Convert snake_case to camelCase."""
    parts = snake.split("_")
    return parts[0] + "".join(p.capitalize() for p in parts[1:])


# ============================================================================
# Route setup
# ============================================================================

def setup_routes(app: web.Application) -> None:
    """Register all API routes."""
    # Config
    app.router.add_get("/api/config", get_config)
    app.router.add_put("/api/config", put_config)
    app.router.add_patch("/api/config", patch_config)
    app.router.add_get("/api/config/export", export_config)

    # Providers
    app.router.add_get("/api/providers", get_providers)
    app.router.add_put("/api/providers/{name}", put_provider)

    # Channels
    app.router.add_get("/api/channels", get_channels)
    app.router.add_put("/api/channels/{name}", put_channel)

    # Tools
    app.router.add_get("/api/tools", get_tools)
    app.router.add_put("/api/tools", put_tools)

    # MCP Servers
    app.router.add_get("/api/tools/mcp", get_mcp_servers)
    app.router.add_put("/api/tools/mcp/{name}", put_mcp_server)
    app.router.add_delete("/api/tools/mcp/{name}", delete_mcp_server)

    # Agent
    app.router.add_get("/api/agent", get_agent_config)
    app.router.add_put("/api/agent", put_agent_config)
    app.router.add_post("/api/agent/restart", post_agent_restart)

    # Skills
    app.router.add_get("/api/skills", get_skills)
    app.router.add_get("/api/skills/{name}", get_skill)
    app.router.add_put("/api/skills/{name}", put_skill)
    app.router.add_delete("/api/skills/{name}", delete_skill)

    # Memory
    app.router.add_get("/api/memory", get_memory)
    app.router.add_put("/api/memory", put_memory)

    # Cron
    app.router.add_get("/api/cron", get_cron_jobs)
    app.router.add_post("/api/cron", post_cron_job)
    app.router.add_delete("/api/cron/{id}", delete_cron_job)
    app.router.add_post("/api/cron/{id}/toggle", post_cron_toggle)

    # Status & Workspace
    app.router.add_get("/api/status", get_status)
    app.router.add_get("/api/workspace", get_workspace_files)
    app.router.add_put("/api/workspace/{name}", put_workspace_file)

    # Dashboard extensions
    app.router.add_get("/api/dashboard/extensions", get_dashboard_extensions)
    app.router.add_put("/api/dashboard/extensions/{id}", put_dashboard_extension)
    app.router.add_delete("/api/dashboard/extensions/{id}", delete_dashboard_extension)

    # OAuth
    app.router.add_get("/api/oauth/{provider}/status", get_oauth_status)
    app.router.add_post("/api/oauth/{provider}/start", post_oauth_start)
    app.router.add_post("/api/oauth/{provider}/callback", post_oauth_callback)

    # WebSockets
    app.router.add_get("/ws/chat", ws_chat)
    app.router.add_get("/ws/events", ws_events)
