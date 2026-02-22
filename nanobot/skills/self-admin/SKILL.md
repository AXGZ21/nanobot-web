---
name: self-admin
description: "Self-administration and dashboard customization. Use when the user asks you to modify your own config, change providers or models, add dashboard widgets/pages, manage skills, update memory, create cron jobs, or customize the web dashboard. Also use when asked to 'modify yourself', 'add something to the dashboard', 'change your settings', or 'add a new feature'."
metadata: {"nanobot":{"emoji":"🔧","always":true}}
---

# Self-Admin Skill

You have full access to your own web dashboard REST API. You can modify your own configuration, add new features to the dashboard, manage skills, and customize your behavior — all through HTTP calls to your own server.

## API Base URL

The dashboard API runs on the same server. Use `localhost` with the web port:

```
NANOBOT_API="http://localhost:${PORT:-1890}"
```

Always set this variable before making API calls:
```bash
NANOBOT_API="http://localhost:${PORT:-1890}"
```

## Configuration Management

### Read current config
```bash
curl -s "$NANOBOT_API/api/config" | python3 -m json.tool
```

### Update specific config values (PATCH merge)
```bash
curl -s -X PATCH "$NANOBOT_API/api/config" \
  -H "Content-Type: application/json" \
  -d '{"providers":{"openrouter":{"apiKey":"sk-or-..."}}}'
```

### Replace full config
```bash
curl -s -X PUT "$NANOBOT_API/api/config" \
  -H "Content-Type: application/json" \
  -d @/path/to/config.json
```

## Provider Management

### List all providers with status
```bash
curl -s "$NANOBOT_API/api/providers" | python3 -m json.tool
```

### Enable/configure a provider
```bash
curl -s -X PUT "$NANOBOT_API/api/providers/openrouter" \
  -H "Content-Type: application/json" \
  -d '{"apiKey":"sk-or-..."}'
```

## Agent Config

### Read agent defaults
```bash
curl -s "$NANOBOT_API/api/agent" | python3 -m json.tool
```

### Change model, temperature, or other defaults
```bash
curl -s -X PUT "$NANOBOT_API/api/agent" \
  -H "Content-Type: application/json" \
  -d '{"defaults":{"model":"openrouter/anthropic/claude-sonnet-4-20250514","temperature":0.7,"maxTokens":8192,"maxToolIterations":20,"memoryWindow":50}}'
```

### Restart the agent (after config changes)
```bash
curl -s -X POST "$NANOBOT_API/api/agent/restart"
```

## Skills Management

### List all skills
```bash
curl -s "$NANOBOT_API/api/skills" | python3 -m json.tool
```

### Create a new skill
```bash
curl -s -X PUT "$NANOBOT_API/api/skills/my-new-skill" \
  -H "Content-Type: application/json" \
  -d '{
    "content": "---\nname: my-new-skill\ndescription: \"What it does\"\nmetadata: {\"nanobot\":{\"emoji\":\"🌟\"}}\n---\n\n# My New Skill\n\nInstructions here..."
  }'
```

### Delete a skill
```bash
curl -s -X DELETE "$NANOBOT_API/api/skills/my-new-skill"
```

## Memory

### Read memory
```bash
curl -s "$NANOBOT_API/api/memory" | python3 -m json.tool
```

### Update long-term memory
```bash
curl -s -X PUT "$NANOBOT_API/api/memory" \
  -H "Content-Type: application/json" \
  -d '{"memory":"# Updated Memory\n\nNew facts to remember..."}'
```

## Cron Jobs

### List cron jobs
```bash
curl -s "$NANOBOT_API/api/cron" | python3 -m json.tool
```

### Add a cron job
```bash
curl -s -X POST "$NANOBOT_API/api/cron" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Daily reminder",
    "schedule": {"kind": "cron", "expr": "0 9 * * *", "tz": "UTC"},
    "message": "Good morning! Here is your daily summary.",
    "deliver": true,
    "channel": "telegram"
  }'
```

### Delete a cron job
```bash
curl -s -X DELETE "$NANOBOT_API/api/cron/JOB_ID"
```

## Dashboard Customization

You can add custom pages and widgets to the web dashboard. These are persisted and loaded automatically.

### Add a custom page

Creates a new page accessible from the dashboard sidebar:

```bash
curl -s -X PUT "$NANOBOT_API/api/dashboard/extensions/my-page" \
  -H "Content-Type: application/json" \
  -d '{
    "type": "page",
    "title": "My Custom Page",
    "icon": "🌟",
    "html": "<div class=\"card\"><div class=\"card-header\"><h3 class=\"card-title\">Hello</h3></div><p style=\"padding:16px;\">This is a custom page added by the agent.</p></div>",
    "css": ".my-custom-class { color: var(--primary-600); }",
    "js": "console.log('Custom page loaded');"
  }'
```

### Add a widget to the overview page

```bash
curl -s -X PUT "$NANOBOT_API/api/dashboard/extensions/weather-widget" \
  -H "Content-Type: application/json" \
  -d '{
    "type": "widget",
    "title": "Weather",
    "position": "overview",
    "html": "<div class=\"card\"><div class=\"card-header\"><h3 class=\"card-title\">🌤 Weather</h3></div><div style=\"padding:16px;\"><div id=\"weather-content\">Loading...</div></div></div>",
    "js": "fetch(\"https://wttr.in/?format=j1\").then(r=>r.json()).then(d=>{document.getElementById(\"weather-content\").textContent=d.current_condition[0].weatherDesc[0].value+\" \"+d.current_condition[0].temp_C+\"°C\"}).catch(()=>{document.getElementById(\"weather-content\").textContent=\"Could not load weather\"});"
  }'
```

### List all extensions
```bash
curl -s "$NANOBOT_API/api/dashboard/extensions" | python3 -m json.tool
```

### Remove an extension
```bash
curl -s -X DELETE "$NANOBOT_API/api/dashboard/extensions/my-page"
```

## Dashboard HTML Reference

When creating custom pages or widgets, use these CSS classes from the dashboard:

- **Layout**: `.card`, `.card-header`, `.card-title`, `.mb-24`
- **Forms**: `.form-group`, `.form-label`, `.form-input`, `.form-select`, `.form-checkbox`
- **Buttons**: `.btn`, `.btn-primary`, `.btn-secondary`, `.btn-danger`
- **Badges**: `.badge`, `.badge-gray`, `.badge-primary`, `.badge-warning`, `.badge-info`, `.badge-danger`, `.badge-new`
- **Colors**: `var(--primary-600)`, `var(--success-600)`, `var(--danger-600)`, `var(--warning-600)`, `var(--text-primary)`, `var(--text-muted)`, `var(--bg-base)`, `var(--bg-subtle)`, `var(--border)`
- **Typography**: `var(--font-mono)` for monospace

## Channels

### List channels
```bash
curl -s "$NANOBOT_API/api/channels" | python3 -m json.tool
```

### Configure a channel (e.g., Telegram)
```bash
curl -s -X PUT "$NANOBOT_API/api/channels/telegram" \
  -H "Content-Type: application/json" \
  -d '{"botToken":"123456:ABC-DEF..."}'
```

## Tools Config

### Read tools config
```bash
curl -s "$NANOBOT_API/api/tools" | python3 -m json.tool
```

### Add an MCP server
```bash
curl -s -X PUT "$NANOBOT_API/api/tools/mcp/my-server" \
  -H "Content-Type: application/json" \
  -d '{"command":"npx","args":["-y","@modelcontextprotocol/server-filesystem","/home/user/docs"]}'
```

## System Status

### Check status
```bash
curl -s "$NANOBOT_API/api/status" | python3 -m json.tool
```

## Workspace Files

### Read workspace files (AGENTS.md, SOUL.md, USER.md)
```bash
curl -s "$NANOBOT_API/api/workspace" | python3 -m json.tool
```

### Update a workspace file
```bash
curl -s -X PUT "$NANOBOT_API/api/workspace/SOUL.md" \
  -H "Content-Type: application/json" \
  -d '{"content":"# Soul\n\nYou are a helpful assistant with a friendly personality."}'
```

## Important Notes

1. **Always use `exec` tool** to run these curl commands
2. **Set NANOBOT_API first** in every exec call: `NANOBOT_API="http://localhost:${PORT:-1890}" && curl ...`
3. **Restart agent after config changes** that affect the agent loop (model, provider, temperature)
4. **Dashboard extensions auto-reload** — the WebSocket broadcasts changes to all connected browsers
5. **Be careful with full config PUT** — prefer PATCH for partial updates
6. **Test changes** — after modifying config, verify with a GET request
7. **Custom pages/widgets** use the dashboard's existing CSS variables and classes for consistent styling
