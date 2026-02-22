#!/usr/bin/env bash
set -e

CONFIG_DIR="$HOME/.nanobot"
CONFIG_FILE="$CONFIG_DIR/config.json"

# ============================================================================
# Auto-configure from Railway environment variables
# ============================================================================

mkdir -p "$CONFIG_DIR"

# Run onboard if no config exists
if [ ! -f "$CONFIG_FILE" ]; then
    echo "[entrypoint] No config found — running nanobot onboard..."
    nanobot onboard
fi

# Inject environment variables into config.json
# This uses python to safely merge env vars into the JSON config
python3 - <<'PYEOF'
import json, os
from pathlib import Path

config_path = Path.home() / ".nanobot" / "config.json"
if not config_path.exists():
    config = {}
else:
    config = json.loads(config_path.read_text())

def ensure(d, *keys):
    for k in keys:
        d = d.setdefault(k, {})
    return d

# --- Providers ---
provider_map = {
    "ANTHROPIC_API_KEY":    ("providers", "anthropic", "apiKey"),
    "OPENAI_API_KEY":       ("providers", "openai", "apiKey"),
    "OPENAI_API_BASE":      ("providers", "openai", "apiBase"),
    "DEEPSEEK_API_KEY":     ("providers", "deepseek", "apiKey"),
    "GEMINI_API_KEY":       ("providers", "gemini", "apiKey"),
    "GROQ_API_KEY":         ("providers", "groq", "apiKey"),
    "OPENROUTER_API_KEY":   ("providers", "openrouter", "apiKey"),
    "AIHUBMIX_API_KEY":     ("providers", "aihubmix", "apiKey"),
    "SILICONFLOW_API_KEY":  ("providers", "siliconflow", "apiKey"),
    "VOLCENGINE_API_KEY":   ("providers", "volcengine", "apiKey"),
    "VOLCENGINE_API_BASE":  ("providers", "volcengine", "apiBase"),
    "DASHSCOPE_API_KEY":    ("providers", "dashscope", "apiKey"),
    "ZHIPU_API_KEY":        ("providers", "zhipu", "apiKey"),
    "MOONSHOT_API_KEY":     ("providers", "moonshot", "apiKey"),
    "MINIMAX_API_KEY":      ("providers", "minimax", "apiKey"),
    "VLLM_API_BASE":        ("providers", "vllm", "apiBase"),
}

for env_key, path in provider_map.items():
    val = os.environ.get(env_key, "")
    if val:
        parent = ensure(config, *path[:-1])
        parent[path[-1]] = val

# --- Channels ---
channel_map = {
    "TELEGRAM_BOT_TOKEN":       ("channels", "telegram", "token"),
    "TELEGRAM_ENABLED":         ("channels", "telegram", "enabled"),
    "DISCORD_BOT_TOKEN":        ("channels", "discord", "token"),
    "DISCORD_ENABLED":          ("channels", "discord", "enabled"),
    "SLACK_BOT_TOKEN":          ("channels", "slack", "botToken"),
    "SLACK_APP_TOKEN":          ("channels", "slack", "appToken"),
    "SLACK_ENABLED":            ("channels", "slack", "enabled"),
    "WHATSAPP_ENABLED":         ("channels", "whatsapp", "enabled"),
    "WHATSAPP_BRIDGE_TOKEN":    ("channels", "whatsapp", "bridgeToken"),
    "EMAIL_ENABLED":            ("channels", "email", "enabled"),
    "EMAIL_IMAP_HOST":          ("channels", "email", "imapHost"),
    "EMAIL_IMAP_USERNAME":      ("channels", "email", "imapUsername"),
    "EMAIL_IMAP_PASSWORD":      ("channels", "email", "imapPassword"),
    "EMAIL_SMTP_HOST":          ("channels", "email", "smtpHost"),
    "EMAIL_SMTP_USERNAME":      ("channels", "email", "smtpUsername"),
    "EMAIL_SMTP_PASSWORD":      ("channels", "email", "smtpPassword"),
    "EMAIL_FROM_ADDRESS":       ("channels", "email", "fromAddress"),
    "FEISHU_APP_ID":            ("channels", "feishu", "appId"),
    "FEISHU_APP_SECRET":        ("channels", "feishu", "appSecret"),
    "FEISHU_ENABLED":           ("channels", "feishu", "enabled"),
    "DINGTALK_CLIENT_ID":       ("channels", "dingtalk", "clientId"),
    "DINGTALK_CLIENT_SECRET":   ("channels", "dingtalk", "clientSecret"),
    "DINGTALK_ENABLED":         ("channels", "dingtalk", "enabled"),
}

for env_key, path in channel_map.items():
    val = os.environ.get(env_key, "")
    if val:
        parent = ensure(config, *path[:-1])
        # Convert "true"/"false" strings to booleans for 'enabled' fields
        if path[-1] == "enabled":
            parent[path[-1]] = val.lower() in ("true", "1", "yes")
        else:
            parent[path[-1]] = val

# --- Agent defaults ---
agent_map = {
    "NANOBOT_MODEL":           ("agents", "defaults", "model"),
    "NANOBOT_TEMPERATURE":     ("agents", "defaults", "temperature"),
    "NANOBOT_MAX_TOKENS":      ("agents", "defaults", "maxTokens"),
    "NANOBOT_MAX_ITERATIONS":  ("agents", "defaults", "maxToolIterations"),
}

for env_key, path in agent_map.items():
    val = os.environ.get(env_key, "")
    if val:
        parent = ensure(config, *path[:-1])
        # Convert numeric values
        if path[-1] in ("temperature",):
            parent[path[-1]] = float(val)
        elif path[-1] in ("maxTokens", "maxToolIterations"):
            parent[path[-1]] = int(val)
        else:
            parent[path[-1]] = val

# --- Tools ---
brave_key = os.environ.get("BRAVE_SEARCH_API_KEY", "")
if brave_key:
    ensure(config, "tools", "web", "search")["apiKey"] = brave_key

config_path.write_text(json.dumps(config, indent=2, ensure_ascii=False))
print("[entrypoint] Config updated from environment variables")
PYEOF

# ============================================================================
# Determine port (Railway sets $PORT)
# ============================================================================

WEB_PORT="${PORT:-1890}"

echo "[entrypoint] Starting nanobot web dashboard on port $WEB_PORT..."
echo "[entrypoint] Gateway will be started via the agent loop on demand."
echo ""

# ============================================================================
# Start the web dashboard (which includes the agent loop for chat)
# ============================================================================

exec nanobot web --port "$WEB_PORT" --host 0.0.0.0
