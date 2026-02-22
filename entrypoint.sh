#!/usr/bin/env bash
set -e

CONFIG_DIR="$HOME/.nanobot"
CONFIG_FILE="$CONFIG_DIR/config.json"

mkdir -p "$CONFIG_DIR"

# Run onboard if no config exists (creates default config + workspace)
if [ ! -f "$CONFIG_FILE" ]; then
    echo "[nanobot] First run — initializing config and workspace..."
    nanobot onboard
fi

# Use Railway's $PORT if set, otherwise default 1890
WEB_PORT="${PORT:-1890}"

echo ""
echo "  ╔══════════════════════════════════════════════════╗"
echo "  ║         nanobot web dashboard starting           ║"
echo "  ║                                                  ║"
echo "  ║  Open the dashboard to configure providers,      ║"
echo "  ║  channels, tools, and chat with your agent.      ║"
echo "  ║                                                  ║"
echo "  ║  All settings save directly to config.json.      ║"
echo "  ╚══════════════════════════════════════════════════╝"
echo ""

exec nanobot web --port "$WEB_PORT" --host 0.0.0.0
