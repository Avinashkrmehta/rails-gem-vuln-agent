#!/bin/bash
# Quick local run script for the Rails Gem Vulnerability Agent
#
# Usage:
#   ./run_local.sh /path/to/your/rails/app
#   ./run_local.sh /path/to/your/rails/app --dry-run
#   ./run_local.sh /path/to/your/rails/app --gem nokogiri

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RAILS_APP="${1:?Usage: $0 /path/to/rails/app [options]}"
shift

# Setup virtual environment if needed
if [ ! -d "$SCRIPT_DIR/venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv "$SCRIPT_DIR/venv"
    source "$SCRIPT_DIR/venv/bin/activate"
    pip install -r "$SCRIPT_DIR/requirements.txt"
else
    source "$SCRIPT_DIR/venv/bin/activate"
fi

# Check for .env
if [ ! -f "$SCRIPT_DIR/.env" ]; then
    echo "⚠ No .env file found. Copy .env.example and add your API keys:"
    echo "  cp $SCRIPT_DIR/.env.example $SCRIPT_DIR/.env"
    exit 1
fi

# Run the agent
echo ""
echo "╔══════════════════════════════════════════════╗"
echo "║  Rails Gem Vulnerability Agent - Local Run   ║"
echo "╚══════════════════════════════════════════════╝"
echo ""

cd "$SCRIPT_DIR"
python main.py --rails-app "$RAILS_APP" "$@"
