#!/bin/bash
# ═══════════════════════════════════════════
# 🏰 FortBot — Startup Script
# ═══════════════════════════════════════════
#
# Starts both components:
#   1. Python Guardian API (port 18790)
#   2. TypeScript FortBot (WhatsApp agent)
#
# Usage:
#   ./start.sh              # Normal start
#   ./start.sh --guardian   # Guardian only (for dev)
#   ./start.sh --bot        # Bot only (Guardian assumed running)
#

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}"
echo "  ╔═══════════════════════════════════╗"
echo "  ║     🏰 FortBot v0.4              ║"
echo "  ║     Security-First WhatsApp Agent ║"
echo "  ╚═══════════════════════════════════╝"
echo -e "${NC}"

# Check dependencies
check_deps() {
    local missing=0
    
    if ! command -v node &>/dev/null; then
        echo -e "${RED}✗ Node.js not found${NC}"
        missing=1
    else
        echo -e "${GREEN}✓ Node.js $(node -v)${NC}"
    fi
    
    if ! command -v python3 &>/dev/null && ! command -v python &>/dev/null; then
        echo -e "${RED}✗ Python not found${NC}"
        missing=1
    else
        echo -e "${GREEN}✓ Python $(python3 --version 2>/dev/null || python --version)${NC}"
    fi
    
    if ! command -v claude &>/dev/null; then
        echo -e "${YELLOW}⚠ Claude CLI not found — LLM calls will use fallback${NC}"
    else
        echo -e "${GREEN}✓ Claude CLI available${NC}"
    fi
    
    if [ $missing -eq 1 ]; then
        echo -e "${RED}Missing required dependencies. Aborting.${NC}"
        exit 1
    fi
}

# Start Guardian API
start_guardian() {
    echo -e "\n${BLUE}[1/2] Starting Guardian API...${NC}"
    
    # Check if already running
    if curl -s http://127.0.0.1:18790/health >/dev/null 2>&1; then
        echo -e "${YELLOW}Guardian already running on port 18790${NC}"
        return
    fi
    
    PYTHON_CMD=$(command -v python3 || command -v python)
    
    # Install Python deps if needed
    $PYTHON_CMD -c "import fastapi" 2>/dev/null || {
        echo "Installing Python dependencies..."
        $PYTHON_CMD -m pip install fastapi uvicorn websockets --break-system-packages -q
    }
    
    # Start in background
    $PYTHON_CMD -m uvicorn core.api:app \
        --host 127.0.0.1 \
        --port 18790 \
        --log-level warning \
        &
    GUARDIAN_PID=$!
    echo $GUARDIAN_PID > .guardian.pid
    
    # Wait for it to be ready
    for i in {1..10}; do
        if curl -s http://127.0.0.1:18790/health >/dev/null 2>&1; then
            echo -e "${GREEN}✓ Guardian API ready (PID $GUARDIAN_PID)${NC}"
            echo -e "  Dashboard: ${BLUE}http://localhost:18790/${NC}"
            return
        fi
        sleep 0.5
    done
    
    echo -e "${YELLOW}⚠ Guardian started but not responding yet${NC}"
}

# Start FortBot (TypeScript)
start_bot() {
    echo -e "\n${BLUE}[2/2] Starting FortBot...${NC}"
    
    # Build if needed
    if [ ! -d "dist" ] || [ "$(find src -name '*.ts' -newer dist -print -quit)" ]; then
        echo "Building TypeScript..."
        npx tsc 2>/dev/null || {
            echo -e "${YELLOW}TypeScript build had warnings (non-fatal)${NC}"
        }
    fi
    
    # Start with tsx for development
    exec npx tsx src/index.ts
}

# Cleanup on exit
cleanup() {
    echo -e "\n${YELLOW}Shutting down...${NC}"
    
    if [ -f .guardian.pid ]; then
        GUARDIAN_PID=$(cat .guardian.pid)
        kill $GUARDIAN_PID 2>/dev/null && echo "Guardian stopped"
        rm .guardian.pid
    fi
}

trap cleanup EXIT

# Main
check_deps

case "${1:-}" in
    --guardian)
        start_guardian
        echo -e "\n${GREEN}Guardian running. Press Ctrl+C to stop.${NC}"
        wait
        ;;
    --bot)
        start_bot
        ;;
    *)
        start_guardian
        start_bot
        ;;
esac
