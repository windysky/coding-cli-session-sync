#!/usr/bin/env bash
#
# setup.sh - Install session_sync package in editable mode to ~/.local/bin
#
# This script installs the session_sync package using pip in editable mode
# with the --user flag, which installs scripts to ~/.local/bin/.
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Project directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo -e "${BLUE}Session Sync - Setup Script${NC}"
echo "============================"
echo ""

# Ensure ~/.local/bin exists
mkdir -p "$HOME/.local/bin"

# Check if ~/.local/bin is in PATH
if [[ ":$PATH:" != *":$HOME/.local/bin:"* ]]; then
    echo -e "${YELLOW}WARNING: ~/.local/bin is not in your PATH${NC}"
    echo ""
    echo "Add this to your ~/.bashrc or ~/.zshrc:"
    echo "  export PATH=\"\$HOME/.local/bin:\$PATH\""
    echo ""
    echo "Then run: source ~/.bashrc  (or source ~/.zshrc)"
    echo ""
fi

# Check for conda base environment
if [ -n "$CONDA_DEFAULT_ENV" ] && [ "$CONDA_DEFAULT_ENV" = "base" ]; then
    echo -e "${YELLOW}WARNING: You are in the conda 'base' environment${NC}"
    echo ""
    echo "It is recommended to install session_sync in a dedicated conda environment."
    echo "This prevents conflicts with conda's base packages."
    echo ""
    echo "To create and activate a new environment:"
    echo "  conda create -n session_sync python=3.11"
    echo "  conda activate session_sync"
    echo "  ./setup.sh"
    echo ""
    read -p "Continue installing in base environment anyway? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo -e "${GREEN}Installation cancelled.${NC}"
        echo "Please create a dedicated environment and run setup.sh again."
        exit 0
    fi
    echo ""
fi

# Check if pip is available
if ! command -v pip3 &> /dev/null && ! command -v pip &> /dev/null; then
    echo -e "${RED}Error: pip is not installed${NC}"
    echo "Please install pip first:"
    echo "  sudo apt install python3-pip  (Ubuntu/Debian)"
    echo "  or"
    echo "  python3 -m ensurepip --upgrade  (Generic)"
    exit 1
fi

# Use pip3 if available, otherwise pip
PIP_CMD="pip3"
if ! command -v pip3 &> /dev/null; then
    PIP_CMD="pip"
fi

# Uninstall old version if exists (try both locations)
echo -e "${YELLOW}Checking for previous installation...${NC}"
if $PIP_CMD show session-sync &> /dev/null; then
    echo "Uninstalling previous version (session-sync)..."
    $PIP_CMD uninstall -y session-sync 2>/dev/null || true
fi
if $PIP_CMD show session_sync &> /dev/null; then
    echo "Uninstalling previous version (session_sync)..."
    $PIP_CMD uninstall -y session_sync 2>/dev/null || true
fi

# Install in editable mode to ~/.local/bin
echo ""
echo -e "${YELLOW}Installing session_sync package to ~/.local/bin...${NC}"
cd "$SCRIPT_DIR"
$PIP_CMD install -e . --user --quiet

echo ""
echo -e "${GREEN}✓ Installation complete!${NC}"
echo ""
echo "Scripts installed to: ~/.local/bin/"
echo ""
echo "You can now run:"
echo -e "  ${GREEN}session-export${NC}  - Export sessions to archive"
echo -e "  ${GREEN}session-import${NC}  - Import sessions from archive"
echo -e "  ${GREEN}session-cleanup${NC}  - Delete sessions (destructive)"
echo ""
echo "The package is installed in editable mode, so changes to the code"
echo "in $SCRIPT_DIR will be immediately available."
