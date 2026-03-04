#!/usr/bin/env bash
# JWTForge Install Script
set -e

BOLD='\033[1m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color

echo ""
echo -e "${CYAN}${BOLD}"
echo '     ██╗██╗    ██╗████████╗    ███████╗ ██████╗ ██████╗  ██████╗ ███████╗'
echo '     ██║██║    ██║╚══██╔══╝    ██╔════╝██╔═══██╗██╔══██╗██╔════╝ ██╔════╝'
echo '     ██║██║ █╗ ██║   ██║       █████╗  ██║   ██║██████╔╝██║  ███╗█████╗  '
echo '██   ██║██║███╗██║   ██║       ██╔══╝  ██║   ██║██╔══██╗██║   ██║██╔══╝  '
echo '╚█████╔╝╚███╔███╔╝   ██║       ██║     ╚██████╔╝██║  ██╗╚██████╔╝███████╗'
echo ' ╚════╝  ╚══╝╚══╝    ╚═╝       ╚═╝      ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝'
echo -e "${NC}"
echo -e "${BOLD}           JWT Attack Suite — Week 15${NC}"
echo ""

# Check Python version
PYTHON=$(which python3 || which python)
PYVER=$($PYTHON -c "import sys; print(sys.version_info.major * 10 + sys.version_info.minor)")
if [ "$PYVER" -lt 38 ]; then
    echo -e "${RED}[!] Python 3.8+ required. Found: $($PYTHON --version)${NC}"
    exit 1
fi
echo -e "${GREEN}[✔] Python OK: $($PYTHON --version)${NC}"

# Install via pip
echo -e "${CYAN}[*] Installing JWTForge...${NC}"
$PYTHON -m pip install -e . --quiet

echo ""
echo -e "${GREEN}${BOLD}[✔] JWTForge installed successfully!${NC}"
echo ""
echo -e "  Run: ${CYAN}jwtforge --help${NC}"
echo -e "  Run: ${CYAN}jwtforge decode <token>${NC}"
echo -e "  Run: ${CYAN}jwtforge scan <token>${NC}"
echo ""
