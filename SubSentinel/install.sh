#!/usr/bin/env bash
# SubSentinel - Automated installer
# Usage: bash install.sh

set -e

CYAN='\033[0;36m'
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${CYAN}"
echo "  ███████╗██╗   ██╗██████╗ ███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗     "
echo "  ██╔════╝██║   ██║██╔══██╗██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║     "
echo "  ███████╗██║   ██║██████╔╝███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║     "
echo "  ╚════██║██║   ██║██╔══██╗╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║     "
echo "  ███████║╚██████╔╝██████╔╝███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗"
echo "  ╚══════╝ ╚═════╝ ╚═════╝ ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝"
echo -e "${NC}"
echo -e "${YELLOW}⚠  FOR AUTHORIZED SECURITY TESTING ONLY${NC}"
echo ""

# Check Python version
echo -e "${CYAN}[1/5] Checking Python version...${NC}"
python3 --version 2>/dev/null || { echo -e "${RED}Python 3 not found. Install Python 3.9+${NC}"; exit 1; }
PY_VER=$(python3 -c "import sys; print(sys.version_info >= (3, 9))")
if [ "$PY_VER" = "False" ]; then
    echo -e "${RED}Python 3.9+ required${NC}"
    exit 1
fi
echo -e "${GREEN}✓ Python OK${NC}"

# Create virtual environment
echo -e "${CYAN}[2/5] Creating virtual environment...${NC}"
python3 -m venv venv
source venv/bin/activate
echo -e "${GREEN}✓ Virtual environment created${NC}"

# Upgrade pip
pip install --upgrade pip -q

# Install requirements
echo -e "${CYAN}[3/5] Installing Python dependencies...${NC}"
pip install -r requirements.txt -q
echo -e "${GREEN}✓ Dependencies installed${NC}"

# Install Playwright browsers
echo -e "${CYAN}[4/5] Installing Playwright browsers (for screenshots)...${NC}"
python3 -m playwright install chromium --with-deps 2>/dev/null || {
    echo -e "${YELLOW}⚠ Playwright browser install failed (screenshots will be disabled)${NC}"
    echo -e "${YELLOW}  Run manually: playwright install chromium${NC}"
}
echo -e "${GREEN}✓ Playwright ready${NC}"

# Check optional tools
echo -e "${CYAN}[5/5] Checking optional external tools...${NC}"
for tool in subfinder amass assetfinder; do
    if command -v $tool &>/dev/null; then
        echo -e "${GREEN}  ✓ $tool found${NC}"
    else
        echo -e "${YELLOW}  ○ $tool not found (optional, enhances enumeration)${NC}"
    fi
done

# Create output directories
mkdir -p output/screenshots output/evidence logs

echo ""
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}✓ SubSentinel installation complete!${NC}"
echo ""
echo -e "  Activate venv:  ${CYAN}source venv/bin/activate${NC}"
echo -e "  Quick scan:     ${CYAN}python main.py -d example.com --accept-legal${NC}"
echo -e "  Full options:   ${CYAN}python main.py --help${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "${YELLOW}⚠  Remember: Only test domains you have explicit written authorization for.${NC}"
