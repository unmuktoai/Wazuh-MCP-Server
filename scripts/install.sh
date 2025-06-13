#!/bin/bash
# Installation script for Linux/macOS - Fixed version

echo "Installing Wazuh MCP Server..."
echo

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if Python is installed
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}ERROR: Python 3 is not installed${NC}"
    echo "Please install Python 3.8 or higher"
    exit 1
fi

# Create virtual environment
echo "Creating virtual environment..."
python3 -m venv venv

# Activate virtual environment
echo "Activating virtual environment..."
source venv/bin/activate

# Upgrade pip
echo "Upgrading pip..."
pip install --upgrade pip

# Install dependencies
echo "Installing dependencies..."
pip install -r requirements.txt

# Create .env.example if it doesn't exist
if [ ! -f .env.example ]; then
    echo "Creating .env.example..."
    cat > .env.example << 'EOF'
# Wazuh Configuration
WAZUH_HOST=localhost
WAZUH_PORT=55000
WAZUH_USER=admin
WAZUH_PASS=admin
VERIFY_SSL=false

# External API Keys (Optional)
# Get your API keys from:
# VirusTotal: https://www.virustotal.com/gui/my-apikey
# Shodan: https://account.shodan.io/
# AbuseIPDB: https://www.abuseipdb.com/api

VIRUSTOTAL_API_KEY=
SHODAN_API_KEY=
ABUSEIPDB_API_KEY=

# Server Configuration
DEBUG=false

# Performance Settings
MAX_ALERTS_PER_QUERY=1000
MAX_AGENTS_PER_SCAN=10
EOF
fi

# Create .env file if not exists
if [ ! -f .env ]; then
    echo
    echo "Creating .env file from .env.example..."
    cp .env.example .env
    echo
    echo -e "${YELLOW}====================================================="
    echo "IMPORTANT: Edit the .env file with your credentials!"
    echo "=====================================================${NC}"
    echo
    echo "Required settings to configure:"
    echo "  - WAZUH_HOST: Your Wazuh server address"
    echo "  - WAZUH_USER: Your Wazuh username"
    echo "  - WAZUH_PASS: Your Wazuh password"
    echo
    echo "Optional: Add API keys for threat intelligence"
    echo
    
    # Ask if user wants to edit now
    read -p "Would you like to edit .env now? (y/n): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        # Use the default editor
        ${EDITOR:-nano} .env
    fi
else
    echo -e "${GREEN}.env file already exists - skipping creation${NC}"
fi

# Make scripts executable
chmod +x scripts/*.py 2>/dev/null
chmod +x scripts/*.sh 2>/dev/null

echo
echo -e "${GREEN}Installation complete!${NC}"
echo
echo "Next steps:"
echo "1. Edit .env with your Wazuh credentials (if not already done)"
echo "2. Test connection: python scripts/test_connection.py"
echo "3. Configure Claude Desktop with the path to this installation"
echo "4. Start using natural language security queries!"