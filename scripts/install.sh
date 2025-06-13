#!/bin/bash
# Installation script for Linux/macOS

echo "Installing Wazuh MCP Server..."

# Create virtual environment
python3 -m venv venv

# Activate virtual environment
source venv/bin/activate

# Install dependencies
pip install --upgrade pip
pip install -r requirements.txt

# Create .env file if not exists
if [ ! -f .env ]; then
    cp .env.example .env
    echo "Created .env file. Please edit it with your credentials."
fi

echo "Installation complete!"
echo "To start the server: python src/wazuh_mcp_server.py"
