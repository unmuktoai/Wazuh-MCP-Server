@echo off
REM Installation script for Windows

echo Installing Wazuh MCP Server...

REM Create virtual environment
python -m venv venv

REM Activate virtual environment
call venv\Scripts\activate

REM Install dependencies
pip install --upgrade pip
pip install -r requirements.txt

REM Create .env file if not exists
if not exist .env (
    copy .env.example .env
    echo Created .env file. Please edit it with your credentials.
)

echo Installation complete!
echo To start the server: python src\wazuh_mcp_server.py
