@echo off
REM Installation script for Windows - Fixed version

echo Installing Wazuh MCP Server...
echo.

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python is not installed or not in PATH
    echo Please install Python 3.8 or higher from https://www.python.org/
    pause
    exit /b 1
)

REM Create virtual environment
echo Creating virtual environment...
python -m venv venv

REM Activate virtual environment
echo Activating virtual environment...
call venv\Scripts\activate

REM Upgrade pip
echo Upgrading pip...
python -m pip install --upgrade pip

REM Install dependencies
echo Installing dependencies...
pip install -r requirements.txt

REM Create .env.example if it doesn't exist
if not exist .env.example (
    echo Creating .env.example...
    (
        echo # Wazuh Configuration
        echo WAZUH_HOST=localhost
        echo WAZUH_PORT=55000
        echo WAZUH_USER=admin
        echo WAZUH_PASS=admin
        echo VERIFY_SSL=false
        echo.
        echo # External API Keys ^(Optional^)
        echo VIRUSTOTAL_API_KEY=
        echo SHODAN_API_KEY=
        echo ABUSEIPDB_API_KEY=
        echo.
        echo # Server Configuration
        echo DEBUG=false
        echo.
        echo # Performance Settings
        echo MAX_ALERTS_PER_QUERY=1000
        echo MAX_AGENTS_PER_SCAN=10
    ) > .env.example
)

REM Create .env file if not exists
if not exist .env (
    echo.
    echo Creating .env file from .env.example...
    copy .env.example .env
    echo.
    echo =====================================================
    echo IMPORTANT: Edit the .env file with your credentials!
    echo =====================================================
    echo.
    echo Required settings to configure:
    echo   - WAZUH_HOST: Your Wazuh server address
    echo   - WAZUH_USER: Your Wazuh username  
    echo   - WAZUH_PASS: Your Wazuh password
    echo.
    echo Optional: Add API keys for threat intelligence
    echo.
    notepad .env
) else (
    echo .env file already exists - skipping creation
)

echo.
echo Installation complete!
echo.
echo Next steps:
echo 1. Edit .env with your Wazuh credentials (if not already done)
echo 2. Test connection: python scripts\test_connection.py
echo 3. Configure Claude Desktop with the path to this installation
echo 4. Start using natural language security queries!
echo.
pause
