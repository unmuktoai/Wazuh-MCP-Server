# Installation Guide

## Requirements
- Python 3.8+
- Wazuh 4.x
- Claude Desktop

## Installation Steps

### 1. Clone Repository
```bash
git clone https://github.com/unmuktoai/wazuh-mcp-server.git
cd wazuh-mcp-server
```

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

### 3. Configure Environment
```bash
cp .env.example .env
# Edit .env with your Wazuh credentials
```

### 4. Configure Claude Desktop
See examples/claude_desktop_config.json

### 5. Run Server
```bash
python src/wazuh_mcp_server.py
```
