[![MseeP.ai Security Assessment Badge](https://mseep.net/pr/unmuktoai-wazuh-mcp-server-badge.png)](https://mseep.ai/app/unmuktoai-wazuh-mcp-server)

# Wazuh MCP Server

A production-grade, open-source MCP server for integrating Wazuh security data with LLMs (such as the Claude Desktop App). This service authenticates with the Wazuh RESTful API, retrieves alerts from Elasticsearch indices, transforms events into an MCP-compliant JSON format, and exposes an HTTP endpoint for Claude Desktop to fetch real-time security context.

## Features

- **JWT-Based Authentication:** Securely authenticate with Wazuh using JWT tokens.
- **Alert Retrieval:** Query Elasticsearch indices for Wazuh alert data.
- **MCP Message Transformation:** Convert security events into standardized MCP messages.
- **Flask HTTP Server:** Exposes an `/mcp` endpoint for Claude Desktop integration.
- **Robust Error Handling:** Handles token expiration, network timeouts, and malformed data.
- **Configurable:** Easily configure via environment variables and integrate with Claude Desktop via its config file.


## Prerequisites

- Python 3.8+
- Access to a Wazuh API instance.
- (Optional) Claude Desktop configured to call the MCP server.

## Installation

1. **Clone the Repository:**

   ```bash
   git clone https://github.com/unmuktoai/Wazuh-MCP-Server.git
   cd Wazuh-MCP-Server
Create and Activate a Virtual Environment:

  ```bash
  
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```
**Install Dependencies:**

  ```bash
pip install -r requirements.txt
```
**Configuration**
Set the following environment variables to configure the MCP server:
  ```bash
WAZUH_HOST: Wazuh server hostname or IP.
WAZUH_PORT: Port for the Wazuh API (default: 55000).
WAZUH_USER: Wazuh API username.
WAZUH_PASS: Wazuh API password.
VERIFY_SSL: Set to "true" or "false" (default: false).
MCP_SERVER_PORT: Port on which the MCP server will run (default: 8000).
```
Example (MacOS):

  ```bash
export WAZUH_HOST="your_wazuh_server"
export WAZUH_PORT="55000"
export WAZUH_USER="your_username"
export WAZUH_PASS="your_password"
export VERIFY_SSL="false"
export MCP_SERVER_PORT="8000"

```
**Running the Server**
Start the MCP server with:

  ```bash
python wazuh_mcp_server.py 
```
The server will listen on all interfaces at the port specified by 
  ```bash
MCP_SERVER_PORT.
```
**Integration with Claude Desktop**
To integrate with Claude Desktop, update its configuration file:

MacOS: ~/Library/Application Support/Claude/claude_desktop_config.json
Windows: %APPDATA%/Claude/claude_desktop_config.json
Add the following entry under mcpServers:

  ```bash
{
  "mcpServers": {
    "mcp-server-wazuh": {
      "command": "python3 /path/to/Wazuh-MCP-Server/wazuh_mcp_server.py",
      "env": {
        "WAZUH_HOST": "your_wazuh_server",
        "WAZUH_PORT": "55000",
        "WAZUH_USER": "your_username",
        "WAZUH_PASS": "your_password",
        "MCP_SERVER_PORT": "8000",
        "VERIFY_SSL": "false"
      }
    }
  }
}
```
License
This project is licensed under the MIT License.

Contributing
Contributions are welcome! Please open issues or submit pull requests for improvements or bug fixes.

