"""Wazuh MCP Server Package"""

__version__ = "2.0.0"

from .wazuh_mcp_server import WazuhMCPServer, main

__all__ = ["WazuhMCPServer", "main"]
