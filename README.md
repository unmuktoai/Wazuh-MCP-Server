# Wazuh-MCP-Server
An open-source MCP server for integrating Wazuh security data with LLMs (such as the Claude Desktop App). This service authenticates with the Wazuh RESTful API, retrieves alerts from Elasticsearch indices, transforms events into an MCP-compliant JSON format, and exposes an HTTP endpoint for Claude Desktop to fetch real-time security context.
