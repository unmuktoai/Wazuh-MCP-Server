# Configuration Guide

## Environment Variables

### Required
- `WAZUH_HOST`: Wazuh server hostname
- `WAZUH_PORT`: Wazuh API port (default: 55000)
- `WAZUH_USER`: API username
- `WAZUH_PASS`: API password

### Optional
- `VERIFY_SSL`: Enable SSL verification (default: false)
- `DEBUG`: Enable debug logging (default: false)
- `VIRUSTOTAL_API_KEY`: VirusTotal API key
- `SHODAN_API_KEY`: Shodan API key
- `ABUSEIPDB_API_KEY`: AbuseIPDB API key

## Claude Desktop Configuration

Add to your Claude Desktop config:
```json
{
  "mcpServers": {
    "wazuh-mcp": {
      "command": "python",
      "args": ["/path/to/src/wazuh_mcp_server.py"]
    }
  }
}
```
