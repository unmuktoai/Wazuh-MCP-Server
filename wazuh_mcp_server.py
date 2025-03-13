#!/usr/bin/env python3
"""
Wazuh MCP Server for Claude Desktop Integration
-------------------------------------------------
This service authenticates with the Wazuh API using JWT, retrieves alert data,
transforms it into MCP-compliant JSON messages, and exposes an HTTP endpoint (/mcp)
for Claude Desktop to fetch real-time security context.
"""

import os
import requests
import json
import logging
import datetime
from flask import Flask, jsonify, request
from typing import Dict, Any, Optional

# Configure logging for production-grade observability.
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger(__name__)

# Configuration via environment variables
WAZUH_HOST = os.getenv("WAZUH_HOST", "localhost")
WAZUH_PORT = int(os.getenv("WAZUH_PORT", "55000"))
WAZUH_USER = os.getenv("WAZUH_USER", "admin")
WAZUH_PASS = os.getenv("WAZUH_PASS", "admin")
VERIFY_SSL = os.getenv("VERIFY_SSL", "false").lower() == "true"
MCP_SERVER_PORT = int(os.getenv("MCP_SERVER_PORT", "8000"))

app = Flask(__name__)

class WazuhAPIClient:
    def __init__(self, host: str, port: int, username: str, password: str, verify_ssl: bool = True):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.verify_ssl = verify_ssl
        self.base_url = f"https://{host}:{port}"
        self.jwt_token: Optional[str] = None
        self.jwt_expiration: Optional[datetime.datetime] = None
        self.auth_endpoint = "/security/user/authenticate"

    def _is_jwt_valid(self) -> bool:
        if not self.jwt_token or not self.jwt_expiration:
            return False
        # Consider token invalid if it expires in less than 60 seconds.
        remaining = (self.jwt_expiration - datetime.datetime.utcnow()).total_seconds()
        return remaining > 60

    def get_jwt(self) -> str:
        if self._is_jwt_valid():
            return self.jwt_token

        auth_url = f"{self.base_url}{self.auth_endpoint}"
        try:
            logger.info("Requesting new JWT token from %s", auth_url)
            response = requests.post(
                auth_url,
                auth=(self.username, self.password),
                verify=self.verify_ssl,
                timeout=10
            )
            response.raise_for_status()
            data = response.json()
            token = data.get("jwt")
            if not token:
                raise ValueError("JWT token not found in response")
            self.jwt_token = token
            # In production, decode the JWT for an accurate expiration timestamp.
            self.jwt_expiration = datetime.datetime.utcnow() + datetime.timedelta(minutes=5)
            logger.info("Obtained new JWT token valid until %s", self.jwt_expiration.isoformat())
            return self.jwt_token
        except Exception as e:
            logger.error("Error obtaining JWT token: %s", str(e))
            raise

    def _make_request(self, method: str, endpoint: str, **kwargs) -> Dict[str, Any]:
        jwt_token = self.get_jwt()
        headers = kwargs.pop("headers", {})
        headers["Authorization"] = f"Bearer {jwt_token}"
        url = f"{self.base_url}{endpoint}"
        try:
            response = requests.request(
                method, url, headers=headers, verify=self.verify_ssl, timeout=10, **kwargs
            )
            if response.status_code == 401:
                logger.warning("JWT expired. Re-authenticating and retrying request.")
                self.jwt_token = None
                jwt_token = self.get_jwt()
                headers["Authorization"] = f"Bearer {jwt_token}"
                response = requests.request(
                    method, url, headers=headers, verify=self.verify_ssl, timeout=10, **kwargs
                )
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logger.error("Request to %s failed: %s", endpoint, str(e))
            raise

    def get_alerts(self, index_pattern: str = "wazuh-alerts-*", query: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        endpoint = f"/{index_pattern}/_search"
        if query is None:
            query = {"query": {"match_all": {}}}
        try:
            logger.info("Retrieving alerts with index pattern '%s'", index_pattern)
            data = self._make_request("GET", endpoint, json=query)
            return data
        except Exception as e:
            logger.error("Error retrieving alerts: %s", str(e))
            raise

def transform_to_mcp(event: Dict[str, Any], event_type: str = "alert") -> Dict[str, Any]:
    """
    Transform a Wazuh event into an MCP message.
    """
    mcp_message = {
        "protocol_version": "1.0",
        "source": "Wazuh",
        "timestamp": datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "event_type": event_type,
        "context": {
            "id": event.get("id", "unknown"),
            "category": event.get("category", "intrusion_detection"),
            "severity": event.get("severity", "unknown"),
            "description": event.get("description", ""),
            "data": event.get("data", {})
        },
        "metadata": {
            "integration": "Wazuh-MCP",
            "notes": event.get("notes", "Data fetched via Wazuh API")
        }
    }
    return mcp_message

# Instantiate Wazuh API client with environment configurations.
wazuh_client = WazuhAPIClient(WAZUH_HOST, WAZUH_PORT, WAZUH_USER, WAZUH_PASS, verify_ssl=VERIFY_SSL)

@app.route('/mcp', methods=['GET'])
def mcp_endpoint():
    """
    MCP endpoint for Claude Desktop.
    Retrieves the latest Wazuh alerts, converts them into MCP messages, and returns as JSON.
    """
    try:
        alert_query = {"query": {"match_all": {}}}
        alerts_data = wazuh_client.get_alerts(query=alert_query)
        hits = alerts_data.get("hits", {}).get("hits", [])
        mcp_messages = [transform_to_mcp(hit.get("_source", {}), event_type="alert") for hit in hits]
        return jsonify(mcp_messages), 200
    except Exception as e:
        logger.error("Error in /mcp endpoint: %s", str(e))
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    logger.info("Starting Wazuh MCP Server on port %s", MCP_SERVER_PORT)
    app.run(host="0.0.0.0", port=MCP_SERVER_PORT)
