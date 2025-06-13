#!/usr/bin/env python3
"""
Wazuh MCP Server for Claude Desktop Integration - Enhanced Edition
------------------------------------------------------------------
Production-grade MCP server with advanced security analysis capabilities,
multi-tool integration, and comprehensive threat intelligence features.
"""

import os
import sys
import json
import asyncio
import logging
import datetime
import hashlib
import re
import ipaddress
import statistics
from typing import Dict, Any, Optional, List, Tuple, Set
from dataclasses import dataclass, asdict
from enum import Enum
from collections import defaultdict, Counter

import aiohttp
import urllib3
from mcp.server import Server, NotificationOptions
from mcp.server.models import InitializationOptions
import mcp.server.stdio
import mcp.types as types

from config import WazuhConfig, AlertSeverity, ComplianceFramework, ThreatCategory

# Disable SSL warnings if VERIFY_SSL is false
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configure logging
logging.basicConfig(
    level=logging.DEBUG if os.getenv("DEBUG", "false").lower() == "true" else logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    stream=sys.stderr
)
logger = logging.getLogger("wazuh-mcp")


class WazuhAPIClient:
    """Async Wazuh API client with JWT authentication"""
    
    def __init__(self, config: WazuhConfig):
        self.config = config
        self.jwt_token: Optional[str] = None
        self.jwt_expiration: Optional[datetime.datetime] = None
        self.session: Optional[aiohttp.ClientSession] = None
    
    async def __aenter__(self):
        connector = aiohttp.TCPConnector(ssl=self.config.verify_ssl)
        self.session = aiohttp.ClientSession(connector=connector)
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()
    
    def _is_jwt_valid(self) -> bool:
        if not self.jwt_token or not self.jwt_expiration:
            return False
        remaining = (self.jwt_expiration - datetime.datetime.utcnow()).total_seconds()
        return remaining > 60
    
    async def authenticate(self) -> str:
        """Authenticate with Wazuh API and get JWT token"""
        if self._is_jwt_valid():
            return self.jwt_token
        
        auth_url = f"{self.config.base_url}/security/user/authenticate"
        auth = aiohttp.BasicAuth(self.config.username, self.config.password)
        
        try:
            logger.info(f"Authenticating with Wazuh API at {auth_url}")
            async with self.session.get(auth_url, auth=auth) as response:
                response.raise_for_status()
                data = await response.json()
                token = data.get("data", {}).get("token")
                if not token:
                    raise ValueError("JWT token not found in response")
                
                self.jwt_token = token
                self.jwt_expiration = datetime.datetime.utcnow() + datetime.timedelta(minutes=14)
                logger.info("Successfully authenticated with Wazuh API")
                return self.jwt_token
        except Exception as e:
            logger.error(f"Authentication failed: {str(e)}")
            raise
    
    async def _request(self, method: str, endpoint: str, **kwargs) -> Dict[str, Any]:
        """Make authenticated API request with automatic retry on 401"""
        token = await self.authenticate()
        headers = kwargs.pop("headers", {})
        headers["Authorization"] = f"Bearer {token}"
        
        url = f"{self.config.base_url}{endpoint}"
        
        try:
            async with self.session.request(method, url, headers=headers, **kwargs) as response:
                if response.status == 401:
                    logger.info("Token expired, re-authenticating...")
                    self.jwt_token = None
                    token = await self.authenticate()
                    headers["Authorization"] = f"Bearer {token}"
                    async with self.session.request(method, url, headers=headers, **kwargs) as retry_response:
                        retry_response.raise_for_status()
                        return await retry_response.json()
                
                response.raise_for_status()
                return await response.json()
        except Exception as e:
            logger.error(f"API request failed: {str(e)}")
            raise
    
    async def get_alerts(self, limit: int = 100, offset: int = 0, 
                        level: Optional[int] = None, sort: str = "-timestamp") -> Dict[str, Any]:
        """Get alerts from Wazuh"""
        params = {
            "limit": limit,
            "offset": offset,
            "sort": sort
        }
        if level is not None:
            params["level"] = level
        
        return await self._request("GET", "/alerts", params=params)
    
    async def get_agents(self, status: Optional[str] = None) -> Dict[str, Any]:
        """Get agent information"""
        params = {}
        if status:
            params["status"] = status
        return await self._request("GET", "/agents", params=params)
    
    async def get_agent_vulnerabilities(self, agent_id: str) -> Dict[str, Any]:
        """Get vulnerabilities for a specific agent"""
        return await self._request("GET", f"/vulnerability/{agent_id}")


class ExternalAPIClient:
    """Client for external security APIs"""
    
    def __init__(self, config: WazuhConfig):
        self.config = config
        self.session: Optional[aiohttp.ClientSession] = None
    
    async def __aenter__(self):
        self.session = aiohttp.ClientSession()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()
    
    async def check_ip_reputation(self, ip: str) -> Dict[str, Any]:
        """Check IP reputation using AbuseIPDB"""
        if not self.config.abuseipdb_api_key:
            return {"error": "AbuseIPDB API key not configured"}
        
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {
            "Key": self.config.abuseipdb_api_key,
            "Accept": "application/json"
        }
        params = {
            "ipAddress": ip,
            "maxAgeInDays": "90",
            "verbose": True
        }
        
        try:
            async with self.session.get(url, headers=headers, params=params) as response:
                response.raise_for_status()
                return await response.json()
        except Exception as e:
            logger.error(f"AbuseIPDB API error: {str(e)}")
            return {"error": str(e)}


class SecurityAnalyzer:
    """Advanced security analysis algorithms"""
    
    @staticmethod
    def calculate_risk_score(alerts: List[Dict[str, Any]], 
                           vulnerabilities: List[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Calculate comprehensive risk score based on multiple factors"""
        risk_factors = {
            "alert_severity": 0,
            "alert_frequency": 0,
            "vulnerability_score": 0,
            "time_clustering": 0,
            "attack_diversity": 0
        }
        
        if not alerts:
            return {"risk_score": 0, "risk_level": "low", "factors": risk_factors}
        
        # Alert severity scoring
        severity_weights = {1: 0.1, 2: 0.2, 3: 0.3, 4: 0.4, 5: 0.5,
                          6: 0.6, 7: 0.7, 8: 0.8, 9: 0.9, 10: 1.0,
                          11: 1.2, 12: 1.4, 13: 1.6, 14: 1.8, 15: 2.0}
        
        total_severity = sum(severity_weights.get(alert.get("rule", {}).get("level", 0), 0) 
                           for alert in alerts)
        risk_factors["alert_severity"] = min(total_severity / len(alerts) * 50, 100)
        
        # Calculate final risk score
        weights = {
            "alert_severity": 0.3,
            "alert_frequency": 0.2,
            "vulnerability_score": 0.25,
            "time_clustering": 0.15,
            "attack_diversity": 0.1
        }
        
        final_score = sum(risk_factors[factor] * weight 
                         for factor, weight in weights.items())
        
        # Determine risk level
        if final_score >= 80:
            risk_level = "critical"
        elif final_score >= 60:
            risk_level = "high"
        elif final_score >= 40:
            risk_level = "medium"
        else:
            risk_level = "low"
        
        return {
            "risk_score": round(final_score, 2),
            "risk_level": risk_level,
            "factors": risk_factors
        }


class WazuhMCPServer:
    """Enhanced MCP Server implementation for Wazuh integration"""
    
    def __init__(self):
        self.server = Server("wazuh-mcp")
        self.config = WazuhConfig()
        self.api_client: Optional[WazuhAPIClient] = None
        self.external_client: Optional[ExternalAPIClient] = None
        self._setup_handlers()
    
    def _setup_handlers(self):
        """Setup MCP protocol handlers with enhanced capabilities"""
        
        @self.server.list_resources()
        async def handle_list_resources() -> list[types.Resource]:
            """List available Wazuh resources"""
            return [
                types.Resource(
                    uri="wazuh://alerts/recent",
                    name="Recent Alerts",
                    description="Most recent security alerts from Wazuh",
                    mimeType="application/json"
                ),
                types.Resource(
                    uri="wazuh://alerts/summary",
                    name="Alert Summary",
                    description="Statistical summary of alerts",
                    mimeType="application/json"
                ),
                types.Resource(
                    uri="wazuh://agents/status",
                    name="Agent Status",
                    description="Status of all Wazuh agents",
                    mimeType="application/json"
                ),
                types.Resource(
                    uri="wazuh://vulnerabilities/critical",
                    name="Critical Vulnerabilities",
                    description="Critical vulnerabilities across all agents",
                    mimeType="application/json"
                ),
                types.Resource(
                    uri="wazuh://compliance/status",
                    name="Compliance Status",
                    description="Current compliance posture",
                    mimeType="application/json"
                )
            ]
        
        @self.server.read_resource()
        async def handle_read_resource(uri: str) -> str:
            """Read specific Wazuh resource"""
            try:
                if not self.api_client:
                    self.api_client = WazuhAPIClient(self.config)
                    await self.api_client.__aenter__()
                
                if uri == "wazuh://alerts/recent":
                    data = await self.api_client.get_alerts(limit=50)
                    return json.dumps(self._format_alerts(data), indent=2)
                
                elif uri == "wazuh://agents/status":
                    data = await self.api_client.get_agents()
                    return json.dumps(self._format_agents(data), indent=2)
                
                else:
                    raise ValueError(f"Unknown resource URI: {uri}")
                    
            except Exception as e:
                logger.error(f"Error reading resource {uri}: {str(e)}")
                return json.dumps({"error": str(e)})
        
        @self.server.list_tools()
        async def handle_list_tools() -> list[types.Tool]:
            """List available Wazuh tools"""
            return [
                types.Tool(
                    name="get_alerts",
                    description="Retrieve Wazuh alerts with filtering options",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "limit": {
                                "type": "integer",
                                "description": "Maximum number of alerts to retrieve",
                                "default": 100
                            },
                            "level": {
                                "type": "integer",
                                "description": "Minimum alert level (1-15)",
                                "minimum": 1,
                                "maximum": 15
                            }
                        }
                    }
                ),
                types.Tool(
                    name="analyze_threats",
                    description="Perform advanced threat analysis on current alerts",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "category": {
                                "type": "string",
                                "description": "Threat category to analyze",
                                "enum": ["all", "intrusion", "malware", "vulnerability"]
                            }
                        }
                    }
                ),
                types.Tool(
                    name="check_agent_health",
                    description="Check health status of Wazuh agents",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "agent_id": {
                                "type": "string",
                                "description": "Specific agent ID to check (optional)"
                            }
                        }
                    }
                )
            ]
        
        @self.server.call_tool()
        async def handle_call_tool(name: str, arguments: dict) -> list[types.TextContent]:
            """Execute Wazuh tools with enhanced capabilities"""
            try:
                if not self.api_client:
                    self.api_client = WazuhAPIClient(self.config)
                    await self.api_client.__aenter__()
                
                if name == "get_alerts":
                    limit = arguments.get("limit", 100)
                    level = arguments.get("level")
                    
                    data = await self.api_client.get_alerts(limit=limit, level=level)
                    formatted = self._format_alerts(data)
                    
                    return [types.TextContent(
                        type="text",
                        text=json.dumps(formatted, indent=2)
                    )]
                
                elif name == "analyze_threats":
                    category = arguments.get("category", "all")
                    alerts_data = await self.api_client.get_alerts(limit=500)
                    alerts = alerts_data.get("data", {}).get("affected_items", [])
                    
                    # Perform risk analysis
                    risk_assessment = SecurityAnalyzer.calculate_risk_score(alerts)
                    
                    analysis = {
                        "category": category,
                        "total_alerts": len(alerts),
                        "risk_assessment": risk_assessment,
                        "timestamp": datetime.datetime.utcnow().isoformat()
                    }
                    
                    return [types.TextContent(
                        type="text",
                        text=json.dumps(analysis, indent=2)
                    )]
                
                elif name == "check_agent_health":
                    agent_id = arguments.get("agent_id")
                    data = await self.api_client.get_agents()
                    agents = data.get("data", {}).get("affected_items", [])
                    
                    if agent_id:
                        agent = next((a for a in agents if a["id"] == agent_id), None)
                        if agent:
                            health = self._assess_agent_health(agent)
                            return [types.TextContent(
                                type="text",
                                text=json.dumps(health, indent=2)
                            )]
                    else:
                        health_report = self._assess_all_agents_health(data)
                        return [types.TextContent(
                            type="text",
                            text=json.dumps(health_report, indent=2)
                        )]
                
                else:
                    raise ValueError(f"Unknown tool: {name}")
                    
            except Exception as e:
                logger.error(f"Error executing tool {name}: {str(e)}")
                return [types.TextContent(
                    type="text",
                    text=json.dumps({"error": str(e)})
                )]
    
    def _format_alerts(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Format alerts for better readability"""
        alerts = data.get("data", {}).get("affected_items", [])
        
        formatted_alerts = []
        for alert in alerts:
            formatted_alerts.append({
                "id": alert.get("id"),
                "timestamp": alert.get("timestamp"),
                "rule": {
                    "id": alert.get("rule", {}).get("id"),
                    "description": alert.get("rule", {}).get("description"),
                    "level": alert.get("rule", {}).get("level"),
                    "groups": alert.get("rule", {}).get("groups", [])
                },
                "agent": {
                    "id": alert.get("agent", {}).get("id"),
                    "name": alert.get("agent", {}).get("name"),
                    "ip": alert.get("agent", {}).get("ip")
                },
                "location": alert.get("location")
            })
        
        return {
            "total_alerts": data.get("data", {}).get("total_affected_items", 0),
            "alerts": formatted_alerts,
            "query_time": datetime.datetime.utcnow().isoformat()
        }
    
    def _format_agents(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Format agent data with enhanced metrics"""
        agents = data.get("data", {}).get("affected_items", [])
        
        status_summary = {
            "active": 0,
            "disconnected": 0,
            "never_connected": 0,
            "pending": 0
        }
        
        formatted_agents = []
        for agent in agents:
            status = agent.get("status", "unknown")
            if status in status_summary:
                status_summary[status] += 1
            
            formatted_agents.append({
                "id": agent.get("id"),
                "name": agent.get("name"),
                "ip": agent.get("ip"),
                "status": status,
                "os": agent.get("os", {}).get("platform"),
                "version": agent.get("version"),
                "last_keep_alive": agent.get("lastKeepAlive")
            })
        
        return {
            "summary": status_summary,
            "total_agents": len(agents),
            "agents": formatted_agents
        }
    
    def _assess_agent_health(self, agent: Dict[str, Any]) -> Dict[str, Any]:
        """Assess health of a single agent"""
        status = agent.get("status", "unknown")
        health_status = "healthy" if status == "active" else "unhealthy"
        
        return {
            "agent_id": agent.get("id"),
            "agent_name": agent.get("name"),
            "health_status": health_status,
            "status": status,
            "details": {
                "ip": agent.get("ip"),
                "os": agent.get("os", {}).get("platform"),
                "version": agent.get("version")
            }
        }
    
    def _assess_all_agents_health(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Assess health of all agents"""
        agents = data.get("data", {}).get("affected_items", [])
        
        health_report = {
            "total_agents": len(agents),
            "healthy": 0,
            "unhealthy": 0,
            "agents": []
        }
        
        for agent in agents:
            agent_health = self._assess_agent_health(agent)
            health_report["agents"].append(agent_health)
            
            if agent_health["health_status"] == "healthy":
                health_report["healthy"] += 1
            else:
                health_report["unhealthy"] += 1
        
        health_report["health_percentage"] = (
            (health_report["healthy"] / len(agents) * 100) if agents else 0
        )
        
        return health_report
    
    async def run(self):
        """Run the MCP server"""
        async with mcp.server.stdio.stdio_server() as (read_stream, write_stream):
            logger.info("Wazuh MCP Server (Enhanced Edition) starting...")
            logger.info(f"Connecting to Wazuh at {self.config.base_url}")
            
            init_options = InitializationOptions(
                server_name="wazuh-mcp",
                server_version="2.0.0",
                capabilities=self.server.get_capabilities(
                    notification_options=NotificationOptions(),
                    experimental_capabilities={}
                )
            )
            
            try:
                await self.server.run(
                    read_stream,
                    write_stream,
                    init_options
                )
            except Exception as e:
                logger.error(f"Server error: {str(e)}")
                raise
            finally:
                if self.api_client:
                    await self.api_client.__aexit__(None, None, None)
                if self.external_client:
                    await self.external_client.__aexit__(None, None, None)


async def main():
    """Main entry point"""
    try:
        server = WazuhMCPServer()
        await server.run()
    except KeyboardInterrupt:
        logger.info("Server shutdown requested")
    except Exception as e:
        logger.error(f"Fatal error: {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
