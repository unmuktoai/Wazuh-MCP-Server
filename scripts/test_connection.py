#!/usr/bin/env python3
import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from config import WazuhConfig
from wazuh_mcp_server import WazuhAPIClient


async def test_connection():
    config = WazuhConfig()
    
    print(f"Testing connection to {config.base_url}...")
    
    try:
        async with WazuhAPIClient(config) as client:
            token = await client.authenticate()
            print("✓ Authentication successful")
            
            agents = await client.get_agents()
            agent_count = agents.get("data", {}).get("total_affected_items", 0)
            print(f"✓ Found {agent_count} agents")
            
            print("\nConnection test successful!")
            
    except Exception as e:
        print(f"✗ Connection test failed: {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(test_connection())
