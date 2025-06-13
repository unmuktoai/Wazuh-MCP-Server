#!/usr/bin/env python3
"""
Quick script to create .env.example file if it doesn't exist
"""

import os

env_example_content = """# Wazuh Configuration
WAZUH_HOST=localhost
WAZUH_PORT=55000
WAZUH_USER=admin
WAZUH_PASS=admin
VERIFY_SSL=false

# External API Keys (Optional)
# Get your API keys from:
# VirusTotal: https://www.virustotal.com/gui/my-apikey
# Shodan: https://account.shodan.io/
# AbuseIPDB: https://www.abuseipdb.com/api

VIRUSTOTAL_API_KEY=
SHODAN_API_KEY=
ABUSEIPDB_API_KEY=

# Server Configuration
DEBUG=false

# Performance Settings
MAX_ALERTS_PER_QUERY=1000
MAX_AGENTS_PER_SCAN=10
CACHE_TTL_SECONDS=300
REQUEST_TIMEOUT_SECONDS=30

# Feature Flags
ENABLE_EXTERNAL_INTEL=true
ENABLE_ML_ANALYSIS=true
ENABLE_COMPLIANCE_CHECKING=true
"""

def create_env_files():
    """Create .env.example and optionally .env"""
    
    # Create .env.example
    if not os.path.exists('.env.example'):
        with open('.env.example', 'w') as f:
            f.write(env_example_content)
        print("✓ Created .env.example")
    else:
        print("✓ .env.example already exists")
    
    # Create .env if it doesn't exist
    if not os.path.exists('.env'):
        response = input("\nWould you like to create .env from .env.example? (y/n): ")
        if response.lower() == 'y':
            with open('.env', 'w') as f:
                f.write(env_example_content)
            print("✓ Created .env")
            print("\n⚠️  IMPORTANT: Edit .env with your actual Wazuh credentials!")
            print("   - WAZUH_HOST: Your Wazuh server address")
            print("   - WAZUH_USER: Your Wazuh username")
            print("   - WAZUH_PASS: Your Wazuh password")
        else:
            print("\nTo create .env manually:")
            print("  Windows: copy .env.example .env")
            print("  Linux/Mac: cp .env.example .env")
    else:
        print("✓ .env already exists")

if __name__ == "__main__":
    create_env_files()
