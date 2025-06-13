"""Configuration management"""

import os
from dataclasses import dataclass
from enum import Enum


class AlertSeverity(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ComplianceFramework(Enum):
    PCI_DSS = "pci_dss"
    HIPAA = "hipaa"
    GDPR = "gdpr"
    NIST = "nist"
    ISO27001 = "iso27001"


class ThreatCategory(Enum):
    MALWARE = "malware"
    INTRUSION = "intrusion"
    VULNERABILITY = "vulnerability"
    COMPLIANCE = "compliance"
    AUTHENTICATION = "authentication"
    DOS = "denial_of_service"
    DATA_LEAK = "data_leak"
    PRIVILEGE_ESCALATION = "privilege_escalation"


@dataclass
class WazuhConfig:
    host: str = os.getenv("WAZUH_HOST", "localhost")
    port: int = int(os.getenv("WAZUH_PORT", "55000"))
    username: str = os.getenv("WAZUH_USER", "admin")
    password: str = os.getenv("WAZUH_PASS", "admin")
    verify_ssl: bool = os.getenv("VERIFY_SSL", "false").lower() == "true"
    api_version: str = os.getenv("WAZUH_API_VERSION", "v4")
    
    virustotal_api_key: str = os.getenv("VIRUSTOTAL_API_KEY", "")
    shodan_api_key: str = os.getenv("SHODAN_API_KEY", "")
    abuseipdb_api_key: str = os.getenv("ABUSEIPDB_API_KEY", "")
    
    @property
    def base_url(self) -> str:
        return f"https://{self.host}:{self.port}"
