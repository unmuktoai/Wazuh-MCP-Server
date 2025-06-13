# 🛡️ Wazuh MCP Server - AI-Powered Security Operations

<div align="center">

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![MCP Compatible](https://img.shields.io/badge/MCP-Compatible-green.svg)](https://modelcontextprotocol.io/)
[![Wazuh 4.x](https://img.shields.io/badge/Wazuh-4.x-blue.svg)](https://wazuh.com/)
[![Claude Desktop](https://img.shields.io/badge/Claude-Desktop-purple.svg)](https://claude.ai/)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](http://makeapullrequest.com)

**Transform your security operations with AI-powered threat detection, automated incident response, and natural language security analysis.**

[Features](#-key-features) •
[Quick Start](#-quick-start) •
[Documentation](#-documentation) •
[Contributing](#-contributing) •
[Roadmap](#-roadmap)

</div>

---

## 🎯 What is Wazuh MCP Server?

Wazuh MCP Server bridges the gap between traditional SIEM operations and conversational AI, enabling security teams to interact with their Wazuh infrastructure using natural language through Claude Desktop. This isn't just another integration - it's a paradigm shift in how security operations are conducted.

### 🤔 Why Should You Care?

- **🚀 10x Faster Incident Response**: Query your security data conversationally instead of writing complex queries
- **🧠 AI-Enhanced Analysis**: Leverage Claude's reasoning capabilities for threat analysis and correlation
- **🔄 Automated Workflows**: Convert natural language requests into complex security operations
- **📊 Real-time Intelligence**: Get instant insights from multiple threat intelligence sources
- **🎓 Lower Learning Curve**: New team members can be productive immediately without learning query languages

## 🌟 Key Features

### 🔍 Advanced Threat Detection & Analysis

- **Multi-dimensional Risk Scoring**: Combines alert severity, frequency, vulnerability data, and behavioral patterns
- **ML-based Anomaly Detection**: Statistical analysis with configurable sensitivity levels
- **MITRE ATT&CK Mapping**: Automatic TTP identification and kill chain analysis
- **Threat Correlation Engine**: Cross-references alerts with external threat intelligence

### 🤖 Natural Language Security Operations

Ask Claude questions like:
- *"Are we under attack right now?"*
- *"Show me all privilege escalation attempts in the last 48 hours"*
- *"Which systems have critical vulnerabilities that are being actively exploited?"*
- *"Generate an executive report on our security posture"*

### 📋 Compliance Automation

- **Multi-Framework Support**: PCI DSS, HIPAA, GDPR, NIST, ISO 27001
- **Automated Gap Analysis**: Identifies missing controls and generates remediation plans
- **Continuous Monitoring**: Real-time compliance scoring with trend analysis
- **Audit-Ready Reports**: Generate compliance evidence with a single command

### 🌐 Threat Intelligence Integration

- **VirusTotal**: File hash reputation and malware analysis
- **Shodan**: Internet-wide scan data and exposure assessment
- **AbuseIPDB**: IP reputation and abuse history
- **Custom Feeds**: Extensible architecture for additional threat feeds

## 🛠️ Technical Architecture

### Core Components

1. **MCP Protocol Handler**: Implements the Model Context Protocol for Claude Desktop communication
2. **Async API Client**: High-performance, non-blocking Wazuh API interactions
3. **Analysis Engine**: Advanced security algorithms for threat detection and risk assessment
4. **Intelligence Aggregator**: Consolidates data from multiple threat intelligence sources
5. **Compliance Framework**: Modular compliance checking and reporting system

## 📊 Available Tools & Resources

### 🛠️ 14 Powerful Tools

- `get_alerts` - Retrieve and filter security alerts
- `analyze_threats` - Advanced threat analysis with ML
- `risk_assessment` - Comprehensive risk scoring
- `detect_anomalies` - ML-based anomaly detection
- `check_agent_health` - Agent health monitoring
- `compliance_check` - Framework compliance validation
- `check_ioc` - IOC reputation checking
- `threat_hunt` - Pattern-based threat hunting
- `create_incident` - Incident management
- `vulnerability_scan` - Vulnerability assessment
- And 4 more...

### 📚 7 Real-time Resources

- `wazuh://alerts/recent` - Live security alert feed
- `wazuh://agents/status` - Agent health dashboard
- `wazuh://vulnerabilities/critical` - Critical vulnerability tracker
- `wazuh://compliance/status` - Compliance posture monitor
- `wazuh://threats/active` - Active threat campaigns

## 🚀 Quick Start

### Prerequisites

- Python 3.8+ 
- Wazuh 4.x deployment
- Claude Desktop application

### Installation

```bash
# Clone and enter directory
git clone https://github.com/unmuktoai/wazuh-mcp-server.git
cd wazuh-mcp-server

# Run installer
./scripts/install.sh  # or install.bat on Windows

# Configure credentials
cp .env.example .env
nano .env  # Add your Wazuh credentials

# Test connection
python scripts/test_connection.py
```

### 🐳 Docker Installation

```bash
docker-compose up -d
```

## 💡 Usage Examples

Ask Claude questions like:

- "Are there any signs of compromise on our web servers?"
- "Generate a PCI DSS compliance report for our quarterly audit"
- "Hunt for signs of lateral movement in our network"
- "Check if IP 192.168.1.100 is malicious"
- "Show me critical vulnerabilities being exploited"

## 🛣️ Roadmap

### 🚀 What's Next?

We're actively developing new features and would love your help! Here's what we're working on:

- [ ] **Advanced ML models** for threat prediction and behavioral analysis
- [ ] **Custom detection rules** creation via natural language
- [ ] **Automated response actions** for common security incidents
- [ ] **Multi-tenant support** for MSSPs and large organizations
- [ ] **Real-time threat intelligence** correlation with custom feeds
- [ ] **GraphQL API** for advanced integrations
- [ ] **Distributed architecture** for high-scale deployments
- [ ] **SOAR platform integration** (Phantom, Demisto, etc.)
- [ ] **Advanced forensics** capabilities with memory analysis
- [ ] **Threat simulation** and purple team automation
- [ ] **Custom dashboards** and visualization tools
- [ ] **Mobile app** for on-the-go security monitoring

### 🤝 Want to Contribute?

Pick any item from the roadmap (or propose your own!) and start contributing. We provide mentorship for new contributors and have a welcoming community. Check our [Contributing Guide](#-contributing) to get started!

## 👥 Contributing

We welcome contributions from the security community! Whether you're a security researcher, developer, or SOC analyst, there's a place for you here.

### 🎯 How You Can Help

- **🔍 Security Researchers**: Contribute new threat detection algorithms or analysis techniques
- **💻 Developers**: Add new integrations, improve performance, or enhance the codebase
- **🛡️ SOC Analysts**: Share real-world use cases and help improve workflows
- **📚 Technical Writers**: Improve documentation and create tutorials
- **🧪 Testers**: Help us find bugs and improve reliability
- **🎨 UX Enthusiasts**: Suggest improvements for better user experience

### 🚀 Getting Started

1. **Fork** the repository
2. **Pick an issue** labeled `good first issue` or `help wanted`
3. **Create** your feature branch (`git checkout -b feature/AmazingFeature`)
4. **Commit** your changes (`git commit -m 'Add some AmazingFeature'`)
5. **Push** to the branch (`git push origin feature/AmazingFeature`)
6. **Open** a Pull Request

### 💡 Contribution Ideas

- Implement a new threat intelligence source integration
- Add support for your favorite compliance framework
- Create custom analysis algorithms for specific attack patterns
- Improve error handling and logging
- Add more natural language query examples
- Create video tutorials or blog posts
- Translate documentation to other languages

### 🛠️ Development Setup

```bash
# Clone your fork
git clone https://github.com/unmuktoai/wazuh-mcp-server.git
cd wazuh-mcp-server

# Create virtual environment
python -m venv venv
source venv/bin/activate  # or venv\Scripts\activate on Windows

# Install in development mode
pip install -e ".[dev]"

# Run tests
pytest

# We're here to help!
# Join our Discord for questions: https://discord.gg/wazuh-mcp
```

**First time contributing to open source?** No problem! We'll help you through the process. Just open an issue saying you'd like to help, and we'll find something perfect for your skill level.

## 📚 Documentation

- [Installation Guide](docs/installation.md)
- [Configuration Reference](docs/configuration.md)
- [Usage Examples](docs/usage.md)
- [API Reference](docs/api_reference.md)

## 💬 Community

- [Discussions](https://github.com/unmuktoai/Wazuh-MCP-Server/discussions/)
- [Issue Tracker](https://github.com/unmuktoai/wazuh-mcp-server/issues)
- 

## 📄 License

MIT License - see [LICENSE](LICENSE) file for details.

---

<div align="center">

**Built with ❤️ in Kolkata and Globally**

*"Making security operations as natural as having a conversation"*

</div>