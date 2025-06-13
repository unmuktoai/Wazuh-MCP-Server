from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="wazuh-mcp-server",
    version="2.0.0",
    author="Security Team",
    description="MCP server for Wazuh SIEM integration",
    long_description=long_description,
    long_description_content_type="text/markdown",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    python_requires=">=3.8",
    install_requires=[
        "mcp>=0.9.0",
        "aiohttp>=3.9.0",
        "urllib3>=2.0.0",
        "python-dateutil>=2.8.2",
    ],
    entry_points={
        "console_scripts": [
            "wazuh-mcp-server=wazuh_mcp_server:main",
        ],
    },
)
