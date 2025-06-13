FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y gcc g++ && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY src/ ./src/
COPY setup.py .
COPY README.md .

RUN pip install -e .

RUN useradd -m -u 1000 mcp && chown -R mcp:mcp /app
USER mcp

ENV PYTHONUNBUFFERED=1

CMD ["python", "src/wazuh_mcp_server.py"]
