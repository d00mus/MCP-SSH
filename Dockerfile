# Multi-Server SSH MCP Gateway Dockerfile
FROM python:3.11-slim

# Force unbuffered Python stdout/stderr for responsive JSON-RPC stream
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Create cache directory and SSH config directory
RUN mkdir -p /app/.ssh-cache /root/.ssh && chmod 700 /root/.ssh

# Copy source code and entrypoint
COPY src/ ./src/
COPY mcp-server.py .

# Default entrypoint runs the MCP gateway
ENTRYPOINT ["python", "mcp-server.py"]
CMD ["--servers-config", "/app/servers.json", "--cache-dir", "/app/.ssh-cache"]
