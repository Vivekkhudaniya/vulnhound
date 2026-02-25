# ============================================
# VulnHound Docker Image
# ============================================
# Includes: Python 3.11, Foundry, Slither, Aderyn
# Usage:
#   docker build -t vulnhound .
#   docker run -it --env-file .env vulnhound audit <repo-url>

FROM python:3.11-slim AS base

# System dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    curl \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Install Foundry (forge, anvil, cast)
RUN curl -L https://foundry.paradigm.xyz | bash \
    && /root/.foundry/bin/foundryup
ENV PATH="/root/.foundry/bin:${PATH}"

# Install Slither
RUN pip install --no-cache-dir slither-analyzer

# Install Aderyn (Rust-based, fast static analysis)
# Note: Requires Rust toolchain for building from source
# For now, we'll use Slither as primary. Add Aderyn when binary releases are stable.
# RUN curl -L https://raw.githubusercontent.com/Cyfrin/aderyn/main/install.sh | bash

WORKDIR /app

# Install Python dependencies
COPY pyproject.toml .
RUN pip install --no-cache-dir -e ".[dev]" 2>/dev/null || pip install --no-cache-dir . 2>/dev/null || echo "Will install after full copy"

# Copy source
COPY . .
RUN pip install --no-cache-dir -e ".[dev]" 2>/dev/null || true

# Create data directories
RUN mkdir -p /app/data/chromadb /app/reports /app/knowledge/exploits

ENTRYPOINT ["python", "-m", "src.cli.main"]
CMD ["--help"]
