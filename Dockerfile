# Pinned multi-stage Dockerfile for reproducible PayoutProof pilot baseline.
# Stage 1: Build the production TypeScript/Vite frontend assets.
FROM node:20.15.1-bookworm-slim AS web-builder

WORKDIR /app/web

COPY web/package.json web/package-lock.json ./
RUN npm ci --ignore-scripts

COPY web/ ./
RUN npm run build

# Stage 2: Minimal hardened Python runtime.
FROM python:3.11.9-slim-bookworm AS runtime

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PAYOUTPROOF_ENV=production \
    PORT=8000

# Install pinned uv binary from official distribution
COPY --from=ghcr.io/astral-sh/uv:0.2.34 /uv /bin/uv

WORKDIR /app

# Create unprivileged system user for runtime execution
RUN groupadd -g 10001 appgroup && \
    useradd -u 10001 -g appgroup -s /bin/false -M appuser

# Install Python project dependencies from frozen lockfile
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project

# Copy application source, tools, and compiled frontend distribution
COPY README.md ./
COPY src/ ./src/
COPY scripts/ ./scripts/
COPY --from=web-builder /app/web/dist ./web/dist

# Install the application itself into the frozen environment
RUN uv sync --frozen --no-dev

# Ensure appropriate filesystem permissions
RUN chown -R appuser:appgroup /app

USER appuser

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD python3 -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/api/health', timeout=4)" || exit 1

ENTRYPOINT ["uv", "run", "uvicorn", "payoutproof.api.app:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000"]
