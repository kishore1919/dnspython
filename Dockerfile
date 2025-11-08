# Multi-stage build: builder stage for dependencies, final stage for runtime
FROM python:3.11-slim AS builder

ENV PYTHONUNBUFFERED=1
WORKDIR /app

# Install uv
RUN pip install uv

# Copy dependency files first for better caching
COPY pyproject.toml uv.lock* requirements.txt* /app/

# Sync dependencies into a virtual environment
RUN uv sync --no-install-project

RUN uv pip install requests==2.28.0
# Final stage: slim runtime image
FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1
WORKDIR /app

# Copy the virtual environment from builder
COPY --from=builder /app/.venv /app/.venv

# Copy repository into container (excluding venv via .dockerignore)
COPY . /app

# Activate venv and set PATH
ENV PATH="/app/.venv/bin:$PATH"

# Default command — override in docker-compose or on docker run
CMD ["python", "main.py"]
