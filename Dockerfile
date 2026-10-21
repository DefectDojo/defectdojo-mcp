# syntax=docker/dockerfile:1
FROM ghcr.io/astral-sh/uv:0.13.1-python3.13-trixie-slim AS build
WORKDIR /app
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy UV_PYTHON_DOWNLOADS=never
COPY pyproject.toml uv.lock README.md LICENSE ./
RUN uv sync --locked --no-dev --no-install-project
COPY src ./src
RUN uv sync --locked --no-dev --no-editable

FROM python:3.13-slim-trixie
LABEL org.opencontainers.image.title="defectdojo-mcp" \
      org.opencontainers.image.description="Open-source MCP server for DefectDojo" \
      org.opencontainers.image.source="https://github.com/DefectDojo/defectdojo-mcp" \
      org.opencontainers.image.licenses="BSD-3-Clause"
# eMudhra's roots stopped being trustworthy on 2026-10-20 (Mozilla bug 2083449). certifi 2026.10.19 (in uv.lock)
# drops them for httpx, and this separate layer patches the system store for anything else that reads it.
RUN apt-get update \
  && apt-get install -y --no-install-recommends --only-upgrade ca-certificates \
  && rm -rf /var/lib/apt/lists/*
RUN useradd --create-home --uid 10001 mcp
COPY --from=build /app/.venv /app/.venv
ENV PATH="/app/.venv/bin:$PATH" PYTHONUNBUFFERED=1
USER mcp
WORKDIR /home/mcp
ENTRYPOINT ["defectdojo-mcp"]
