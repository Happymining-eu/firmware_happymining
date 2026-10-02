# HappyMining OS control plane (API, dashboard and worker share this image).
# Build context is the repository root:
#   docker build -f api/Dockerfile -t happymining-api .
#
# Dependencies are installed from api/uv.lock, which pins every package and
# its hash. Nothing is resolved at build time.

FROM python:3.13-slim-bookworm AS build
COPY --from=ghcr.io/astral-sh/uv:0.11.32 /uv /usr/local/bin/uv
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy UV_PYTHON_DOWNLOADS=never
WORKDIR /app/api
COPY api/pyproject.toml api/uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project
COPY api/happymining ./happymining
RUN uv sync --frozen --no-dev --no-editable

FROM python:3.13-slim-bookworm
RUN groupadd --system --gid 10001 happymining \
 && useradd --system --uid 10001 --gid happymining --home-dir /nonexistent --shell /usr/sbin/nologin happymining
WORKDIR /app
COPY --from=build /app/api/.venv /app/api/.venv
COPY api/happymining /app/api/happymining
COPY migrations /app/migrations
COPY alembic.ini /app/alembic.ini
COPY dashboard /app/dashboard
ENV PATH="/app/api/.venv/bin:${PATH}" \
    PYTHONPATH=/app/api \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    HM_MIGRATIONS_DIR=/app/migrations
USER 10001:10001
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=3)"]
# The client address is taken from X-Forwarded-For by the application itself,
# for exactly HM_TRUSTED_PROXY_HOPS proxies. uvicorn's own --proxy-headers is
# deliberately not used: with a wildcard it would trust a client-supplied value.
CMD ["uvicorn", "happymining.main:app_factory", "--factory", "--host", "0.0.0.0", "--port", "8000", \
     "--no-proxy-headers", "--no-server-header"]
