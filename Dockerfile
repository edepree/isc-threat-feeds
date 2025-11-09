# --------------------------------------------------------------
# BUILDER STAGE
# --------------------------------------------------------------
FROM ghcr.io/astral-sh/uv:python3.13-alpine AS builder

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=0

WORKDIR /app

COPY pyproject.toml uv.lock entrypoint.sh isc_threat_feeds.py ./
RUN uv sync --locked --no-dev

# --------------------------------------------------------------
# RUNTIME STAGE
# --------------------------------------------------------------
FROM python:3.13-alpine

# add a tiny PID1 to forward signals correctly
RUN apk add --no-cache dumb-init

# setup a non-root user
RUN addgroup -S appgroup && adduser -S appuser -G appgroup

# copy the application from the builder
COPY --from=builder --chown=appuser:appgroup /app/ /app/

# place executables in the environment at the front of the path
# ensures output is logged in real time and keep bytecode in memory
ENV PATH="/app/.venv/bin:$PATH" PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1

# configure user, ports, and entrypoint
WORKDIR /app
USER appuser
EXPOSE 8080
ENTRYPOINT ["/usr/bin/dumb-init", "--", "/app/entrypoint.sh"]
