# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e

FROM ghcr.io/astral-sh/uv:0.11.21@sha256:ff07b86af50d4d9391d9daf4ff89ce427bc544f9aae87057e69a1cc0aa369946 AS uv

FROM python:3.14-slim@sha256:a7fb1e634c4a578f9e0bd6327f11a3cde11b7a9395f48e24360c0988bcc5c2bc AS builder
COPY --from=uv /uv /usr/local/bin/uv
ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never
WORKDIR /app
COPY pyproject.toml uv.lock README.md LICENSE NOTICE ./
COPY src ./src
RUN uv sync --frozen --no-dev --extra server --extra client --no-editable

FROM python:3.14-slim@sha256:a7fb1e634c4a578f9e0bd6327f11a3cde11b7a9395f48e24360c0988bcc5c2bc AS runtime
ENV PATH="/app/.venv/bin:${PATH}" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1
RUN groupadd --gid 10001 lets \
    && useradd --uid 10001 --gid 10001 --no-create-home --home-dir /nonexistent lets
WORKDIR /app
COPY --from=builder --chown=10001:10001 /app/.venv /app/.venv
COPY --chown=10001:10001 \
    deploy/__init__.py \
    deploy/bootstrap_cluster.py \
    deploy/configure_toxiproxy.py \
    deploy/peer_tool.py \
    deploy/start_warden.py \
    /app/deploy/
USER 10001:10001
EXPOSE 8080
ENTRYPOINT []
CMD ["lets", "--help"]
