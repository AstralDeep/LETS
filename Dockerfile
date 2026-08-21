# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e

ARG SOURCE_DATE_EPOCH=0

FROM ghcr.io/astral-sh/uv:0.12.3@sha256:2d890623d310b57771ce840f0da5eed5fc6d657da05ffaa45d82797b53fa3abc AS uv

FROM python:3.14-alpine@sha256:05b2b8b732ecd268fee8727a369f936f022d1321b59befd13c30ede22769dcdc AS builder
ARG SOURCE_DATE_EPOCH
COPY --from=uv /uv /usr/local/bin/uv
ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never \
    SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH}
WORKDIR /app
COPY pyproject.toml uv.lock README.md LICENSE NOTICE ./
COPY src ./src
RUN uv sync --frozen --no-dev --extra server --extra client --no-editable \
    && for record in /app/.venv/lib/python*/site-packages/lets_agent-*.dist-info/RECORD; do \
        test -f "${record}"; \
        sed -i '/lets_agent-.*\.dist-info\/uv_cache\.json,/d' "${record}"; \
    done \
    && find /app/.venv \
        -path '*/lets_agent-*.dist-info/uv_cache.json' \
        -type f -delete \
    && find /app/.venv -exec touch -h -d "@${SOURCE_DATE_EPOCH}" {} +

FROM python:3.14-alpine@sha256:05b2b8b732ecd268fee8727a369f936f022d1321b59befd13c30ede22769dcdc AS runtime
ARG SOURCE_DATE_EPOCH
ARG BUILD_DATE="unknown"
ARG VERSION="0.0.0"
ARG VCS_REF="unknown"
LABEL org.opencontainers.image.created="${BUILD_DATE}" \
    org.opencontainers.image.description="Distributed Lineage Escrow Transition Systems runtime" \
    org.opencontainers.image.licenses="Apache-2.0" \
    org.opencontainers.image.revision="${VCS_REF}" \
    org.opencontainers.image.source="https://github.com/AstralDeep/LETS" \
    org.opencontainers.image.title="LETS" \
    org.opencontainers.image.version="${VERSION}"
ENV PATH="/app/.venv/bin:${PATH}" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1
RUN rm -rf \
        /usr/local/lib/python3.14/site-packages/pip \
        /usr/local/lib/python3.14/site-packages/pip-*.dist-info \
        /usr/local/bin/pip \
        /usr/local/bin/pip3 \
        /usr/local/bin/pip3.14 \
    && addgroup -S -g 10001 lets \
    && adduser -S -D -H -h /nonexistent -s /sbin/nologin -u 10001 -G lets lets \
    && mkdir -p /app \
    && for account_file in \
        /etc/group /etc/group- /etc/gshadow /etc/gshadow- \
        /etc/passwd /etc/passwd- /etc/shadow /etc/shadow-; do \
        if test -e "${account_file}"; then \
            touch -h -d "@${SOURCE_DATE_EPOCH}" "${account_file}"; \
        fi; \
    done \
    && touch -h -d "@${SOURCE_DATE_EPOCH}" /app
WORKDIR /app
COPY --from=builder --chown=0:0 /app/.venv /app/.venv
COPY --chown=0:0 deploy/production/healthcheck.py /app/deploy/production/healthcheck.py
RUN chmod -R a-w /app \
    && find /app -type d -exec chmod a+rx {} + \
    && find /app -exec touch -h -d "@${SOURCE_DATE_EPOCH}" {} +
USER 10001:10001
EXPOSE 8080 8443
ENTRYPOINT []
CMD ["lets", "--help"]

FROM runtime AS production-acceptance
USER 0:0
RUN apk add --no-cache openssl=3.5.7-r0
COPY --chown=0:0 deploy/production/acceptance /app/deploy/production/acceptance
RUN chmod -R a-w /app/deploy/production/acceptance \
    && find /app/deploy/production/acceptance -type d -exec chmod a+rx {} +
USER 10001:10001

FROM runtime AS development-acceptance
USER 0:0
COPY --chown=0:0 \
    deploy/__init__.py \
    deploy/bootstrap_cluster.py \
    deploy/configure_toxiproxy.py \
    deploy/peer_tool.py \
    deploy/start_warden.py \
    /app/deploy/
RUN chmod -R a-w /app/deploy \
    && find /app/deploy -type d -exec chmod a+rx {} +
USER 10001:10001
