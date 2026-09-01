FROM node:22-bookworm-slim@sha256:6c74791e557ce11fc957704f6d4fe134a7bc8d6f5ca4403205b2966bd488f6b3 AS dashboard

WORKDIR /build
COPY package.json package-lock.json tsconfig.json ./
COPY frontend ./frontend
RUN npm ci --ignore-scripts \
    && npm run frontend:check \
    && npm run frontend:build

FROM langchain/langgraph-api:3.11@sha256:b3d7570205d4100f97f63ab1e32815f4d795b3cdd9dde66070081d3db23b0cb6

# PostgreSQL 16 client for scheduler backups (the Debian base otherwise ships an older major).
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl gnupg \
    && install -d /usr/share/postgresql-common/pgdg \
    && curl --fail --location https://www.postgresql.org/media/keys/ACCC4CF8.asc \
      | gpg --dearmor -o /usr/share/postgresql-common/pgdg/apt.postgresql.org.gpg \
    && . /etc/os-release \
    && echo "deb [signed-by=/usr/share/postgresql-common/pgdg/apt.postgresql.org.gpg] https://apt.postgresql.org/pub/repos/apt ${VERSION_CODENAME}-pgdg main" \
      > /etc/apt/sources.list.d/pgdg.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends postgresql-client-16 \
    && pg_dump --version | grep -E " 16[.]" \
    && rm -rf /var/lib/apt/lists/*

ARG VERSION=0.0.0
ARG VCS_REF=unknown

LABEL org.opencontainers.image.title="opendevops" \
      org.opencontainers.image.description="Policy-gated autonomous DevOps agent" \
      org.opencontainers.image.source="https://github.com/skundu42/opendevops" \
      org.opencontainers.image.url="https://github.com/skundu42/opendevops" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${VCS_REF}"

COPY . /deps/devops-agent
COPY --from=dashboard \
    /build/src/opendevops/interfaces/dashboard_assets/generated/ \
    /deps/devops-agent/src/opendevops/interfaces/dashboard_assets/generated/

RUN cd /deps/devops-agent \
    && PYTHONDONTWRITEBYTECODE=1 uv pip install --system --no-cache-dir \
        -c /api/constraints.txt -e '.[checkpoint,server,slack,scheduler,ssh]'

ENV LANGGRAPH_HTTP='{"app": "/deps/devops-agent/src/opendevops/interfaces/webapp.py:app"}'
ENV LANGSERVE_GRAPHS='{"devops": "/deps/devops-agent/src/opendevops/agent.py:server_graph"}'

# Ensure user dependencies did not overwrite the Agent Server package.
RUN mkdir -p /api/langgraph_api /api/langgraph_runtime /api/langgraph_license \
    && touch /api/langgraph_api/__init__.py /api/langgraph_runtime/__init__.py \
        /api/langgraph_license/__init__.py \
    && PYTHONDONTWRITEBYTECODE=1 uv pip install --system --no-cache-dir --no-deps -e /api

# Match the LangGraph CLI-generated hardening: build tooling is absent from the runtime image.
RUN pip uninstall -y pip setuptools wheel \
    && rm -rf /usr/local/lib/python*/site-packages/pip* \
        /usr/local/lib/python*/site-packages/setuptools* \
        /usr/local/lib/python*/site-packages/wheel* \
        /usr/lib/python*/site-packages/pip* \
        /usr/lib/python*/site-packages/setuptools* \
        /usr/lib/python*/site-packages/wheel* \
    && find /usr/local/bin /usr/bin -name "pip*" -delete \
    && uv pip uninstall --system pip setuptools wheel \
    && rm -f /usr/bin/uv /usr/bin/uvx

WORKDIR /deps/devops-agent
