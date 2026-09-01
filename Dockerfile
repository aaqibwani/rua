# syntax=docker/dockerfile:1

FROM python:3.12-slim AS build
WORKDIR /app
ENV PIP_DISABLE_PIP_VERSION_CHECK=1 PIP_NO_CACHE_DIR=1
RUN apt-get update && apt-get install -y --no-install-recommends build-essential \
    && rm -rf /var/lib/apt/lists/*
COPY requirements.txt .
# setuptools and wheel are installed explicitly so that the package build below
# can run without network access. See the --no-build-isolation note there.
RUN python -m venv /venv \
    && /venv/bin/pip install --upgrade "setuptools>=77" wheel \
    && /venv/bin/pip install -r requirements.txt
# Install the package itself so the `rua` console script exists in /venv/bin.
# Without this the runtime CMD below fails with "rua: not found": installing
# requirements.txt brings in the dependencies but never the application.
#
# --no-deps: requirements.txt is the single source of truth for versions, and
#   pyproject.toml deliberately declares no runtime dependencies.
# --no-build-isolation: PEP 517 otherwise builds in a throwaway environment and
#   downloads the newest setuptools from PyPI mid-build. That makes the image
#   depend on whatever was released today, and it fails outright on any network
#   that inspects TLS. The setuptools installed above is used instead.
COPY pyproject.toml README.md LICENSE NOTICE ./
COPY rua ./rua
RUN /venv/bin/pip install --no-deps --no-build-isolation .

FROM python:3.12-slim AS runtime
WORKDIR /app
ENV PATH="/venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1
RUN apt-get update && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 10001 rua
COPY --from=build /venv /venv
COPY --chown=rua:rua . .
USER rua
EXPOSE 8080

# One image, two entrypoints. Compose runs both.
#   rua serve      — FastAPI, API + frontend
#   rua scheduler  — ingestion and domain sync
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD curl -fsS http://localhost:8080/healthz || exit 1
CMD ["rua", "serve", "--host", "0.0.0.0", "--port", "8080"]
