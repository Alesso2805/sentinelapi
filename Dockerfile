# The demo app's image: SentinelAPI as installed from uv.lock, and the demo on top.
# Every version is pinned, so the same commit builds the same image (SEN-28).

FROM python:3.12.15-slim-bookworm AS build
COPY --from=ghcr.io/astral-sh/uv:0.11.25 /uv /bin/uv
ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=0
WORKDIR /app
# Dependencies first: this layer stays cached as long as uv.lock does not change.
COPY pyproject.toml uv.lock README.md ./
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --locked --no-dev --no-install-project --extra demo --extra redis --extra postgres
COPY sentinelapi ./sentinelapi
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --locked --no-dev --no-editable --extra demo --extra redis --extra postgres

FROM python:3.12.15-slim-bookworm AS runtime
RUN useradd --create-home --uid 10001 sentinel
WORKDIR /app
COPY --from=build --chown=sentinel:sentinel /app/.venv /app/.venv
COPY --chown=sentinel:sentinel examples ./examples
RUN chown sentinel:sentinel /app
ENV PATH="/app/.venv/bin:$PATH" \
    PYTHONUNBUFFERED=1
USER sentinel
EXPOSE 8000
# No curl in a slim image: the standard library asks /health.
HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=2)"]
CMD ["uvicorn", "examples.demo_app.main:app", "--host", "0.0.0.0", "--port", "8000"]
