FROM ghcr.io/astral-sh/uv:python3.12-alpine

WORKDIR /app

RUN apk add --no-cache nftables

COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project

COPY wlt/ ./wlt/
COPY templates/ ./templates/
RUN uv sync --frozen --no-dev

EXPOSE 80 2222

CMD ["uv", "run", "gunicorn", "-c", "python:wlt.web", "wlt.web:app"]
