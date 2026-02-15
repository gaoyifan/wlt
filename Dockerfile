FROM ghcr.io/astral-sh/uv:python3.12-alpine

WORKDIR /app

RUN apk add --no-cache nftables

COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project

COPY main.py ssh_server.py ./
COPY templates/ ./templates/

EXPOSE 80 2222

CMD ["uv", "run", "gunicorn", "-c", "python:main", "main:app"]
