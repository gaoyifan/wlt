FROM ghcr.io/astral-sh/uv:python3.12-alpine

WORKDIR /app

RUN apk add --no-cache nftables

COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project

COPY main.py ./
COPY templates/ ./templates/

EXPOSE 80

CMD ["uv", "run", "gunicorn", "-b", "0.0.0.0:80", "main:app"]
