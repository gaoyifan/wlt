FROM ghcr.io/astral-sh/uv:python3.12-trixie-slim

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends nftables \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project

COPY main.py ./
COPY templates/ ./templates/

EXPOSE 80

CMD ["uv", "run", "gunicorn", "-b", "0.0.0.0:80", "main:app"]