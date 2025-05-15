FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && apt-get install -y nftables && rm -rf /var/lib/apt/lists/*

COPY requirements.txt ./
RUN PYTHONDONTWRITEBYTECODE=1 pip install --no-cache-dir -r requirements.txt

COPY main.py ./
COPY templates/ ./templates/

ENV WLT_HOST=0.0.0.0
ENV WLT_PORT=80
ENV FLASK_APP=main.py

EXPOSE 80

CMD ["python", "main.py"] 