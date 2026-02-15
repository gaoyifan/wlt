default: build up
    sleep 10
    curl 100.64.110.254

build:
    docker build . -t ghcr.io/gaoyifan/wlt:latest --network=host

up:
    docker compose --profile tls --profile ssh up -d --wait
