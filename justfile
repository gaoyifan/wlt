default: build up
    sleep 10
    curl -s http://198.18.255.254/api/status | head -c 200; echo

build:
    docker build . -t ghcr.io/gaoyifan/wlt:latest --network=host

up:
    docker compose --profile tls --profile ssh up -d --wait --force-recreate
