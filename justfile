default: pull up
    sleep 2
    curl -s http://198.18.255.254/api/status | head -c 200; echo

# Images are built by GitHub Actions (native amd64/arm64 runners); deploy pulls
# from ghcr instead of building locally.
pull:
    docker compose pull

build:
    docker build . -t ghcr.io/gaoyifan/wlt:latest --network=host

up:
    docker compose up -d --wait --force-recreate --remove-orphans

test:
    cargo test
