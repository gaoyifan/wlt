default:
    docker build . -t ghcr.io/gaoyifan/wlt:latest --network=host
    docker compose up -d --wait
    sleep 10
    curl 100.64.110.254
