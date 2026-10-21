#!/usr/bin/env bash
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMAGE="${IMAGE:-php2shell-official:8.4.26-apache2.4.68}"
CONTAINER="${CONTAINER:-php2shell-official-target}"
PORT="${PORT:-8088}"

if [[ "${1:-start}" == "stop" ]]; then
    docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
    echo "[+] stopped $CONTAINER"
    exit 0
fi

if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    echo "[*] building $IMAGE"
    docker build --platform linux/amd64 -t "$IMAGE" "$HERE"
fi

docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
mkdir -p "$HERE/out"

echo "[*] starting http://127.0.0.1:${PORT}/index.php"
docker run -d \
    --name "$CONTAINER" \
    --platform linux/amd64 \
    -p "127.0.0.1:${PORT}:80" \
    -v "$HERE/out:/out" \
    --entrypoint /bin/sh \
    "$IMAGE" \
    -c 'mkdir -p /out && chown -R www-data:www-data /out && exec /opt/httpd-2.4.68/bin/httpd -DFOREGROUND -f /etc/httpd-php2shell.conf' \
    >/dev/null

for _ in $(seq 1 100); do
    if curl -fsS --max-time 2 "http://127.0.0.1:${PORT}/index.php" \
        >/dev/null 2>&1; then
        echo "[+] target ready"
        echo "    URL: http://127.0.0.1:${PORT}/index.php"
        exit 0
    fi
    sleep 0.1
done

echo "[-] target did not become ready" >&2
docker logs --tail 80 "$CONTAINER" >&2 || true
exit 1
