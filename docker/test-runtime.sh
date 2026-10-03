#!/usr/bin/env bash
set -euo pipefail
image=${1:-watchtower:security-scan}
prefix="watchtower-runtime-$$"
volume="$prefix-data"
http="$prefix-http"
https="$prefix-https"
tls=$(mktemp -d)
cleanup() {
  docker rm -f "$http" "$https" >/dev/null 2>&1 || true
  docker volume rm "$volume" >/dev/null 2>&1 || true
  rm -rf "$tls"
}
trap cleanup EXIT
docker run --rm --entrypoint /nodejs/bin/node "$image" -e '
const assert = require("node:assert/strict"), fs = require("node:fs");
assert.equal(process.getuid(), 1000); assert.equal(process.getgid(), 1000);
assert.match(process.version, /^v22\./);
for (const path of ["/bin/sh", "/bin/bash", "/usr/bin/apt", "/sbin/apk", "/usr/local/bin/npm", "/usr/local/bin/yarn"]) assert.equal(fs.existsSync(path), false, path);
'
docker volume create "$volume" >/dev/null
# Legacy configuration and persistent state must survive initialization.
docker run --rm --mount "type=volume,src=$volume,dst=/home/container" --entrypoint /nodejs/bin/node "$image" -e '
const fs = require("node:fs");
fs.copyFileSync("/opt/watchtower/defaults/general.yaml", "/home/container/general.yaml");
fs.mkdirSync("/home/container/data", {recursive:true});
fs.writeFileSync("/home/container/data/runtime-marker", "persisted");
'
start() {
  docker run -d --name "$1" --read-only --cap-drop ALL --security-opt no-new-privileges \
    --mount "type=volume,src=$volume,dst=/home/container" \
    -e AUTH_DISABLED=true -e AUTO_SCAN=false "${@:2}" "$image" >/dev/null
}
healthy() {
  for _ in {1..45}; do
    [[ $(docker inspect --format '{{.State.Health.Status}}' "$1") == healthy ]] && return
    [[ $(docker inspect --format '{{.State.Running}}' "$1") != true ]] && break
    sleep 1
  done
  docker logs "$1"
  return 1
}
start "$http"
healthy "$http"
docker exec "$http" /nodejs/bin/node -e '
const assert = require("node:assert/strict"), fs = require("node:fs");
assert.equal(fs.existsSync("/home/container/general.yaml"), false);
for (const name of ["general.yaml", "applications.yaml"]) assert.equal(fs.existsSync("/home/container/config/"+name), true);
assert.equal(fs.readFileSync("/home/container/data/runtime-marker", "utf8"), "persisted");
'
# Docker uses image SIGINT; Kubernetes normally sends SIGTERM.
docker stop --time 5 "$http" >/dev/null
[[ $(docker inspect --format '{{.State.ExitCode}}' "$http") == 130 ]]
docker start "$http" >/dev/null
healthy "$http"
docker exec "$http" /nodejs/bin/node -e 'require("node:assert/strict").equal(require("node:fs").readFileSync("/home/container/data/runtime-marker","utf8"),"persisted")'
docker kill --signal TERM "$http" >/dev/null
for _ in {1..5}; do
  [[ $(docker inspect --format '{{.State.Running}}' "$http") == false ]] && break
  sleep 1
done
[[ $(docker inspect --format '{{.State.Running}}' "$http") == false ]]
[[ $(docker inspect --format '{{.State.ExitCode}}' "$http") == 143 ]]
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$tls/key.pem" -out "$tls/cert.pem" \
  -days 1 -subj /CN=localhost >/dev/null 2>&1
# Disposable test key only; production keys need restricted ownership.
chmod 755 "$tls"
chmod 644 "$tls/key.pem" "$tls/cert.pem"
start "$https" --mount "type=bind,src=$tls,dst=/run/tls,readonly" \
  -e TLS_ENABLED=true -e TLS_CERT_FILE=/run/tls/cert.pem -e TLS_KEY_FILE=/run/tls/key.pem
healthy "$https"
docker exec "$https" /nodejs/bin/node -e 'require("node:https").get({host:"127.0.0.1",port:4173,path:"/healthz",rejectUnauthorized:false},r=>process.exit(r.statusCode===200?0:1)).on("error",()=>process.exit(1))'
echo 'Runtime checks passed: shell-free non-root image, restricted HTTP/HTTPS, migration, persistence, SIGINT and SIGTERM.'
