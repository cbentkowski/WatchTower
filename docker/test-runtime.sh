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
assert.equal(process.env.CONFIG_DIR, "/opt/watchtower/data/config");
assert.equal(process.env.DATA_DIR, "/opt/watchtower/data/state");
assert.equal(process.cwd(), "/opt/watchtower");
for (const path of ["/bin/sh", "/bin/bash", "/usr/bin/apt", "/sbin/apk", "/usr/local/bin/npm", "/usr/local/bin/yarn"]) assert.equal(fs.existsSync(path), false, path);
'
docker volume create "$volume" >/dev/null
# Legacy configuration and persistent state must survive initialization.
docker run --rm --mount "type=volume,src=$volume,dst=/opt/watchtower/data" --entrypoint /nodejs/bin/node "$image" -e '
const fs = require("node:fs");
fs.copyFileSync("/opt/watchtower/defaults/general.yaml", "/opt/watchtower/data/general.yaml");
fs.mkdirSync("/opt/watchtower/data/state", {recursive:true});
fs.writeFileSync("/opt/watchtower/data/state/runtime-marker", "persisted");
'
start() {
  docker run -d --name "$1" --read-only --cap-drop ALL --security-opt no-new-privileges \
    --mount "type=volume,src=$volume,dst=/opt/watchtower/data" \
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
assert.equal(fs.existsSync("/opt/watchtower/data/general.yaml"), false);
for (const name of ["general.yaml", "applications.yaml"]) assert.equal(fs.existsSync("/opt/watchtower/data/config/"+name), true);
assert.equal(fs.readFileSync("/opt/watchtower/data/state/runtime-marker", "utf8"), "persisted");
'
# Docker uses image SIGINT; Kubernetes normally sends SIGTERM.
docker stop --time 5 "$http" >/dev/null
[[ $(docker inspect --format '{{.State.ExitCode}}' "$http") == 130 ]]
docker start "$http" >/dev/null
healthy "$http"
docker exec "$http" /nodejs/bin/node -e 'require("node:assert/strict").equal(require("node:fs").readFileSync("/opt/watchtower/data/state/runtime-marker","utf8"),"persisted")'
docker kill --signal TERM "$http" >/dev/null
for _ in {1..5}; do
  [[ $(docker inspect --format '{{.State.Running}}' "$http") == false ]] && break
  sleep 1
done
[[ $(docker inspect --format '{{.State.Running}}' "$http") == false ]]
[[ $(docker inspect --format '{{.State.ExitCode}}' "$http") == 143 ]]
# Reuse the previous config/data volume layout through the documented override.
docker rm "$http" >/dev/null
docker run --rm --mount "type=volume,src=$volume,dst=/opt/watchtower/data" --entrypoint /nodejs/bin/node "$image" -e 'require("node:fs").renameSync("/opt/watchtower/data/state", "/opt/watchtower/data/data")'
start "$http" -e DATA_DIR=/opt/watchtower/data/data
healthy "$http"
docker exec "$http" /nodejs/bin/node -e '
const assert = require("node:assert/strict"), fs = require("node:fs");
assert.equal(fs.readFileSync(process.env.DATA_DIR+"/runtime-marker", "utf8"), "persisted");
assert.equal(fs.existsSync("/opt/watchtower/data/state"), false);
assert.equal(fs.existsSync("/opt/watchtower/data/config/general.yaml"), true);
'
docker stop --time 5 "$http" >/dev/null
docker rm "$http" >/dev/null
# Also validate the documented offline rename back to the default state layout.
docker run --rm --mount "type=volume,src=$volume,dst=/opt/watchtower/data" --entrypoint /nodejs/bin/node "$image" -e 'require("node:fs").renameSync("/opt/watchtower/data/data", "/opt/watchtower/data/state")'
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
