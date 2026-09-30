#!/bin/sh
set -eu

config_dir="${CONFIG_DIR:-/home/container/config}"
data_dir="${DATA_DIR:-/home/container/data}"
mkdir -p "$config_dir" "$data_dir"
for file in applications.yaml workspaces.yaml feeds.yaml owners.yaml smtp.yaml general.yaml; do
  if [ ! -f "$config_dir/$file" ]; then
    if [ -f "/home/container/$file" ]; then
      mv "/home/container/$file" "$config_dir/$file"
    else
      cp "/opt/watchtower/defaults/$file" "$config_dir/$file"
    fi
  fi
done

if [ -z "${STARTUP:-}" ] || [ "$STARTUP" = 'node /opt/watchtower/server.mjs' ] || [ "$STARTUP" = 'node /opt/watchtower/src/server.mjs' ]; then
  exec node /opt/watchtower/src/server.mjs
fi
exec /bin/sh -c "$STARTUP"
