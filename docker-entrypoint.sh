#!/bin/sh
# Run mcpsonar as an unprivileged user (uid 10001).
#
# Started as root (the default), this script only makes sure the data volume belongs to
# that user, so volumes created by older images (root-owned) keep working, then drops all
# privileges before exec'ing mcpsonar. Started with `--user`, it just execs.
set -eu

if [ "$(id -u)" = "0" ]; then
    mkdir -p /data
    chown -R 10001:10001 /data
    exec setpriv --reuid=10001 --regid=10001 --clear-groups --inh-caps=-all \
        --no-new-privs mcpsonar "$@"
fi
exec mcpsonar "$@"
