#!/bin/sh
# Fix data directory permissions — runs as root, then drops to castaway user.
# This handles volume mounts where host directory has root-owned files.

set -e

# Ensure data dirs exist
mkdir -p /data /data/screenshots

# Fix ownership (best effort — may fail in unprivileged LXC but that's fine
# if permissions are already open enough)
chown -R castaway:castaway /data 2>/dev/null || true

# Make sure castaway can read/write (fallback for unprivileged LXC)
chmod -R u+rwX,g+rwX /data 2>/dev/null || true
# Secret key: keep restrictive but readable by castaway
[ -f /data/.secret_key ] && chmod 640 /data/.secret_key 2>/dev/null || true

# Drop to castaway user
exec gosu castaway "$@"
