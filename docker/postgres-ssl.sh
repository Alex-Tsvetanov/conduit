#!/bin/bash
# Copies the test certificate to a path the postgres user can read, then
# starts the image's own entrypoint with ssl=on. Plaintext connections still
# work: ssl is offered, not required, so the existing integration cases are
# unchanged.
set -euo pipefail
cp /certs/server.crt /tmp/pg-server.crt
cp /certs/server.key /tmp/pg-server.key
chown postgres:postgres /tmp/pg-server.crt /tmp/pg-server.key
chmod 644 /tmp/pg-server.crt
chmod 600 /tmp/pg-server.key
exec docker-entrypoint.sh postgres \
  -c ssl=on \
  -c ssl_cert_file=/tmp/pg-server.crt \
  -c ssl_key_file=/tmp/pg-server.key
