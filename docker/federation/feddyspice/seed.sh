#!/bin/sh
set -eu

if wget -qO- "http://feddyspice_web:8080/.well-known/webfinger?resource=acct:alice@feddyspice.fedbox.dev" >/dev/null; then
  echo "[fedbox] feddyspice: alice already exists"
  exit 0
fi

wget -qO- \
  --post-data "username=alice&password=password" \
  "http://feddyspice_web:8080/signup" >/dev/null || true

tries=0
until wget -qO- "http://feddyspice_web:8080/.well-known/webfinger?resource=acct:alice@feddyspice.fedbox.dev" >/dev/null; do
  tries=$((tries + 1))

  if [ "$tries" -ge 30 ]; then
    echo "[fedbox] feddyspice: timeout waiting for webfinger alice" >&2
    exit 1
  fi

  sleep 1
done
