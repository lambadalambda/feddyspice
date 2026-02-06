#!/bin/sh
set -eu

if wget -qO- "http://feddyspice_web:8080/.well-known/webfinger?resource=acct:alice@feddyspice.fedbox.dev" >/dev/null; then
  echo "[fedbox] feddyspice: alice already exists"
  exit 0
fi

wget -q -S -O /tmp/feddy_signup.html \
  "http://feddyspice_web:8080/signup" 2>/tmp/feddy_signup.headers || true

csrf_cookie="$(sed -n 's/^[[:space:]]*[Ss]et-[Cc]ookie:[[:space:]]*[Ff]eddyspice_csrf=\([^;]*\).*/\1/p' /tmp/feddy_signup.headers | tail -n1)"
csrf_token="$(sed -n 's/.*name="csrf" value="\([^"]*\)".*/\1/p' /tmp/feddy_signup.html | head -n1)"

if [ -n "${csrf_cookie}" ] && [ -n "${csrf_token}" ]; then
  wget -qO- \
    --header "Cookie: feddyspice_csrf=${csrf_cookie}" \
    --post-data "username=alice&password=password&csrf=${csrf_token}" \
    "http://feddyspice_web:8080/signup" >/dev/null || true
else
  echo "[fedbox] feddyspice: missing csrf cookie/token from signup page" >&2
fi

tries=0
until wget -qO- "http://feddyspice_web:8080/.well-known/webfinger?resource=acct:alice@feddyspice.fedbox.dev" >/dev/null; do
  tries=$((tries + 1))

  if [ "$tries" -ge 30 ]; then
    echo "[fedbox] feddyspice: timeout waiting for webfinger alice" >&2
    exit 1
  fi

  sleep 1
done
