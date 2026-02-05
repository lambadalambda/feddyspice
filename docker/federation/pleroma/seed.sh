#!/bin/sh
set -eu

for username in bob dave; do
  if wget -qO- "http://pleroma_web:4000/.well-known/webfinger?resource=acct:${username}@pleroma.fedbox.dev" >/dev/null; then
    echo "[fedbox] pleroma: ${username} already exists"
  fi
done

app="$(
  wget -qO- \
    --post-data "client_name=fedbox&redirect_uris=urn:ietf:wg:oauth:2.0:oob&scopes=read+write+follow&website=" \
    "http://pleroma_web:4000/api/v1/apps"
)"
client_id="$(echo "$app" | sed -n 's/.*"client_id":"\([^"]*\)".*/\1/p')"
client_secret="$(echo "$app" | sed -n 's/.*"client_secret":"\([^"]*\)".*/\1/p')"

token="$(
  wget -qO- \
    --post-data "client_id=${client_id}&client_secret=${client_secret}&grant_type=client_credentials&scope=read+write+follow" \
    "http://pleroma_web:4000/oauth/token"
)"
access_token="$(echo "$token" | sed -n 's/.*"access_token":"\([^"]*\)".*/\1/p')"

for username in bob dave; do
  if wget -qO- "http://pleroma_web:4000/.well-known/webfinger?resource=acct:${username}@pleroma.fedbox.dev" >/dev/null; then
    echo "[fedbox] pleroma: ${username} already exists"
    continue
  fi

  wget -qO- \
    --header "Authorization: Bearer ${access_token}" \
    --header "Content-Type: application/json" \
    --post-data "{\"username\":\"${username}\",\"email\":\"${username}@pleroma.fedbox.dev\",\"password\":\"password\",\"agreement\":true,\"locale\":\"en\"}" \
    "http://pleroma_web:4000/api/v1/accounts" >/dev/null || true

  tries=0
  until wget -qO- "http://pleroma_web:4000/.well-known/webfinger?resource=acct:${username}@pleroma.fedbox.dev" >/dev/null; do
    tries=$((tries + 1))

    if [ "$tries" -ge 30 ]; then
      echo "[fedbox] pleroma: timeout waiting for webfinger ${username}" >&2
      exit 1
    fi

    sleep 1
  done
done
