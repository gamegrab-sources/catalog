#!/bin/bash
# Signs a file with a detached JWS for droidtop (docs in tools/sign_jws.py).
#   sign_jws.sh <typ> <content file> <out .jws>
# Needs PLUGIN_SIGNING_KEY / PLUGIN_SIGNING_CERT (typ droidtop-plugin+jws) or
# CATALOG_SIGNING_KEY / CATALOG_SIGNING_CERT (typ droidtop-catalog+jws) in the environment.
# Private key only ever exists in a 0600 file that is removed on exit.
set -eu
typ=${1:?usage: sign_jws.sh <typ> <content> <out>}
content=${2:?}
out=${3:?}
case "$typ" in
  droidtop-plugin+jws) key=${PLUGIN_SIGNING_KEY:?}; cert=${PLUGIN_SIGNING_CERT:?} ;;
  droidtop-catalog+jws) key=${CATALOG_SIGNING_KEY:?}; cert=${CATALOG_SIGNING_CERT:?} ;;
  *) echo "unknown typ $typ" >&2; exit 2 ;;
esac
here=$(cd "$(dirname "$0")" && pwd)
umask 077
tmp=$(mktemp -d "${RUNNER_TEMP:-/tmp}/jws-sign.XXXXXX")
trap 'rm -f -- "${tmp:?}/key.pem" "${tmp:?}/cert.pem"; rmdir -- "${tmp:?}"' EXIT
printf '%s\n' "$key" > "$tmp/key.pem"
printf '%s\n' "$cert" > "$tmp/cert.pem"
python3 "$here/sign_jws.py" "$typ" "$content" "$tmp/key.pem" "$tmp/cert.pem" > "$out"
