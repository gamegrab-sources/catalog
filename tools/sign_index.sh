#!/bin/bash
# Signs index.json (README.md, "Signature").
#   CATALOG_SIGNING_KEY   the catalog key, a PEM P-256 private key (repository secret)
#   CATALOG_SIGNING_CERT  its certificate (droidtop-catalog-cert-v1), issued by the organisation's
#                         plugin master in catalog-master-key.json (repository secret)
# Writes index.json.sig (base64 DER ECDSA/SHA-256 over the exact file bytes) and index.cert, and
# checks the signature against the key the certificate names before anything is committed. An
# index whose committed signature still verifies keeps it, so an unchanged index is not re-signed
# (ECDSA signatures differ on every run) and makes no commit. The revocation list is not signed
# here: the master signs it (plugin-key-provision revoke).
# The private key only ever exists in a 0600 file under RUNNER_TEMP.
set -eu
cd "$(dirname "$0")/.."
: "${CATALOG_SIGNING_KEY:?}" "${CATALOG_SIGNING_CERT:?}"
tmp=$(mktemp -d "${RUNNER_TEMP:-/tmp}/catalog-sign.XXXXXX")
trap 'rm -rf -- "${tmp:?}"' EXIT
umask 077
printf '%s\n' "$CATALOG_SIGNING_KEY" > "$tmp/key.pem"
printf '%s\n' "$CATALOG_SIGNING_CERT" > "$tmp/index.cert"
python3 - "$tmp/index.cert" "$tmp/pub.der" <<'PY'
import base64, hashlib, json, sys
cert = json.load(open(sys.argv[1]))
catalog = json.load(open("catalog.json"))["catalog"]["id"]
assert cert.get("formatVersion") == 1 and catalog in cert.get("catalogs", []), "the certificate is not for " + catalog
master = json.load(open("catalog-master-key.json"))
assert cert["issuer"]["keySha256"].lower() == hashlib.sha256(base64.b64decode(master["publicKeySpki"])).hexdigest(), \
    "the certificate was not issued by the master in catalog-master-key.json"
open(sys.argv[2], "wb").write(base64.b64decode(cert["publicKeySpki"]))
PY
verify() {
  [ -f index.json.sig ] || return 1
  base64 -d index.json.sig > "$tmp/sig.der" 2>/dev/null || return 1
  openssl dgst -sha256 -verify "$tmp/pub.der" -keyform DER -signature "$tmp/sig.der" index.json >/dev/null 2>&1
}
if verify; then
  echo "index.json: the committed signature still verifies"
else
  openssl dgst -sha256 -sign "$tmp/key.pem" index.json | base64 -w0 > index.json.sig
  verify || { echo "index.json: the new signature does not verify against the certified key" >&2; exit 1; }
  echo "index.json: signed"
fi
cmp -s "$tmp/index.cert" index.cert 2>/dev/null || cp "$tmp/index.cert" index.cert
