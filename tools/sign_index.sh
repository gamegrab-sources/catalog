#!/bin/bash
# Signs index.json and revocations.json (README.md, "Signature").
#   CATALOG_SIGNING_KEY   the catalog key, a PEM P-256 private key (repository secret)
#   CATALOG_SIGNING_CERT  its certificate, issued by the catalog master (repository secret)
# Writes <file>.sig (base64 DER ECDSA/SHA-256 over the exact file bytes) for both files and
# index.cert, and checks every signature against the key the certificate names before anything
# is committed. A file whose committed signature still verifies keeps it, so an unchanged file
# is not re-signed (ECDSA signatures differ on every run) and makes no commit.
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
import base64, json, sys
cert = json.load(open(sys.argv[1]))
catalog = json.load(open("catalog.json"))["catalog"]["id"]
assert cert.get("formatVersion") == 1 and catalog in cert.get("catalogs", []), "the certificate is not for " + catalog
master = json.load(open("catalog-master-key.json"))
assert cert["issuer"]["keySha256"].lower() == __import__("hashlib").sha256(base64.b64decode(master["publicKeySpki"])).hexdigest(), \
    "the certificate was not issued by the master in catalog-master-key.json"
open(sys.argv[2], "wb").write(base64.b64decode(cert["publicKeySpki"]))
PY
verify() {
  [ -f "$1.sig" ] || return 1
  base64 -d "$1.sig" > "$tmp/sig.der" 2>/dev/null || return 1
  openssl dgst -sha256 -verify "$tmp/pub.der" -keyform DER -signature "$tmp/sig.der" "$1" >/dev/null 2>&1
}
for file in index.json revocations.json; do
  if verify "$file"; then
    echo "$file: the committed signature still verifies"
  else
    openssl dgst -sha256 -sign "$tmp/key.pem" "$file" | base64 -w0 > "$file.sig"
    verify "$file" || { echo "$file: the new signature does not verify against the certified key" >&2; exit 1; }
    echo "$file: signed"
  fi
done
cmp -s "$tmp/index.cert" index.cert 2>/dev/null || cp "$tmp/index.cert" index.cert
