# Catalog format, signing and revocation

The technical reference for how this catalog is built, signed and revoked. For what the catalog is and how to add it, see the [README](../README.md).

## What is listed

`tools/build_index.py` (run by `.github/workflows/index.yml` four times a day, on demand, and when a
plugin repository sends a `plugin-published` dispatch) reads every public, unarchived repository of
the organisation and lists each `*.droidplugin.tar.xz` release asset whose `manifest.jws` verifies:
a detached ES256 JWS over the exact bytes of `manifest.json` (`typ` `droidtop-plugin+jws`), the
repository's leaf certificate in `x5c` (the root is not included), issued by the gamegrab root
(`gamegrab-root.pub`, public). The leaf names `urn:droidtop:origin:gamegrab` and, if it names
plugins, the manifest's id (`urn:droidtop:plugin:<id>`, `.*` covers a namespace). The manifest's
origin is `gamegrab` (ids `gamegrab.<name>`). A repository's key and leaf come from the owner's
provisioning and are the repository secrets `PLUGIN_SIGNING_KEY` and `PLUGIN_SIGNING_CERT`. Each
plugin repository also publishes `droidtop-plugin-key.json`, `{"origin": "gamegrab", "certificate":
"<the gamegrab root certificate>"}`, on its releases, which droidtop uses to anchor the origin.

A prerelease is listed in the `testing` stream, which droidtop does not offer; any other release
is `stable`. A plugin id named in `catalog.json` `retired` (id -> note saying why, e.g. a variant
merged into another plugin) is left out too, its note in the run's summary; its repository, releases
and tags stay. Anything else is left out, with the reason in the run's summary. Two repositories
cannot list the same origin with different keys, or the same plugin id.

## Index format

`index.json` is droidtop's plugin catalog index, schema version 1, the same format as
droidtop-platforms' `droidtop-plugins/index.json`, plus two blocks that droidtop reads from a
catalog that is not its own:

```
{
 "schemaVersion": 1,
 "generatedAt": "<ISO-8601 UTC, changes only when the content does>",
 "catalog": {
  "id": "gamegrab-sources/catalog",
  "name": "gamegrab-sources",
  "homepage": "https://github.com/gamegrab-sources/catalog",
  "trust": "unofficial",
  "origin": "gamegrab",                     // the organisation's own origin, beside its key
  "key": {                                  // the gamegrab root
   "formatVersion": 1,
   "algorithm": "droidtop-chain-v1",
   "publicKeySpki": "<the root's public key, base64>",
   "keySha256": "<hex SHA-256 of its DER>"
  }
 },
 "disclaimer": { "version": 1, "text": "<the text above>" },
 "origins": [
  {
   "origin": "<origin id>",
   "trust": "third-party",
   "key": { "formatVersion": 1, "algorithm": "droidtop-chain-v1", "origin": "<origin id>",
            "publicKeySpki": "<base64>", "keySha256": "<hex>" },
   "plugins": [
    {
     "id": "<origin>.<name>",
     "label": "<from the signed manifest>",
     "description": "<from the signed manifest, or null>",
     "releases": [
      {
       "version": "<the manifest's version>",
       "stream": "stable" | "testing",
       "publishedAt": "<ISO-8601 UTC>",
       "manifestSha256": "<hex SHA-256 of manifest.json>",
       "bundle": { "name": "<file>", "url": "<https>", "size": <bytes>, "sha256": "<hex>" }
      }
     ]
    }
   ]
  }
 ]
}
```

`catalog` and `disclaimer` are configured in `catalog.json`. Raising the disclaimer's `version`
makes droidtop ask every user to accept the new text before it lists anything again.

## The root and the signature

The gamegrab root (`gamegrab-root.pub`, public material only; origin `gamegrab`) is a third-party
anchor that people choose to trust when they add this catalog. It is not pinned by droidtop and its
plugins are never "Official". droidtop shows its fingerprint when you add the catalog, trusts it
from then on, verifies every bundle as `manifest.jws` -> leaf -> this root, and refuses a later copy
of the index that names another root. Expiry dates are not checked.

When the repository secrets `CATALOG_SIGNING_KEY` (a PEM P-256 private key) and
`CATALOG_SIGNING_CERT` (its leaf certificate, issued by the gamegrab root, naming
`urn:droidtop:catalog:gamegrab-sources/catalog`) exist, the workflow also commits `index.json.jws`
beside the index: a detached ES256 JWS (`typ` `droidtop-catalog+jws`, the leaf in `x5c`) over the
exact bytes of `index.json`, written by `tools/sign_jws.sh` and checked by
`build_index.py --check-signature` before it is committed. Once droidtop has seen a valid signature
it refuses an unsigned copy. Without the secrets the index is published unsigned.

## Revocation

A revocation list for this catalog would be published as `revocations.jws` beside the index, signed
with a leaf issued by the gamegrab root (EKU `.3`) naming `urn:droidtop:catalog:gamegrab-sources/catalog`.
Nothing is revoked, so none is published.
