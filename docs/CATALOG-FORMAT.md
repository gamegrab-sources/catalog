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

Each release is listed in a channel, its `stream` (Droidtop/tracker#179; the owner, 2026-10-16: "Yeah,
plugins are channeled, too. They should also have categories"; droidtop SPEC 12a "Channels"): a
release that is not a pre-release is `stable`; a pre-release whose tag is `plugin-unstable*` or
`plugin-build*` (the per-push builds of `droidtop-plugin-bundle.yml`) is `unstable`; any other
pre-release is `testing`. droidtop offers a channel's own line and every steadier one, `stable` by
default. The index keeps the newest 5 stable, 3 testing and 3 unstable releases per plugin, so a busy
branch cannot push the newest stable release off the list.

Each plugin carries a `category`, taken from its newest release's signed manifest. It is one of
`sources`, `emulators`, `system`, `sync`, `integrations`, `appearance` or `other` (droidtop plugin-api.md
1.2 "Categories"), or one of the four 2026-10-15 ids droidtop reads as their successors: `tools`
(system), `themes` (appearance), `social` (integrations), `games` (sources). An unknown value is a
warning in the run and the plugin is listed without a category, which droidtop reads as `other`;
`build_index.py --check` refuses an unknown category in the committed index. The catalog's site shows each
plugin's category and the channel of each release. This mirrors droidtop-platforms
`generator/droidtop_plugins_index.py` (commit c1f41b0).

A plugin id named in `catalog.json` `retired` (id -> note saying why, e.g. a variant
merged into another plugin) is left out too, its note in the run's summary; its repository, releases
and tags stay. Anything else is left out, with the reason in the run's summary. Two repositories
cannot list the same origin with different keys, or the same plugin id.

## The dispatch each plugin repository sends

droidtop reads this catalog's `index.json`, so a release is offered only once the index lists it. The
index workflow rebuilds on `repository_dispatch` of type `plugin-published` as well as on its schedule,
so each plugin repository sends one after publishing a release, as a step placed after its release step
and under that step's own condition (`<the release step's own condition>` below):

```yaml
      - name: Ask the gamegrab-sources catalog to reindex
        if: <the release step's own condition>
        env:
          GH_TOKEN: ${{ secrets.CATALOG_DISPATCH_TOKEN }}
          GH_REPO: ${{ github.repository }}
        run: |
          set -euo pipefail
          if [ -z "${GH_TOKEN:-}" ]; then
            echo "No CATALOG_DISPATCH_TOKEN; the catalog lists this release on its schedule."
            exit 0
          fi
          gh api repos/gamegrab-sources/catalog/dispatches \
            -f event_type=plugin-published \
            -f "client_payload[repo]=$GH_REPO"
```

A dispatch to another repository needs a token of its own, as the job's `GITHUB_TOKEN` cannot reach it.
That token is the organisation secret `CATALOG_DISPATCH_TOKEN`: a fine-grained token with
`contents: write` on `gamegrab-sources/catalog` only, available to the plugin repositories. While the
secret is unset the step is a no-op and the scheduled run lists the release within hours.

A dispatch only asks for a run. The index still holds only what the generator verifies, whoever sent it.

Decision (coordinator, 2026-10-16): "Add the same step after their release step, as a no-op when the
token is unset."

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
     "category": "<from the newest release signed manifest; omitted when absent or unknown>",
     "releases": [
      {
       "version": "<the manifest's version>",
       "stream": "stable" | "testing" | "unstable",
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
