# gamegrab-sources catalog

An **unofficial** plugin catalog for [droidtop](https://github.com/Droidtop/droidtop). It lists every
droidtop plugin published in the [gamegrab-sources](https://github.com/gamegrab-sources)
organisation, in one index file that droidtop can read.

## Disclaimer

This catalog is unofficial. It is not part of droidtop, and the droidtop project does not make, review or endorse it or the plugins it lists. The plugins listed here may enable access to content from unofficial sources. The catalog and its plugins are provided as is, without warranty of any kind. The maintainers are not responsible for how unofficial plugins are used, or for any content reached through them. You are responsible for complying with the law where you live and with the terms of the sites and services involved. Takedown requests and other concerns: https://github.com/gamegrab-sources/catalog/issues

The same text is in the index (`disclaimer`), and droidtop shows it and asks you to accept it
before it lists anything from this catalog.

## Adding it to droidtop

Settings > Accounts and sources > Plugins > Catalogs > Add a catalog, then enter

    https://raw.githubusercontent.com/gamegrab-sources/catalog/main/index.json

(or `https://github.com/gamegrab-sources/catalog`). droidtop fetches the index, shows the catalog's
name, its disclaimer, its master key and the key of every origin it lists, and adds nothing until
you accept.
Plugins from it are marked **Unofficial** everywhere droidtop shows them, and each one still runs
only after you approve it.

## Takedown and contact

Open an issue: https://github.com/gamegrab-sources/catalog/issues. A plugin can be removed from the
index, and its certificate or key revoked (`revocations.json`), so droidtop stops it on every
device that has this catalog.

## What is listed

`tools/build_index.py` (run by `.github/workflows/index.yml` four times a day, on demand, and when a
plugin repository sends a `plugin-published` dispatch) reads every public, unarchived repository of
the organisation and lists each `*.droidplugin.tar.xz` release asset that is one of:

- **certified** (the organisation's own plugins): the bundle carries `origin.cert`, a plugin
  certificate issued by the organisation's plugin master (`catalog-master-key.json`, public) for
  the bundle's plugin id, its `manifest.sig` verifies against the certified key, and its origin is
  the organisation's, `gamegrab` (ids `gamegrab.<name>`). That origin is listed under the master's
  key. A repository gets its key and certificate with `plugin-key-provision official` run with the
  organisation's master seed (owner-run), which sets `PLUGIN_SIGNING_KEY` and `PLUGIN_SIGNING_CERT`
  on it;
- **independent**: the repository commits a `droidtop-plugin-key.json`
  (`{"origin": "<origin id>", "key": "<P-256 SubjectPublicKeyInfo, base64>"}`) at the root of its
  default branch, and the bundle's manifest is signed by that key under that origin (romgi's shape
  today, origin `bi0shacker001`).

A prerelease is listed in the `testing` stream, which droidtop does not offer; any other release
is `stable`. Anything else is left out, with the reason in the run's summary. Two repositories
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
  "key": {                                  // the organisation's plugin master
   "formatVersion": 1,
   "algorithm": "SHA256withECDSA",
   "publicKeySpki": "<the master's P-256 public key, base64>",
   "keySha256": "<hex SHA-256 of its DER>"
  }
 },
 "disclaimer": { "version": 1, "text": "<the text above>" },
 "origins": [
  {
   "origin": "<origin id>",
   "trust": "third-party",
   "key": { "formatVersion": 1, "algorithm": "SHA256withECDSA", "origin": "<origin id>",
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

## The master and the signature

The organisation's plugin master (`catalog-master-key.json`, public material only; origin
`gamegrab`, key sha256 `1076ed8549a37166568cc5d4c92914da3b286b6bef61ed3a757650d2e20fca3f`) is its
own, from a separate master seed: it is not derived from, or certified by, droidtop's plugin
master, and its plugins are never "Official" in droidtop. droidtop shows its fingerprint when you
add the catalog, trusts it from then on, verifies every certified bundle as bundle -> repository key
-> `origin.cert` -> this master, and refuses a later copy of the index that names another master.

When the repository secrets `CATALOG_SIGNING_KEY` (a PEM P-256 private key) and
`CATALOG_SIGNING_CERT` (its certificate) exist, the workflow also commits beside the index:

- `index.json.sig`: base64 DER ECDSA/SHA-256 over the exact bytes of `index.json`;
- `index.cert`: the catalog key's certificate in droidtop's catalog certificate format (the one
  droidtop-components uses), with `catalogs: ["gamegrab-sources/catalog"]`, issued by the master
  over

      droidtop-catalog-cert-v1
      id:<certId>
      catalogs:gamegrab-sources/catalog
      key:<publicKeySpki>
      notBefore:<epoch s>
      notAfter:<epoch s>

Once droidtop has seen a valid signature it refuses an unsigned copy. Without the secrets the index
is published unsigned.

## Revocation

`revocations.json` is droidtop's plugin revocation list, signed by the master
(`plugin-key-provision revoke --master-seed <the organisation's seed>`, owner-run):

```
{ "formatVersion": 1, "sequence": <raised on every change>, "certIds": ["gamegrab-sources/<repo>#<generation>"],
  "keySha256": ["<hex SHA-256 of a revoked key>"], "signature": "<base64, by the master>" }
```

droidtop fetches it with the index and keeps it only when the master signed it and its sequence is
higher than the one it has. It applies to this catalog's origins only: a revoked certificate or key
refuses installs and stops installed plugins at their next start. The committed file is a
placeholder (sequence 0, nothing listed, unsigned), which droidtop ignores.

## History

Changes to the tooling are in `CHANGELOG.md` and tagged as releases; every change to the index is a
commit on `main`.

## Licence

The tooling and documentation in this repository are GPL-3.0 licensed (`LICENSE`). Each listed plugin
has its own repository and licence.
