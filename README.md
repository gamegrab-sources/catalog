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
name, its disclaimer and the key of every origin it lists, and adds nothing until you accept.
Plugins from it are marked **Unofficial** everywhere droidtop shows them, and each one still runs
only after you approve it.

## Takedown and contact

Open an issue: https://github.com/gamegrab-sources/catalog/issues. A plugin can be removed from the
index, and its signing key revoked (`revocations.json`), so droidtop stops it on every device that
has this catalog.

## What is listed

`tools/build_index.py` (run by `.github/workflows/index.yml` four times a day, on demand, and when a
plugin repository sends a `plugin-published` dispatch) lists:

- every public, unarchived repository of the organisation that commits a `droidtop-plugin-key.json`
  (`{"origin": "<origin id>", "key": "<P-256 SubjectPublicKeyInfo, base64>"}`) at the root of its
  default branch;
- from each of its releases, every `*.droidplugin.tar.xz` asset whose `manifest.json` is signed by
  that key (`manifest.sig`) and names that origin and an id under it (`<origin>.<name>`). A
  prerelease is listed in the `testing` stream, which droidtop does not offer; any other release is
  `stable`.

Anything else is left out, with the reason in the run's summary. Two repositories cannot list the
same origin with different keys, or the same plugin id.

To list a plugin, create its repository in the organisation, commit its `droidtop-plugin-key.json`
and publish releases that carry the signed bundle.

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
  "key": {                                  // only in a signed index
   "formatVersion": 1,
   "algorithm": "SHA256withECDSA",
   "publicKeySpki": "<the catalog master's P-256 public key, base64>",
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

## Signature

When the repository secrets `CATALOG_SIGNING_KEY` (a PEM P-256 private key) and
`CATALOG_SIGNING_CERT` (its certificate) exist, the workflow puts the catalog master's public key
(`catalog-master-key.json`, committed; public material only) in `catalog.key` and commits beside the
index:

- `index.json.sig` and `revocations.json.sig`: base64 DER ECDSA/SHA-256 over the exact file bytes;
- `index.cert`: the catalog key's certificate, in droidtop's catalog certificate format (the one
  droidtop-components uses), with `catalogs: ["gamegrab-sources/catalog"]`, issued by the catalog
  master over

      droidtop-catalog-cert-v1
      id:<certId>
      catalogs:gamegrab-sources/catalog
      key:<publicKeySpki>
      notBefore:<epoch s>
      notAfter:<epoch s>

The catalog master belongs to this organisation and is not derived from, or certified by,
droidtop's plugin master. droidtop trusts it on first use, when you accept the catalog, and from
then on refuses an index that is not signed under the same master. Without the secrets the index is
published unsigned and droidtop says so when you add it.

## Revocation

`revocations.json` (edited by hand, signed by the workflow when the secrets exist):

```
{ "formatVersion": 1, "sequence": <whole number, raised on every change>, "keySha256": ["<hex SHA-256 of a revoked origin key>"] }
```

droidtop fetches it with the index and keeps a list only when its sequence is higher than the one it
has. A revoked key stops verifying for the plugins droidtop trusted through this catalog: they stop
running and are not updated.

## History

Changes to the tooling are in `CHANGELOG.md` and tagged as releases; every change to the index is a
commit on `main`.

## Licence

The tooling and documentation in this repository are MIT licensed (`LICENSE`). Each listed plugin
has its own repository and licence.
