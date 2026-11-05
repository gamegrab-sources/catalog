# Changelog

## 1.4.0 (2026-11-05)

- `catalog.json` `superseded`: roots this catalog used before. The index's root key blocks
  (`catalog.key` and each origin's `key`) carry `"superseded": [{"keySha256": <old>, "by":
  <current>}]`, so droidtop moves an origin approved under an old root to the current one
  (Droidtop/tracker#887). Listed: the root replaced in the 2026-11-04 rotation,
  824af8929c27b467e37916b6016966f0579498656c3d537809fcc99123dda77d, superseded by
  538218f14080fb907aa44d3d0c1657c46e91fda7dd390a0ea75a8e465e55676d.

## 1.3.0 (2026-10-14)

- `catalog.json` `retired`: plugin ids the index no longer lists, each with a note; a rebuilt
  index that still lists one is refused. Retired: the romgi-bio branch variants
  `bi0shacker001.romgi-3ds-decrypt`, `-macintosh-garden`, `-prowlarr-integration`, `-ps3-license`
  and `-self-hosted-db`, merged into `bi0shacker001.romgi-main` (romgi-bio). Their repository,
  releases and tags stay.

## 1.2.0 (2026-10-09)

- The index is signed: `index.json.sig` by the catalog key (sha256
  e4f40764ad89f15999f68aec61b766abe4ab65e63c1bc5283b5f0420d4a33abb) and `index.cert`
  (`gamegrab-sources/catalog#catalog0`), issued by the organisation's master, from the
  `CATALOG_SIGNING_KEY` and `CATALOG_SIGNING_CERT` secrets.
- `build_index.py --check-signature` verifies the signature as droidtop does (the master's
  signature on the certificate, the catalog id, the validity window, the index signature). The
  workflow runs it after signing, on the files it is about to publish.

## 1.1.0 (2026-10-08)

- The organisation's plugin master is published (`catalog-master-key.json`, origin `gamegrab`)
  and named in the index's `catalog` block (`key`, `origin`).
- Certified bundles: a bundle carrying `origin.cert` issued by the master is listed under origin
  `gamegrab` after its certificate and signature are checked. Independent bundles (a committed
  `droidtop-plugin-key.json`) are listed as before.
- `revocations.json` is droidtop's plugin revocation list signed by the master; the workflow signs
  only the index now.

## 1.0.0 (2026-10-08)

- The catalog: `index.json` in droidtop's plugin catalog format (schema 1) with the `catalog` and
  `disclaimer` blocks, built from every plugin repository of the gamegrab-sources organisation by
  `tools/build_index.py` and `.github/workflows/index.yml` (four times a day, on dispatch, and on a
  `plugin-published` repository dispatch).
- `revocations.json`, the catalog's revocation list.
- Signing with `CATALOG_SIGNING_KEY` and `CATALOG_SIGNING_CERT` (`tools/sign_index.sh`), ready for
  when the secrets exist; until then the index is published unsigned.
