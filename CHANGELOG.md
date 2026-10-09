# Changelog

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
