# Changelog

## 1.0.0 (2026-10-08)

- The catalog: `index.json` in droidtop's plugin catalog format (schema 1) with the `catalog` and
  `disclaimer` blocks, built from every plugin repository of the gamegrab-sources organisation by
  `tools/build_index.py` and `.github/workflows/index.yml` (four times a day, on dispatch, and on a
  `plugin-published` repository dispatch).
- `revocations.json`, the catalog's revocation list.
- Signing with `CATALOG_SIGNING_KEY` and `CATALOG_SIGNING_CERT` (`tools/sign_index.sh`), ready for
  when the secrets exist; until then the index is published unsigned.
