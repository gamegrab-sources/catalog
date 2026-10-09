#!/usr/bin/env python3
"""Tests for build_index.py that need no network and no keys: the shape checks and the config."""

import copy
import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import build_index  # noqa: E402

FAILURES = []


def check(condition, what):
    print(("  ok  " if condition else "  FAIL ") + what)
    if not condition:
        FAILURES.append(what)


def sample(config):
    return {
        "schemaVersion": 1,
        "generatedAt": "2026-10-08T00:00:00Z",
        "catalog": {k: v for k, v in config["catalog"].items() if k != "origin"},
        "disclaimer": dict(config["disclaimer"]),
        "origins": [{
            "origin": "acme",
            "trust": "third-party",
            "key": {"formatVersion": 1, "algorithm": "SHA256withECDSA", "origin": "acme",
                    "publicKeySpki": "AAAA", "keySha256": "a" * 64},
            "plugins": [{
                "id": "acme.tool",
                "label": "Tool",
                "description": None,
                "releases": [{
                    "version": "1.0.0",
                    "stream": "stable",
                    "publishedAt": "2026-10-08T00:00:00Z",
                    "manifestSha256": "b" * 64,
                    "bundle": {"name": "acme.tool.droidplugin.tar.xz", "url": "https://example.invalid/b", "size": 1, "sha256": "c" * 64},
                }],
            }],
        }],
    }


def main():
    config = build_index.load_config()
    check(config["catalog"]["trust"] == "unofficial", "the catalog says it is unofficial")
    check(build_index.check_static(config) == [], "README.md carries the disclaimer and revocations.json is well formed")

    good = sample(config)
    check(build_index.check_document(good, config) == [], "a well-formed index passes")

    for what, change in [
        ("an official origin is refused", lambda d: d["origins"][0].update(origin="droidtop")),
        ("a plugin outside its origin is refused", lambda d: d["origins"][0]["plugins"][0].update(id="other.tool")),
        ("a plain http bundle is refused", lambda d: d["origins"][0]["plugins"][0]["releases"][0]["bundle"].update(url="http://x")),
        ("a changed disclaimer is refused", lambda d: d["disclaimer"].update(text="nothing")),
        ("another schema version is refused", lambda d: d.update(schemaVersion=2)),
        ("a key block for another origin is refused", lambda d: d["origins"][0]["key"].update(origin="other")),
    ]:
        bad = copy.deepcopy(good)
        change(bad)
        check(build_index.check_document(bad, config) != [], what)

    named = copy.deepcopy(good)
    named["catalog"]["origin"] = config["catalog"]["origin"]
    check(build_index.check_document(named, config) != [], "an origin without its master key is refused")
    check(build_index.covers(["gamegrab.*"], "gamegrab.f95") and not build_index.covers(["gamegrab.*"], "gamegrab"), "a namespace covers ids under it, not itself")
    check(build_index.cert_signed_bytes("a/b#0", ["gamegrab.f95"], "SPKI", 1, 2)
          == b"droidtop-plugin-cert-v1\nid:a/b#0\nplugins:gamegrab.f95\nkey:SPKI\nnotBefore:1\nnotAfter:2\n", "certificate bytes match droidtop's")
    check(build_index.revocations_signed_bytes(3, ["b#1", "a#0"], ["AB" * 32])
          == ("droidtop-plugin-revocations-v1\nsequence:3\ncert:a#0\ncert:b#1\nkey:" + "ab" * 32 + "\n").encode(), "revocation bytes match droidtop's")
    check(build_index.catalog_cert_signed_bytes("o/c#0", ["o/c"], "SPKI", 1, 2)
          == b"droidtop-catalog-cert-v1\nid:o/c#0\ncatalogs:o/c\nkey:SPKI\nnotBefore:1\nnotAfter:2\n", "catalog certificate bytes match droidtop's")
    check(build_index.body(good) == build_index.body(dict(good, generatedAt="later")), "generatedAt alone is not a change")
    check(json.loads(build_index.dump(good)) == good, "the index round-trips")
    try:
        build_index.published_key(json.dumps({"origin": "droidtop", "key": "AAAA"}), "x/y")
        check(False, "a repository may not claim the official origin")
    except build_index.Rejected:
        check(True, "a repository may not claim the official origin")
    if FAILURES:
        sys.exit("FAILED: " + "; ".join(FAILURES))
    print("all tests passed")


if __name__ == "__main__":
    main()
