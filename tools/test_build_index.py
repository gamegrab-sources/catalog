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
            "key": {"formatVersion": 1, "algorithm": "droidtop-chain-v1", "origin": "acme",
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
    check(build_index.check_static(config) == [], "README.md carries the disclaimer")

    good = sample(config)
    check(build_index.check_document(good, config) == [], "a well-formed index passes")

    retiring = dict(config, retired={"acme.tool": "merged into acme.suite"})
    check(build_index.retired_listed(good, retiring) != [], "a retired plugin in a rebuilt index is refused")
    check(build_index.retired_listed(good, config) == [], "nothing else counts as retired")

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

    check(build_index.stream_of({"tag_name": "plugin-v1.5.0", "prerelease": False}) == "stable", "a release is stable")
    for tag in ("plugin-unstable", "plugin-build.42", "plugin-unstable-arm", "plugin-build-arm.7"):
        check(build_index.stream_of({"tag_name": tag, "prerelease": True}) == "unstable", tag + " is unstable")
    for tag in ("plugin-v1.6.0-beta.1", "plugin-builder", "plugin-unstabled"):
        check(build_index.stream_of({"tag_name": tag, "prerelease": True}) == "testing", tag + " is testing")
    for category in ("sources", "system", "appearance", "tools", "games"):
        check(build_index.category_of({"category": category}) == category, category + " is a known category")
    for manifest in ({}, {"category": "Sources"}, {"category": "misc"}, {"category": 3}):
        check(build_index.category_of(manifest) is None, repr(manifest) + " has no known category")
    known_category = copy.deepcopy(good)
    known_category["origins"][0]["plugins"][0].update(category="sync")
    known_category["origins"][0]["plugins"][0]["releases"][0]["stream"] = "unstable"
    check(build_index.check_document(known_category, config) == [], "unstable releases and a known category pass")
    unknown_category = copy.deepcopy(good)
    unknown_category["origins"][0]["plugins"][0].update(category="misc")
    check(build_index.check_document(unknown_category, config) != [], "an unknown category is refused by --check")

    named = copy.deepcopy(good)
    named["catalog"]["origin"] = config["catalog"]["origin"]
    check(build_index.check_document(named, config) != [], "an origin without its root key is refused")
    check(build_index.covers(["gamegrab.*"], "gamegrab.f95") and not build_index.covers(["gamegrab.*"], "gamegrab"), "a namespace covers ids under it, not itself")
    check(build_index.body(good) == build_index.body(dict(good, generatedAt="later")), "generatedAt alone is not a change")
    check(json.loads(build_index.dump(good)) == good, "the index round-trips")
    root = build_index.load_root(config)
    check(root[0] == "gamegrab" and root[2]["algorithm"] == "droidtop-chain-v1" and len(root[2]["keySha256"]) == 64, "the root key block is droidtop-chain-v1")
    if FAILURES:
        sys.exit("FAILED: " + "; ".join(FAILURES))
    print("all tests passed")


if __name__ == "__main__":
    main()
