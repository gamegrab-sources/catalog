#!/usr/bin/env python3
"""Offline tests of build_site.py: the registry reader, the bundle reader, the page."""
import datetime
import hashlib
import io
import json
import os
import sys
import tarfile
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import build_site as b  # noqa: E402

KOTLIN = "".join(
    f'    PluginPermission("p.n{i}", PermissionTier.NORMAL, "Label {i}"),\n' for i in range(40)
) + '''
    PluginPermission("net.domains", PermissionTier.NORMAL, "Connect to: listed domains"),
    PluginPermission("net.any", PermissionTier.DANGEROUS, "Connect to any site on the internet", android = AndroidNeed("android.permission.INTERNET")),
    PluginPermission(
        "gpu.render", PermissionTier.DANGEROUS, "Use the graphics chip to draw its screen",
        caution = "Only allow it for a plugin from a source you trust",
    ),
    PluginPermission("host.full_trust", PermissionTier.CRITICAL, "Run with droidtop's full access"),
'''


def bundle_with(manifest: dict) -> bytes:
    raw = json.dumps(manifest).encode()
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode="w:xz") as tar:
        info = tarfile.TarInfo("manifest.json")
        info.size = len(raw)
        tar.addfile(info, io.BytesIO(raw))
    return out.getvalue(), raw


class Registry(unittest.TestCase):
    def test_reads_rows_cautions_and_android_names(self):
        registry = b.parse_registry(KOTLIN)
        self.assertEqual(registry["net.any"]["tier"], "DANGEROUS")
        self.assertEqual(registry["net.any"]["android"], "android.permission.INTERNET")
        self.assertEqual(registry["gpu.render"]["caution"], "Only allow it for a plugin from a source you trust")
        self.assertIsNone(registry["net.domains"]["caution"])
        self.assertEqual(registry["host.full_trust"]["tier"], "CRITICAL")

    def test_a_changed_format_is_an_error_not_an_empty_page(self):
        with self.assertRaises(ValueError):
            b.parse_registry('PluginPermission("a", PermissionTier.NORMAL, "A")')


class Permissions(unittest.TestCase):
    def setUp(self):
        self.registry = b.parse_registry(KOTLIN)

    def test_plain_language_with_domains_optional_and_reason(self):
        manifest = {"permissions": [
            {"id": "net.domains", "domains": ["a.example", "b.example"], "reason": "Downloads cores"},
            {"id": "net.any", "required": False, "reason": "Optional"},
            {"id": "android.permission.INTERNET"},
            {"id": "nope.unknown"},
        ]}
        perms = b.describe_permissions(manifest, self.registry)
        self.assertEqual(perms[0]["label"], "Connect to a.example, b.example")
        self.assertEqual(perms[0]["details"], [])
        self.assertTrue(perms[1]["optional"])
        self.assertEqual(perms[2]["label"], "Connect to any site on the internet")
        self.assertIn("does not know", perms[3]["label"])

    def test_manifest_is_read_from_the_bundle_in_memory(self):
        data, raw = bundle_with({"id": "x.y", "permissions": []})
        self.assertEqual(b.read_manifest(data), raw)
        with self.assertRaises(Exception):
            b.read_manifest(b"not a bundle")


def index(description="Does a thing", stream="stable", sha="a" * 64, msha="b" * 64, catalog=None):
    release = {"version": "1.0.0", "stream": stream, "publishedAt": "2026-10-10T01:00:00Z", "manifestSha256": msha,
               "bundle": {"name": "x.tar.xz", "url": "https://github.com/Org/repo/releases/download/v1/x.tar.xz", "size": 2048, "sha256": sha}}
    out = {"schemaVersion": 1, "generatedAt": "2026-10-10T00:00:00Z", "origins": [{
        "origin": "acme", "trust": "third-party", "key": {"keySha256": "c" * 64},
        "plugins": [{"id": "acme.tool", "label": "Tool <b>", "description": description, "releases": [release]}]}]}
    if catalog:
        out["catalog"] = catalog
        out["disclaimer"] = {"version": 1, "text": "Unofficial. <script>alert(1)</script>"}
    return out


class Page(unittest.TestCase):
    now = datetime.datetime(2026, 10, 10, tzinfo=datetime.timezone.utc)

    def render(self, idx, bundles_patch=None):
        registry = b.parse_registry(KOTLIN)
        original = b.fetch
        try:
            if bundles_patch is not None:
                b.fetch = bundles_patch
            return b.render_catalog(idx, "https://example.com/index.json", registry, "none", self.now, "https://droidtop.github.io")
        finally:
            b.fetch = original

    def test_everything_from_the_index_is_escaped(self):
        page = self.render(index("<img src=x onerror=alert(1)>"), bundles_patch=lambda url, limit: (_ for _ in ()).throw(OSError("down")))
        self.assertNotIn("<img", page)
        self.assertIn("&lt;img", page)
        self.assertIn("Tool &lt;b&gt;", page)

    def test_unofficial_catalog_leads_with_its_notice_and_escapes_it(self):
        catalog = {"id": "o/c", "name": "Org", "homepage": "https://github.com/o/c", "trust": "unofficial"}
        page = self.render(index(catalog=catalog), bundles_patch=lambda url, limit: (_ for _ in ()).throw(OSError("down")))
        body = page.split("<body>", 1)[1]
        self.assertTrue(body.lstrip().startswith('<aside class="disclaimer"'))
        self.assertNotIn("<script>alert", page)
        self.assertIn("Add this catalog to droidtop", page)
        self.assertIn("https://droidtop.github.io/add-catalog?address=https%3A%2F%2Fexample.com%2Findex.json", page)
        self.assertIn("could not be read", page)

    def test_a_good_bundle_shows_its_permissions_and_a_mismatch_does_not(self):
        data, raw = bundle_with({"permissions": [{"id": "net.any", "reason": "Because"}]})
        good = index(sha=hashlib.sha256(data).hexdigest(), msha=hashlib.sha256(raw).hexdigest())
        page = self.render(good, bundles_patch=lambda url, limit: data)
        self.assertIn("Connect to any site on the internet", page)
        self.assertIn("Because", page)
        self.assertIn("/install-plugin?catalog=https%3A%2F%2Fexample.com%2Findex.json&amp;id=acme.tool", page)
        bad = index(sha="0" * 64, msha=hashlib.sha256(raw).hexdigest())
        page = self.render(bad, bundles_patch=lambda url, limit: data)
        self.assertNotIn("Connect to any site", page)
        self.assertIn("no longer matches", page)

    def test_testing_only_plugin_has_no_install_button(self):
        page = self.render(index(stream="testing"))
        self.assertNotIn("Install in droidtop", page)
        self.assertIn("No stable release yet", page)

    def test_source_repo_comes_from_the_release_url(self):
        self.assertEqual(b.source_repo(index()["origins"][0]["plugins"][0]), "https://github.com/Org/repo")

    def test_forward_pages_are_written_only_when_asked(self):
        with tempfile.TemporaryDirectory() as out:
            for mode in ("add-catalog", "install-plugin"):
                page = b.render_forward(mode)
                self.assertIn(f'data-mode="{mode}"', page)
                self.assertNotIn("{{", page)


if __name__ == "__main__":
    unittest.main()
