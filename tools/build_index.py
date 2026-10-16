#!/usr/bin/env python3
"""Builds index.json: every droidtop plugin the gamegrab-sources organisation publishes.

The format is droidtop's plugin catalog index (schema version 1, the same as
droidtop-platforms' droidtop-plugins/index.json) plus two top-level blocks that
droidtop shows before it lists anything from a catalog that is not its own:
`catalog` (id, name, homepage, trust) and `disclaimer` (version, text). README.md
documents the whole format.

What enters the index, from every public, unarchived repository of the
organisation, every *.droidplugin.tar.xz release asset whose manifest.jws verifies:
a detached ES256 JWS over the exact manifest.json bytes, the repository's leaf
certificate in x5c, issued by the gamegrab root (gamegrab-root.pub, public). The
leaf names urn:droidtop:origin:gamegrab and, if it names plugins, the manifest's
id; the manifest is under the origin gamegrab (ids gamegrab.<name>).
Each release is listed with its channel (`stream`, as droidtop-platforms' generator does,
Droidtop/tracker#179): a release is "stable"; a pre-release is "unstable" when its tag is
`plugin-unstable*` or `plugin-build*` (the per-push builds), and "testing" otherwise. The index keeps
the newest 5 stable, 3 testing and 3 unstable releases per plugin. Each plugin carries the
`category` of its newest release's signed manifest, when it is one droidtop knows.

Nothing a repository says is trusted for more than display: droidtop verifies
each bundle's signature and every payload hash again on the device. This script
refuses what droidtop would refuse, so the index does not offer it.

Usage
  build_index.py --build   rebuild index.json from the repositories
  build_index.py --check   check the committed files, no network
  build_index.py --check-signature
                           verify index.json.jws as droidtop does; the workflow runs it
                           after signing, on the file it publishes

The `catalog` block names the gamegrab root as `key` (algorithm droidtop-chain-v1) and
the organisation's `origin`; droidtop trusts it on first use when the person accepts
the catalog. Signing the index (tools/sign_jws.sh) is separate.
"""

import argparse
import base64
import hashlib
import io
import json
import os
import pathlib
import re
import sys
import tarfile
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import verify_jws  # noqa: E402

CONFIG = ROOT / "catalog.json"
INDEX = ROOT / "index.json"
README = ROOT / "README.md"
ROOT_KEY = ROOT / "gamegrab-root.pub"
INDEX_SIGNATURE = ROOT / "index.json.jws"

SCHEMA_VERSION = 1
ALGORITHM = "droidtop-chain-v1"
PLUGIN_TYP = "droidtop-plugin+jws"
CATALOG_TYP = "droidtop-catalog+jws"
ORIGIN_URN = "urn:droidtop:origin:"
PLUGIN_URN = "urn:droidtop:plugin:"
CATALOG_URN = "urn:droidtop:catalog:"
BUNDLE_SUFFIX = ".droidplugin.tar.xz"
MAX_BUNDLES_PER_RELEASE = 8
MAX_BUNDLE_BYTES = 512 * 1024 * 1024
# Per plugin and stream: a plugin's newest stable release must never fall off the list
# because a busy branch published many pre-releases after it.
KEEP_RELEASES = {"stable": 5, "testing": 3, "unstable": 3}
# The per-push pre-releases of droidtop-plugin-bundle.yml (with the caller's optional suffix).
UNSTABLE_TAG = re.compile(r"plugin-(unstable|build)([.-]|$)")
# droidtop's categories (plugin-api.md 1.2), and the 2026-10-15 ids droidtop reads as their
# successors (tools, themes, social, games). Anything else is left out, which droidtop shows as "other".
CATEGORIES = {"sources", "emulators", "system", "sync", "integrations", "appearance", "other",
              "tools", "themes", "social", "games"}
MAX_DISCLAIMER_CHARS = 4000
RETRIES = 3
RETRY_PAUSE_SECONDS = 10
USER_AGENT = "gamegrab-sources-catalog"

ORIGIN = re.compile(r"[a-z0-9-]{1,64}")
CATALOG_ID = re.compile(r"[A-Za-z0-9._/-]{1,100}")
HEX_64 = re.compile(r"[0-9a-f]{64}")


class Rejected(Exception):
    """A repository, release or bundle the index leaves out, with the reason."""


def log(message):
    print(message, flush=True)


def warn(message):
    print("::warning::" + message, flush=True)


# --- GitHub --------------------------------------------------------------------


def with_retries(fetch):
    for attempt in range(RETRIES):
        try:
            return fetch()
        except urllib.error.HTTPError as error:
            if error.code < 500 or attempt == RETRIES - 1:
                raise
        except urllib.error.URLError:
            if attempt == RETRIES - 1:
                raise
        time.sleep(RETRY_PAUSE_SECONDS * (attempt + 1))


def request(url, api):
    req = urllib.request.Request(url)
    req.add_header("User-Agent", USER_AGENT)
    if api:
        req.add_header("Accept", "application/vnd.github+json")
        req.add_header("X-GitHub-Api-Version", "2022-11-28")
    token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    if token and url.startswith("https://api.github.com/"):
        req.add_header("Authorization", "Bearer " + token)
    return req


def api(url):
    def once():
        with urllib.request.urlopen(request(url, True), timeout=60) as response:
            return json.loads(response.read().decode("utf-8")), response.headers.get("Link")
    return with_retries(once)


def download(url, limit):
    def once():
        with urllib.request.urlopen(request(url, False), timeout=300) as response:
            data = response.read(limit + 1)
            if len(data) > limit:
                raise Rejected(url + " is larger than " + str(limit) + " bytes")
            return data
    return with_retries(once)


def next_link(link):
    if not link:
        return None
    for part in link.split(","):
        segments = part.split(";")
        if any(s.strip() == 'rel="next"' for s in segments[1:]):
            return segments[0].strip().strip("<>")
    return None


def paged(url):
    while url:
        page, link = api(url)
        yield from page
        url = next_link(link)


def repositories(organisation):
    for repo in paged("https://api.github.com/orgs/" + organisation + "/repos?type=public&per_page=100"):
        if not repo.get("archived") and not repo.get("private") and not repo.get("fork"):
            yield repo


# --- keys and signatures -------------------------------------------------------


def sha256_hex(data):
    return hashlib.sha256(data).hexdigest()


def spki_der(pem):
    from cryptography.hazmat.primitives import serialization
    return serialization.load_pem_public_key(pem).public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def covers(plugin_ids, plugin_id):
    for entry in plugin_ids:
        if entry.endswith(".*"):
            prefix = entry[:-1]
            if plugin_id.startswith(prefix) and len(plugin_id) > len(prefix):
                return True
        elif entry == plugin_id:
            return True
    return False


# --- bundles -------------------------------------------------------------------


def manifest_of(bundle, what):
    """manifest.json bytes and manifest.jws text from a .droidplugin.tar.xz."""
    wanted = ("manifest.json", "manifest.jws")
    try:
        with tarfile.open(fileobj=io.BytesIO(bundle), mode="r:xz") as archive:
            found = {}
            for member in archive:
                if member.name in wanted and member.isfile() and member.size <= 1024 * 1024:
                    found[member.name] = archive.extractfile(member).read()
    except (tarfile.TarError, EOFError, OSError) as error:
        raise Rejected(what + ": not a readable tar.xz (" + str(error) + ")")
    if "manifest.json" not in found or "manifest.jws" not in found:
        raise Rejected(what + ": no manifest.json and manifest.jws at the top of the bundle")
    return found["manifest.json"], found["manifest.jws"].decode("ascii", "replace")


def stream_of(release):
    """The channel a GitHub release is listed in."""
    if not release.get("prerelease"):
        return "stable"
    return "unstable" if UNSTABLE_TAG.match(str(release.get("tag_name", ""))) else "testing"


def category_of(manifest):
    """The manifest's category when droidtop knows it, else None."""
    category = manifest.get("category")
    return category if isinstance(category, str) and category in CATEGORIES else None


def release_entry(release, asset, bundle, root):
    """root: the organisation's (origin, PEM)."""
    what = release["tag_name"] + "/" + asset["name"]
    manifest_bytes, jws = manifest_of(bundle, what)
    try:
        manifest = json.loads(manifest_bytes)
    except ValueError:
        raise Rejected(what + ": manifest.json is not JSON")
    plugin_id = str(manifest.get("id", ""))
    origin, root_pem = root
    try:
        san = verify_jws.verify(PLUGIN_TYP, manifest_bytes, jws, root_pem, [ORIGIN_URN + origin])
    except Exception as error:
        raise Rejected(what + ": manifest.jws does not verify to the gamegrab root (" + str(error) + ")")
    named = [u[len(PLUGIN_URN):] for u in san if u.startswith(PLUGIN_URN)]
    if named and not covers(named, plugin_id):
        raise Rejected(what + ": the leaf is for " + ", ".join(named) + ", not " + plugin_id)
    if manifest.get("origin") != origin or plugin_id != plugin_id.lower() or not plugin_id.startswith(origin + "."):
        raise Rejected(what + ": the manifest's origin and id are not under origin " + repr(origin))
    label = str(manifest.get("label") or "").strip()
    version = str(manifest.get("version") or "").strip()
    if not label or not version:
        raise Rejected(what + ": the manifest has no label or version")
    description = manifest.get("description")
    if manifest.get("category") is not None and category_of(manifest) is None:
        warn(what + ": unknown category " + repr(manifest.get("category")) + "; listed without one")
    meta = (label, description if isinstance(description, str) and description.strip() else None,
            category_of(manifest))
    return origin, plugin_id, meta, {
        "version": version,
        "stream": stream_of(release),
        "publishedAt": release.get("published_at"),
        "manifestSha256": sha256_hex(manifest_bytes),
        "bundle": {
            "name": asset["name"],
            "url": asset["browser_download_url"],
            "size": len(bundle),
            "sha256": sha256_hex(bundle),
        },
    }


def known_entries(previous):
    """Releases already in the committed index, by bundle URL, size and publish time: they are not downloaded again."""
    known = {}
    for origin in (previous or {}).get("origins", []):
        for plugin in origin.get("plugins", []):
            for release in plugin.get("releases", []):
                bundle = release.get("bundle", {})
                key = (bundle.get("url"), bundle.get("size"), release.get("publishedAt"))
                known[key] = (origin.get("origin"), origin.get("key", {}).get("keySha256"), plugin, release)
    return known


# --- the index -----------------------------------------------------------------


def load_config():
    config = json.loads(CONFIG.read_text(encoding="utf-8"))
    catalog, disclaimer = config["catalog"], config["disclaimer"]
    if not CATALOG_ID.fullmatch(catalog["id"]) or catalog.get("trust") != "unofficial":
        raise SystemExit("catalog.json: the catalog id is malformed or its trust is not \"unofficial\"")
    if not ORIGIN.fullmatch(catalog.get("origin", "")) or catalog["origin"] == "droidtop":
        raise SystemExit("catalog.json: the catalog's origin is not a third-party origin id")
    if not isinstance(disclaimer.get("version"), int) or disclaimer["version"] < 1:
        raise SystemExit("catalog.json: the disclaimer version is a whole number from 1")
    text = disclaimer.get("text", "")
    if not text.strip() or len(text) > MAX_DISCLAIMER_CHARS:
        raise SystemExit("catalog.json: the disclaimer text is empty or longer than " + str(MAX_DISCLAIMER_CHARS))
    retired = config.get("retired", {})
    if not isinstance(retired, dict) or not all(isinstance(k, str) and isinstance(v, str) and v.strip() for k, v in retired.items()):
        raise SystemExit("catalog.json: retired maps plugin ids to a note saying why")
    return config


def load_root(config):
    """The organisation's root (public): (origin, PEM, key block). The origin's one trust anchor."""
    if not ROOT_KEY.is_file():
        raise SystemExit("gamegrab-root.pub is missing")
    pem = ROOT_KEY.read_bytes()
    der = spki_der(pem)
    spki = base64.b64encode(der).decode("ascii")
    return config["catalog"]["origin"], pem, {"formatVersion": 1, "algorithm": ALGORITHM, "publicKeySpki": spki, "keySha256": sha256_hex(der)}


def catalog_block(config, root):
    """The catalog block: catalog.json's, with the root as `key`; `origin` only beside a key."""
    block = {k: v for k, v in config["catalog"].items() if k != "origin"}
    block["origin"] = root[0]
    block["key"] = dict(root[2])
    return block


def build(config, previous):
    organisation = config["organisation"]
    own_repo = config["catalog"]["homepage"].rstrip("/").split("github.com/")[-1].lower()
    root = load_root(config)
    known = known_entries(previous)
    retired = config.get("retired", {})
    origins = {}
    plugin_owner = {}
    refused = []

    def origin_entry(origin, key_block, repo):
        entry = origins.get(origin)
        if entry is None:
            entry = origins[origin] = {"origin": origin, "trust": "third-party", "key": key_block, "plugins": {}, "repos": []}
        if repo not in entry["repos"]:
            entry["repos"].append(repo)
        return entry

    for repo in sorted(repositories(organisation), key=lambda r: r["full_name"].lower()):
        name = repo["full_name"]
        if name.lower() == own_repo:
            continue
        for release in paged("https://api.github.com/repos/" + name + "/releases?per_page=100"):
            if release.get("draft"):
                continue
            assets = [a for a in release.get("assets", []) if a["name"].endswith(BUNDLE_SUFFIX)]
            for asset in assets[:MAX_BUNDLES_PER_RELEASE]:
                what = name + " " + release["tag_name"] + "/" + asset["name"]
                try:
                    if asset["size"] > MAX_BUNDLE_BYTES:
                        raise Rejected(what + ": larger than " + str(MAX_BUNDLE_BYTES) + " bytes")
                    cached = known.get((asset["browser_download_url"], asset["size"], release.get("published_at")))
                    if cached and cached[0] == root[0] and cached[1] == root[2]["keySha256"]:
                        origin, _, plugin, listed = cached
                        plugin_id = plugin["id"]
                        meta = (plugin["label"], plugin.get("description"), plugin.get("category"))
                        release_json = dict(listed, stream=stream_of(release))
                    else:
                        log("downloading " + what)
                        bundle = download(asset["browser_download_url"], MAX_BUNDLE_BYTES)
                        origin, plugin_id, meta, release_json = release_entry(release, asset, bundle, (root[0], root[1]))
                    if plugin_id in retired:
                        raise Rejected(what + ": " + plugin_id + " is retired: " + retired[plugin_id])
                    entry = origin_entry(origin, dict(root[2], origin=origin), name)
                    owner = plugin_owner.setdefault(plugin_id, name)
                    if owner != name:
                        raise Rejected(what + ": plugin " + plugin_id + " is already listed from " + owner)
                    plugin = entry["plugins"].setdefault(plugin_id, {"id": plugin_id, "releases": []})
                    plugin["releases"].append((release.get("published_at") or "", meta, release_json))
                except Rejected as reason:
                    refused.append(str(reason))
    document_origins = []
    for origin in sorted(origins):
        entry = origins[origin]
        plugins = []
        for plugin_id in sorted(entry["plugins"]):
            plugin = entry["plugins"][plugin_id]
            ordered = sorted(plugin["releases"], key=lambda r: r[0], reverse=True)
            kept, counts = [], {}
            for item in ordered:
                stream = item[2]["stream"]
                if counts.get(stream, 0) < KEEP_RELEASES.get(stream, 3):
                    counts[stream] = counts.get(stream, 0) + 1
                    kept.append(item)
            # Label, description and category come from the newest release's signed manifest.
            label, description, category = ordered[0][1]
            listed = {"id": plugin_id, "label": label, "description": description}
            if category is not None:
                listed["category"] = category
            listed["releases"] = [r[2] for r in kept]
            plugins.append(listed)
        if plugins:
            document_origins.append({"origin": origin, "trust": "third-party", "key": entry["key"], "plugins": plugins})
    document = {
        "schemaVersion": SCHEMA_VERSION,
        "generatedAt": None,
        "catalog": catalog_block(config, root),
        "disclaimer": dict(config["disclaimer"]),
        "origins": document_origins,
    }
    return document, refused, origins


def body(document):
    return {k: v for k, v in document.items() if k != "generatedAt"}


def dump(document):
    return json.dumps(document, indent=1, ensure_ascii=False) + "\n"


def retired_listed(document, config):
    """catalog.json `retired`: plugin ids the index must no longer list. Checked on a rebuilt index only:
    the committed one may still list a plugin until the run that retires it rebuilds it."""
    retired = config.get("retired", {})
    return [
        "retired plugin " + str(plugin.get("id")) + " is listed"
        for origin in document.get("origins", [])
        for plugin in origin.get("plugins", [])
        if plugin.get("id") in retired
    ]


def check_document(document, config):
    """What droidtop's parser requires, plus this catalog's own blocks. Returns a list of problems."""
    problems = []
    if document.get("schemaVersion") != SCHEMA_VERSION:
        problems.append("schemaVersion is not " + str(SCHEMA_VERSION))
    catalog = document.get("catalog", {})
    expected = {k: v for k, v in config["catalog"].items() if k != "origin"}
    if {k: v for k, v in catalog.items() if k not in ("key", "origin")} != expected:
        problems.append("the catalog block differs from catalog.json")
    if ("key" in catalog) != ("origin" in catalog) or catalog.get("origin", config["catalog"]["origin"]) != config["catalog"]["origin"]:
        problems.append("the catalog block names its origin without its root key, or another origin")
    if document.get("disclaimer") != config["disclaimer"]:
        problems.append("the disclaimer differs from catalog.json")
    seen = set()
    for origin in document.get("origins", []):
        name = origin.get("origin", "")
        if not ORIGIN.fullmatch(name) or name == "droidtop" or origin.get("trust") != "third-party":
            problems.append("origin " + repr(name) + " is not a third-party origin")
        key = origin.get("key", {})
        if key.get("origin") != name or key.get("algorithm") != ALGORITHM or not HEX_64.fullmatch(str(key.get("keySha256", ""))):
            problems.append("origin " + repr(name) + " has a malformed key block")
        for plugin in origin.get("plugins", []):
            plugin_id = plugin.get("id", "")
            if not plugin_id.startswith(name + ".") or plugin_id != plugin_id.lower() or plugin_id in seen:
                problems.append("plugin " + repr(plugin_id) + " is not unique under its origin")
            seen.add(plugin_id)
            if not plugin.get("label") or not plugin.get("releases"):
                problems.append("plugin " + repr(plugin_id) + " has no label or no release")
            if "category" in plugin and plugin["category"] not in CATEGORIES:
                problems.append("plugin " + repr(plugin_id) + " has an unknown category")
            for release in plugin.get("releases", []):
                bundle = release.get("bundle", {})
                if release.get("stream") not in ("stable", "testing", "unstable") \
                        or not HEX_64.fullmatch(str(release.get("manifestSha256", ""))) \
                        or not HEX_64.fullmatch(str(bundle.get("sha256", ""))) \
                        or not str(bundle.get("url", "")).startswith("https://"):
                    problems.append("plugin " + repr(plugin_id) + " has a malformed release")
    return problems


def check_static(config):
    problems = []
    readme = README.read_text(encoding="utf-8")
    if config["disclaimer"]["text"] not in readme:
        problems.append("README.md does not carry the disclaimer text from catalog.json word for word")
    return problems


def check_signature(config):
    """index.json.jws, when published, checked as droidtop's CatalogSignature checks it."""
    if not INDEX_SIGNATURE.is_file():
        return []
    root = load_root(config)
    try:
        san = verify_jws.verify(CATALOG_TYP, INDEX.read_bytes(), INDEX_SIGNATURE.read_text(encoding="ascii"), root[1], [CATALOG_URN + config["catalog"]["id"]])
    except Exception as error:
        return ["index.json.jws does not verify to the gamegrab root (" + str(error) + ")"]
    log("index.json is signed by a catalog leaf " + " ".join(san) + ", issued by the root " + root[2]["keySha256"])
    return []


def summary(document, refused, origins):
    lines = ["## Catalog index", ""]
    for origin in document["origins"]:
        repos = ", ".join(origins[origin["origin"]]["repos"])
        lines.append("- **" + origin["origin"] + "** (" + repos + "), key sha256 `" + origin["key"]["keySha256"] + "`")
        for plugin in origin["plugins"]:
            lines.append("  - " + plugin["id"] + ": " + ", ".join(r["version"] + " (" + r["stream"] + ")" for r in plugin["releases"]))
    if refused:
        lines += ["", "### Left out", ""] + ["- " + r for r in refused]
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    if path:
        with open(path, "a", encoding="utf-8") as handle:
            handle.write("\n".join(lines) + "\n")
    log("\n".join(lines))


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--build", action="store_true")
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--check-signature", action="store_true")
    args = parser.parse_args()
    config = load_config()
    previous = json.loads(INDEX.read_text(encoding="utf-8")) if INDEX.is_file() else None
    if args.check_signature:
        problems = check_signature(config)
        for problem in problems:
            print("::error::" + problem, flush=True)
        if problems:
            sys.exit(1)
        if not INDEX_SIGNATURE.is_file():
            log("index.json is published unsigned")
        return
    problems = check_static(config)
    if args.check:
        if previous is not None:
            problems += check_document(previous, config)
        for problem in problems:
            print("::error::" + problem, flush=True)
        if problems:
            sys.exit(1)
        log("index.json, catalog.json and README.md agree")
        return
    if problems:
        for problem in problems:
            print("::error::" + problem, flush=True)
        sys.exit(1)
    document, refused, origins = build(config, previous)
    for reason in refused:
        warn(reason)
    problems = check_document(document, config) + retired_listed(document, config)
    if problems:
        for problem in problems:
            print("::error::" + problem, flush=True)
        sys.exit(1)
    if previous is not None and body(previous) == body(document):
        document["generatedAt"] = previous.get("generatedAt")
    else:
        document["generatedAt"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    INDEX.write_text(dump(document), encoding="utf-8")
    summary(document, refused, origins)


if __name__ == "__main__":
    main()
