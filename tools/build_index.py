#!/usr/bin/env python3
"""Builds index.json: every droidtop plugin the gamegrab-sources organisation publishes.

The format is droidtop's plugin catalog index (schema version 1, the same as
droidtop-platforms' droidtop-plugins/index.json) plus two top-level blocks that
droidtop shows before it lists anything from a catalog that is not its own:
`catalog` (id, name, homepage, trust) and `disclaimer` (version, text). README.md
documents the whole format.

What enters the index:
  * every public, unarchived repository of the organisation that commits a
    droidtop-plugin-key.json at the root of its default branch (the origin id
    and P-256 key its bundles are signed with);
  * from each of its releases, every *.droidplugin.tar.xz asset whose
    manifest.json is signed by that key (manifest.sig), names that origin and
    an id under it. A prerelease is the "testing" stream, anything else
    "stable".

Nothing a repository says is trusted for more than display: droidtop verifies
each bundle's signature and every payload hash again on the device. This script
refuses what droidtop would refuse, so the index does not offer it.

Usage
  build_index.py --build [--signed]   rebuild index.json from the repositories
  build_index.py --check              check the committed files, no network

--signed puts the catalog master's public key (catalog-master-key.json) in the
`catalog` block. It is passed only when the workflow is about to sign the index
(tools/sign_index.sh): an index that names a key must carry a valid signature,
or droidtop refuses it.
"""

import argparse
import base64
import hashlib
import io
import json
import os
import pathlib
import re
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

ROOT = pathlib.Path(__file__).resolve().parent.parent
CONFIG = ROOT / "catalog.json"
INDEX = ROOT / "index.json"
README = ROOT / "README.md"
REVOCATIONS = ROOT / "revocations.json"
MASTER_KEY = ROOT / "catalog-master-key.json"

SCHEMA_VERSION = 1
ALGORITHM = "SHA256withECDSA"
KEY_FILE = "droidtop-plugin-key.json"
BUNDLE_SUFFIX = ".droidplugin.tar.xz"
MAX_BUNDLES_PER_RELEASE = 8
MAX_BUNDLE_BYTES = 512 * 1024 * 1024
MAX_RELEASES_PER_PLUGIN = 10
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


def committed_file(repo, branch, name):
    try:
        return download("https://raw.githubusercontent.com/" + repo + "/" + branch + "/" + name, 64 * 1024)
    except urllib.error.HTTPError as error:
        if error.code == 404:
            return None
        raise


# --- keys and signatures -------------------------------------------------------


def openssl(*arguments):
    return subprocess.run(["openssl", *arguments], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)


def p256_der(spki_b64, what):
    try:
        der = base64.b64decode(spki_b64, validate=True)
    except (ValueError, TypeError):
        raise Rejected(what + ": the key is not base64")
    with tempfile.NamedTemporaryFile(suffix=".der") as key:
        key.write(der)
        key.flush()
        result = openssl("pkey", "-pubin", "-inform", "DER", "-in", key.name, "-noout", "-text")
    text = result.stdout.decode(errors="replace")
    if result.returncode != 0 or not ("prime256v1" in text or "P-256" in text):
        raise Rejected(what + ": not an EC P-256 SubjectPublicKeyInfo")
    return der


def verifies(message, signature_b64, der):
    try:
        signature = base64.b64decode(signature_b64.strip(), validate=True)
    except (ValueError, TypeError):
        return False
    with tempfile.TemporaryDirectory() as temporary:
        folder = pathlib.Path(temporary)
        (folder / "message").write_bytes(message)
        (folder / "signature").write_bytes(signature)
        (folder / "key.der").write_bytes(der)
        result = openssl("dgst", "-sha256", "-verify", str(folder / "key.der"), "-keyform", "DER",
                         "-signature", str(folder / "signature"), str(folder / "message"))
    return result.returncode == 0


def sha256_hex(data):
    return hashlib.sha256(data).hexdigest()


def published_key(raw, repo):
    """A repository's droidtop-plugin-key.json, read the way droidtop reads it ("key", or "publicKey")."""
    try:
        document = json.loads(raw)
    except (ValueError, UnicodeDecodeError):
        raise Rejected(repo + ": " + KEY_FILE + " is not JSON")
    origin = str(document.get("origin", "")).strip()
    key = str(document.get("key") or document.get("publicKey") or "").strip()
    if not ORIGIN.fullmatch(origin) or origin == "droidtop":
        raise Rejected(repo + ": origin " + repr(origin) + " is not a third-party origin id")
    der = p256_der(key, repo + " " + KEY_FILE)
    spki = base64.b64encode(der).decode("ascii")
    return origin, {
        "formatVersion": 1,
        "algorithm": ALGORITHM,
        "origin": origin,
        "publicKeySpki": spki,
        "keySha256": sha256_hex(der),
    }, der


# --- bundles -------------------------------------------------------------------


def manifest_of(bundle, what):
    """manifest.json bytes and manifest.sig text from a .droidplugin.tar.xz."""
    try:
        with tarfile.open(fileobj=io.BytesIO(bundle), mode="r:xz") as archive:
            found = {}
            for member in archive:
                if member.name in ("manifest.json", "manifest.sig") and member.isfile() and member.size <= 1024 * 1024:
                    found[member.name] = archive.extractfile(member).read()
                if len(found) == 2:
                    break
    except (tarfile.TarError, EOFError, OSError) as error:
        raise Rejected(what + ": not a readable tar.xz (" + str(error) + ")")
    if "manifest.json" not in found or "manifest.sig" not in found:
        raise Rejected(what + ": no manifest.json and manifest.sig at the top of the bundle")
    return found["manifest.json"], found["manifest.sig"].decode("ascii", "replace")


def release_entry(release, asset, bundle, origin, der):
    what = release["tag_name"] + "/" + asset["name"]
    manifest_bytes, signature = manifest_of(bundle, what)
    if not verifies(manifest_bytes, signature, der):
        raise Rejected(what + ": manifest.sig does not verify against the repository's committed key")
    try:
        manifest = json.loads(manifest_bytes)
    except ValueError:
        raise Rejected(what + ": manifest.json is not JSON")
    plugin_id = str(manifest.get("id", ""))
    if manifest.get("origin") != origin or plugin_id != plugin_id.lower() or not plugin_id.startswith(origin + "."):
        raise Rejected(what + ": the manifest's origin and id are not under origin " + repr(origin))
    label = str(manifest.get("label") or "").strip()
    version = str(manifest.get("version") or "").strip()
    if not label or not version:
        raise Rejected(what + ": the manifest has no label or version")
    description = manifest.get("description")
    return plugin_id, label, description if isinstance(description, str) and description.strip() else None, {
        "version": version,
        "stream": "testing" if release.get("prerelease") else "stable",
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
    if not isinstance(disclaimer.get("version"), int) or disclaimer["version"] < 1:
        raise SystemExit("catalog.json: the disclaimer version is a whole number from 1")
    text = disclaimer.get("text", "")
    if not text.strip() or len(text) > MAX_DISCLAIMER_CHARS:
        raise SystemExit("catalog.json: the disclaimer text is empty or longer than " + str(MAX_DISCLAIMER_CHARS))
    return config


def catalog_block(config, signed):
    block = dict(config["catalog"])
    if signed:
        if not MASTER_KEY.is_file():
            raise SystemExit("--signed needs catalog-master-key.json, the catalog master's PUBLIC key, committed beside the index")
        master = json.loads(MASTER_KEY.read_text(encoding="utf-8"))
        der = p256_der(master.get("publicKeySpki", ""), "catalog-master-key.json")
        block["key"] = {
            "formatVersion": 1,
            "algorithm": ALGORITHM,
            "publicKeySpki": base64.b64encode(der).decode("ascii"),
            "keySha256": sha256_hex(der),
        }
    return block


def build(config, previous, signed):
    organisation = config["organisation"]
    own_repo = config["catalog"]["homepage"].rstrip("/").split("github.com/")[-1].lower()
    known = known_entries(previous)
    origins = {}
    plugin_owner = {}
    refused = []
    for repo in sorted(repositories(organisation), key=lambda r: r["full_name"].lower()):
        name = repo["full_name"]
        if name.lower() == own_repo:
            continue
        raw = committed_file(name, repo["default_branch"], KEY_FILE)
        if raw is None:
            log(name + ": no committed " + KEY_FILE + ", not a plugin repository")
            continue
        try:
            origin, key_block, der = published_key(raw, name)
        except Rejected as reason:
            refused.append(str(reason))
            continue
        entry = origins.get(origin)
        if entry is None:
            entry = origins[origin] = {"origin": origin, "trust": "third-party", "key": key_block, "plugins": {}, "repos": [name]}
        elif entry["key"]["keySha256"] != key_block["keySha256"]:
            refused.append(name + ": origin " + repr(origin) + " is already listed from " + entry["repos"][0] + " with another key")
            continue
        else:
            entry["repos"].append(name)
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
                    if cached and cached[0] == origin and cached[1] == key_block["keySha256"]:
                        _, _, plugin, listed = cached
                        plugin_id, label, description = plugin["id"], plugin["label"], plugin.get("description")
                        release_json = dict(listed, stream="testing" if release.get("prerelease") else "stable")
                    else:
                        log("downloading " + what)
                        bundle = download(asset["browser_download_url"], MAX_BUNDLE_BYTES)
                        plugin_id, label, description, release_json = release_entry(release, asset, bundle, origin, der)
                    owner = plugin_owner.setdefault(plugin_id, name)
                    if owner != name:
                        raise Rejected(what + ": plugin " + plugin_id + " is already listed from " + owner)
                    plugin = entry["plugins"].setdefault(plugin_id, {"id": plugin_id, "label": label, "description": description, "releases": []})
                    plugin["releases"].append((release.get("published_at") or "", label, description, release_json))
                except Rejected as reason:
                    refused.append(str(reason))
    document_origins = []
    for origin in sorted(origins):
        entry = origins[origin]
        plugins = []
        for plugin_id in sorted(entry["plugins"]):
            plugin = entry["plugins"][plugin_id]
            ordered = sorted(plugin["releases"], key=lambda r: r[0], reverse=True)[:MAX_RELEASES_PER_PLUGIN]
            # Label and description come from the newest release's signed manifest.
            plugins.append({
                "id": plugin_id,
                "label": ordered[0][1],
                "description": ordered[0][2],
                "releases": [r[3] for r in ordered],
            })
        if plugins:
            document_origins.append({"origin": origin, "trust": "third-party", "key": entry["key"], "plugins": plugins})
    document = {
        "schemaVersion": SCHEMA_VERSION,
        "generatedAt": None,
        "catalog": catalog_block(config, signed),
        "disclaimer": dict(config["disclaimer"]),
        "origins": document_origins,
    }
    return document, refused, origins


def body(document):
    return {k: v for k, v in document.items() if k != "generatedAt"}


def dump(document):
    return json.dumps(document, indent=1, ensure_ascii=False) + "\n"


def check_document(document, config):
    """What droidtop's parser requires, plus this catalog's own blocks. Returns a list of problems."""
    problems = []
    if document.get("schemaVersion") != SCHEMA_VERSION:
        problems.append("schemaVersion is not " + str(SCHEMA_VERSION))
    catalog = document.get("catalog", {})
    expected = dict(config["catalog"])
    if {k: v for k, v in catalog.items() if k != "key"} != expected:
        problems.append("the catalog block differs from catalog.json")
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
    revocations = json.loads(REVOCATIONS.read_text(encoding="utf-8"))
    if revocations.get("formatVersion") != 1 or not isinstance(revocations.get("sequence"), int) or revocations["sequence"] < 1:
        problems.append("revocations.json needs formatVersion 1 and a sequence from 1")
    if any(not HEX_64.fullmatch(str(k)) for k in revocations.get("keySha256", [])):
        problems.append("revocations.json: every keySha256 is 64 lowercase hex digits")
    return problems


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
    parser.add_argument("--signed", action="store_true")
    args = parser.parse_args()
    config = load_config()
    previous = json.loads(INDEX.read_text(encoding="utf-8")) if INDEX.is_file() else None
    problems = check_static(config)
    if args.check:
        if previous is not None:
            problems += check_document(previous, config)
        for problem in problems:
            print("::error::" + problem, flush=True)
        if problems:
            sys.exit(1)
        log("index.json, catalog.json, README.md and revocations.json agree")
        return
    if problems:
        for problem in problems:
            print("::error::" + problem, flush=True)
        sys.exit(1)
    document, refused, origins = build(config, previous, args.signed)
    for reason in refused:
        warn(reason)
    problems = check_document(document, config)
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
