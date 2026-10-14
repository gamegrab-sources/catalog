#!/usr/bin/env python3
"""Builds the web page of a droidtop plugin catalog from the catalog's own index.json.

The same script makes droidtop.github.io (droidtop's official catalog) and the
gamegrab-sources catalog's page (copied into that repository, like build_index.py).
Standard library only.

    build_site.py --index <index.json path or https URL> --address <the catalog address droidtop is given>
                  --registry <PluginPermissions.kt path or https URL> --out <dir>
                  [--link-host https://droidtop.github.io] [--forward-pages]

What a page says comes from the index and from the newest stable bundle of each plugin
(its manifest.json, read after the bundle's SHA-256 and its manifest's SHA-256 matched the
index). Nothing is invented: what could not be read is said so on the page.
"""
from __future__ import annotations

import argparse
import datetime
import hashlib
import html
import io
import json
import os
import re
import shutil
import sys
import tarfile
import time
import urllib.error
import urllib.parse
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
STATIC = os.path.join(HERE, "static")

MAX_INDEX = 8 * 1024 * 1024
MAX_BUNDLE = 64 * 1024 * 1024
MAX_MANIFEST = 1024 * 1024
MAX_REGISTRY = 1024 * 1024
LINK_HOST = "https://droidtop.github.io"
PLUGIN_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")

# PermissionTier in droidtop's PluginPermissions.kt -> (css class, word on the page).
TIERS = {
    "NORMAL": ("normal", "Normal"),
    "DANGEROUS": ("sensitive", "Sensitive"),
    "CRITICAL": ("critical", "Critical"),
}

e = html.escape


# ---------------------------------------------------------------- reading

def fetch(url: str, limit: int) -> bytes:
    if not url.startswith("https://"):
        raise ValueError(f"refusing a non-https address: {url}")
    last: Exception | None = None
    for attempt in range(3):
        try:
            request = urllib.request.Request(url, headers={"User-Agent": "droidtop-catalog-site"})
            with urllib.request.urlopen(request, timeout=60) as response:
                data = response.read(limit + 1)
            if len(data) > limit:
                raise ValueError(f"{url} is larger than {limit} bytes")
            return data
        except urllib.error.HTTPError as error:
            if error.code == 404:
                raise
            last = error
        except (urllib.error.URLError, TimeoutError, OSError) as error:
            last = error
        time.sleep(2 * (attempt + 1))
    raise last if last else RuntimeError(url)


def read_source(source: str, limit: int) -> bytes:
    if source.startswith("https://"):
        return fetch(source, limit)
    with open(source, "rb") as handle:
        return handle.read()


def index_signature(source: str) -> str:
    """"published" when a signature file sits beside the index, "none" when it does not, "unknown" when that could not be told."""
    sibling = source.rsplit("/", 1)[0] + "/index.json.sig" if source.startswith("https://") else os.path.join(os.path.dirname(source), "index.json.sig")
    try:
        read_source(sibling, 64 * 1024)
        return "published"
    except (FileNotFoundError, urllib.error.HTTPError) as error:
        if isinstance(error, urllib.error.HTTPError) and error.code != 404:
            return "unknown"
        return "none"
    except (urllib.error.URLError, OSError, ValueError):
        return "unknown"


def parse_index(data: bytes) -> dict:
    index = json.loads(data.decode("utf-8"))
    if not isinstance(index, dict) or index.get("schemaVersion") != 1 or not isinstance(index.get("origins"), list):
        raise ValueError("not a droidtop plugin catalog index (schema version 1)")
    return index


_PERM = re.compile(r'PluginPermission\(\s*"([^"]+)",\s*PermissionTier\.(\w+),\s*"((?:[^"\\]|\\.)*)"', re.S)
_CAUTION = re.compile(r'caution\s*=\s*"((?:[^"\\]|\\.)*)"', re.S)
_ANDROID = re.compile(r'AndroidNeed\(\s*"([^"]+)"')


def _unescape(text: str) -> str:
    return re.sub(r"\\(.)", r"\1", text)


def parse_registry(source: str) -> dict:
    """The permission registry of droidtop's PluginPermissions.kt: id -> {tier, label, caution, android}."""
    matches = list(_PERM.finditer(source))
    registry: dict = {}
    for i, match in enumerate(matches):
        end = matches[i + 1].start() if i + 1 < len(matches) else len(source)
        chunk = source[match.end():end]
        caution = _CAUTION.search(chunk)
        android = _ANDROID.search(chunk)
        registry[match.group(1)] = {
            "tier": match.group(2),
            "label": _unescape(match.group(3)),
            "caution": _unescape(caution.group(1)) if caution else None,
            "android": android.group(1) if android else None,
        }
    if len(registry) < 40:
        raise ValueError(f"read only {len(registry)} permissions from the registry; its format changed")
    return registry


def read_manifest(bundle: bytes) -> bytes:
    """manifest.json of a .droidplugin.tar.xz, read in memory; nothing else is opened."""
    with tarfile.open(fileobj=io.BytesIO(bundle), mode="r:xz") as tar:
        for member in tar:
            if member.name.lstrip("./") == "manifest.json" and member.isfile():
                if member.size > MAX_MANIFEST:
                    raise ValueError("manifest.json is unreasonably large")
                handle = tar.extractfile(member)
                if handle is None:
                    break
                return handle.read()
    raise ValueError("the bundle has no manifest.json")


def describe_permissions(manifest: dict, registry: dict) -> list:
    by_android = {v["android"]: k for k, v in registry.items() if v.get("android")}
    out = []
    for entry in manifest.get("permissions") or []:
        if not isinstance(entry, dict) or not isinstance(entry.get("id"), str):
            continue
        pid = entry["id"]
        host_id = by_android.get(pid, pid)
        known = registry.get(host_id)
        details = []
        for key, value in entry.items():
            if key in ("id", "reason", "required", "android"):
                continue
            if isinstance(value, str):
                details.append((key, [value]))
            elif isinstance(value, list) and all(isinstance(v, str) for v in value):
                details.append((key, value))
        if known:
            tier = TIERS.get(known["tier"], ("unknown", "Unknown"))
            label, caution = known["label"], known["caution"]
        elif host_id.startswith("provide:"):
            tier, label, caution = ("unknown", "Unknown"), "Add to droidtop: " + host_id[len("provide:"):], None
        else:
            tier, label, caution = ("unknown", "Unknown"), "A permission this page does not know (" + pid + ")", None
        if host_id == "net.domains":
            domains = dict(details).get("domains")
            if domains:
                label = "Connect to " + ", ".join(domains)
                details = [d for d in details if d[0] != "domains"]
        out.append({
            "id": pid,
            "label": label,
            "tier": tier,
            "caution": caution,
            "reason": entry.get("reason") if isinstance(entry.get("reason"), str) else None,
            "optional": entry.get("required") is False,
            "details": details,
        })
    return out


# ---------------------------------------------------------------- model

def latest_stable(plugin: dict):
    stable = [r for r in plugin.get("releases", []) if r.get("stream") == "stable"]
    return max(stable, key=lambda r: r.get("publishedAt", ""), default=None)


def source_repo(plugin: dict):
    for release in sorted(plugin.get("releases", []), key=lambda r: r.get("publishedAt", ""), reverse=True):
        match = re.match(r"^https://github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)/releases/", release.get("bundle", {}).get("url", ""))
        if match:
            return f"https://github.com/{match.group(1)}/{match.group(2)}"
    return None


def unique_releases(plugin: dict) -> list:
    seen = set()
    out = []
    for r in sorted(plugin.get("releases", []), key=lambda r: r.get("publishedAt", ""), reverse=True):
        key = (r.get("version"), r.get("stream"), r.get("bundle", {}).get("sha256"))
        if key not in seen:
            seen.add(key)
            out.append(r)
    return out


def plugin_permissions(plugin: dict, registry: dict, bundles: dict):
    """(permissions, note): the permissions of the newest stable bundle, or why they are not shown."""
    release = latest_stable(plugin)
    if release is None:
        return None, "No stable release yet, so droidtop does not offer this plugin and there are no permissions to show."
    bundle = release.get("bundle", {})
    url = bundle.get("url", "")
    try:
        if url not in bundles:
            bundles[url] = fetch(url, MAX_BUNDLE)
        data = bundles[url]
        if hashlib.sha256(data).hexdigest() != str(bundle.get("sha256", "")).lower():
            return None, "The bundle on the release no longer matches the catalog's hash, so its permissions are not shown until the catalog is rebuilt."
        manifest_bytes = read_manifest(data)
        if hashlib.sha256(manifest_bytes).hexdigest() != str(release.get("manifestSha256", "")).lower():
            return None, "The bundle's manifest does not match the catalog's hash, so its permissions are not shown."
        manifest = json.loads(manifest_bytes.decode("utf-8"))
        return describe_permissions(manifest, registry), None
    except Exception as error:  # noqa: BLE001 - said on the page and in the build log, never guessed
        print(f"::warning::permissions of {plugin.get('id')} not read: {error}", file=sys.stderr)
        return None, "Its permissions could not be read when this page was built. droidtop shows them before you approve the plugin."


# ---------------------------------------------------------------- html

def short_date(iso: str) -> str:
    return iso[:10] if iso else ""


def size_text(size) -> str:
    if not isinstance(size, int) or size <= 0:
        return ""
    return f"{size / 1024:.0f} KB" if size < 1024 * 1024 else f"{size / 1024 / 1024:.1f} MB"


def safe_https(url) -> str | None:
    return url if isinstance(url, str) and url.startswith("https://") and " " not in url and '"' not in url else None


def add_link(link_host: str, address: str) -> str:
    return f"{link_host}/add-catalog?address={urllib.parse.quote(address, safe='')}"


def install_link(link_host: str, address: str, plugin_id: str) -> str:
    return f"{link_host}/install-plugin?catalog={urllib.parse.quote(address, safe='')}&id={urllib.parse.quote(plugin_id, safe='')}"


def render_permissions(perms) -> str:
    if not perms:
        return "<p>It asks for no permissions.</p>"
    rows = []
    for p in perms:
        css, word = p["tier"]
        extra = "".join(f'<span class="detail">{e(k)}: {e(", ".join(v))}</span>' for k, v in p["details"])
        rows.append(
            f'<li class="perm {css}"><div class="perm-head"><span class="tier">{e(word)}</span>'
            f'<strong>{e(p["label"])}</strong>' + ('<span class="opt">Optional</span>' if p["optional"] else "") + "</div>"
            + (f'<p class="why">{e(p["reason"])}</p>' if p["reason"] else "")
            + (f'<p class="caution">{e(p["caution"])}</p>' if p["caution"] else "")
            + (f'<p class="details">{extra}</p>' if extra else "")
            + "</li>"
        )
    return '<ul class="perms">' + "".join(rows) + "</ul>"


def signature_text(index: dict, origin: dict, official: bool) -> str:
    catalog = index.get("catalog") or {}
    key = origin.get("key") or {}
    fingerprint = key.get("keySha256", "")
    if official:
        how = ("Certified by droidtop's plugin master. The catalog lists a bundle only when its certificate from that master "
               "and its signature both verify.")
    elif catalog.get("origin") and origin.get("origin") == catalog.get("origin"):
        how = ("Certified by this catalog's own master key. The catalog lists a bundle only when its certificate from that key "
               "and its signature both verify. This key is not droidtop's.")
    else:
        how = ("Signed by the publisher's own key, which the plugin's repository publishes and this catalog accepted. "
               "droidtop trusts that key only if you accept this catalog. It is not droidtop's key.")
    return (f"<p>{e(how)}</p><p>Publisher <strong>{e(origin.get('origin', ''))}</strong>, key fingerprint (SHA-256) "
            f"<code>{e(fingerprint)}</code>.</p>")


def render_plugin(index: dict, origin: dict, plugin: dict, perms, perm_note, official: bool, address: str, link_host: str) -> str:
    pid = plugin.get("id", "")
    latest = latest_stable(plugin)
    chip = '<span class="chip official">Official</span>' if official else '<span class="chip unofficial">Unofficial</span>'
    repo = source_repo(plugin)
    meta = f'<code>{e(pid)}</code> &middot; publisher <strong>{e(origin.get("origin", ""))}</strong> &middot; '
    meta += f"stable {e(latest['version'])}" if latest else "no stable release yet"
    actions = []
    if latest and PLUGIN_ID.match(pid):
        actions.append(f'<a class="btn primary" href="{e(install_link(link_host, address, pid))}">Install in droidtop</a>')
    if repo:
        actions.append(f'<a class="btn" href="{e(repo)}">Source</a>')
    releases = unique_releases(plugin)
    rows = "".join(
        f"<tr><td>{e(str(r.get('version', '')))}</td>"
        f"<td>{'Stable' if r.get('stream') == 'stable' else 'Testing'}</td>"
        f"<td>{e(short_date(r.get('publishedAt', '')))}</td><td>{e(size_text(r.get('bundle', {}).get('size')))}</td></tr>"
        for r in releases
    )
    bundle_hash = latest["bundle"].get("sha256", "") if latest else ""
    perm_html = render_permissions(perms) if perms is not None else f"<p>{e(perm_note or '')}</p>"
    count = f" ({len(perms)})" if perms is not None else ""
    anchor = "p-" + re.sub(r"[^A-Za-z0-9_-]", "-", pid)
    return f"""<article class="plugin" id="{e(anchor)}">
<header><h2>{e(plugin.get('label', pid))}</h2>{chip}</header>
<p class="meta">{meta}</p>
<p class="desc">{e(plugin.get('description') or 'No description.')}</p>
<p class="actions">{''.join(actions)}</p>
<details><summary>Permissions{count}</summary>{perm_html}</details>
<details><summary>Versions and channels</summary>
<table><thead><tr><th>Version</th><th>Channel</th><th>Published</th><th>Size</th></tr></thead><tbody>{rows}</tbody></table>
<p class="note">Stable is what droidtop offers. Testing builds are listed for the record and are not offered.</p></details>
<details><summary>Signature</summary>{signature_text(index, origin, official)}
{f'<p>Bundle SHA-256 <code>{e(bundle_hash)}</code>, checked against this catalog when the page was built.</p>' if bundle_hash and perms is not None else ''}
<p class="note">droidtop checks the signature and every file again on your device, and the plugin runs only after you approve it.</p></details>
</article>"""


def render_catalog(index: dict, address: str, registry: dict, signature: str, now: datetime.datetime, link_host: str) -> str:
    catalog = index.get("catalog")
    official = catalog is None
    name = "droidtop plugins" if official else catalog.get("name", "Catalog")
    bundles: dict = {}
    cards = []
    plugins = [(o, p) for o in index["origins"] for p in o.get("plugins", [])]
    for origin, plugin in sorted(plugins, key=lambda op: op[1].get("label", "").lower()):
        perms, note = plugin_permissions(plugin, registry, bundles)
        cards.append(render_plugin(index, origin, plugin, perms, note, official, address, link_host))
    disclaimer = index.get("disclaimer") or {}
    banner = ""
    if not official:
        banner = (f'<aside class="disclaimer" role="note"><p class="label"><span class="chip unofficial">Unofficial</span> '
                  f"This catalog is not part of droidtop</p><p>{e(disclaimer.get('text', 'This catalog is unofficial and is not part of droidtop.'))}</p></aside>")
    if official:
        intro = ("The plugins droidtop itself offers under Settings &gt; Plugins &gt; Add. Each is published by the droidtop project "
                 "and certified by droidtop's plugin key. A plugin runs only after you approve it, and you see every permission it asks for first.")
        top_button = f'<a class="btn primary" href="{e(add_link(link_host, address))}">Open this catalog in droidtop</a>'
    else:
        intro = ("Plugins from the people named below, listed here so they can be installed in droidtop. droidtop shows this catalog's "
                 "notice and asks you before it adds anything, and a plugin runs only after you approve it.")
        top_button = f'<a class="btn primary" href="{e(add_link(link_host, address))}">Add this catalog to droidtop</a>'
    homepage = safe_https(catalog.get("homepage")) if catalog else None
    key = (catalog or {}).get("key") or {}
    about = [f"<dt>Catalog address</dt><dd><code>{e(address)}</code></dd>"]
    if homepage:
        about.append(f'<dt>Home</dt><dd><a href="{e(homepage)}">{e(homepage)}</a></dd>')
    about.append(f"<dt>Index made</dt><dd>{e(index.get('generatedAt', 'unknown'))}</dd>")
    about.append("<dt>Index signature</dt><dd>" + {
        "published": "A signature is published beside the index. droidtop checks it when you add the catalog and refuses an unsigned or altered copy afterwards.",
        "none": "None is published beside the index, so droidtop can only check that it came from this address.",
    }.get(signature, "Could not be checked when this page was built.") + "</dd>")
    if key.get("keySha256"):
        about.append(f"<dt>Catalog master key</dt><dd><code>{e(key['keySha256'])}</code></dd>")
    for origin in index["origins"]:
        fp = (origin.get("key") or {}).get("keySha256", "")
        about.append(f"<dt>Publisher {e(origin.get('origin', ''))}</dt><dd><code>{e(fp)}</code></dd>")
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{e(name)}</title>
<meta name="description" content="{e(intro.replace('&gt;', '>')[:200])}">
<link rel="stylesheet" href="style.css">
</head>
<body>
{banner}
<header class="top"><div class="wrap">
<p class="eyebrow">droidtop plugin catalog</p>
<h1>{e(name)} {'<span class="chip official">Official</span>' if official else '<span class="chip unofficial">Unofficial</span>'}</h1>
<p class="intro">{intro}</p>
<p class="actions">{top_button}</p>
<p class="note">The buttons open droidtop on an Android device. Nothing is added or installed until you confirm it in the app.</p>
</div></header>
<main class="wrap">
<p class="legend">Permissions: <span class="tier normal">Normal</span> ones are granted when you approve a plugin; <span class="tier sensitive">Sensitive</span> and <span class="tier critical">Critical</span> ones are asked about separately.</p>
<div class="grid">
{chr(10).join(cards) if cards else '<p>Nothing is listed yet.</p>'}
</div>
<section class="about"><h2>About this catalog</h2><dl>{''.join(about)}</dl></section>
</main>
<footer class="wrap"><p>Page built {e(now.strftime('%Y-%m-%d %H:%M'))} UTC from the catalog's index.json. GPL-3.0.</p></footer>
</body>
</html>
"""


def render_forward(mode: str) -> str:
    with open(os.path.join(STATIC, "forward.html"), encoding="utf-8") as handle:
        template = handle.read()
    title = "Add a catalog to droidtop" if mode == "add-catalog" else "Install a plugin in droidtop"
    return template.replace("{{MODE}}", mode).replace("{{TITLE}}", title)


def build(args) -> None:
    index = parse_index(read_source(args.index, MAX_INDEX))
    registry = parse_registry(read_source(args.registry, MAX_REGISTRY).decode("utf-8"))
    signature = index_signature(args.index)
    now = datetime.datetime.now(datetime.timezone.utc)
    page = render_catalog(index, args.address, registry, signature, now, args.link_host.rstrip("/"))
    os.makedirs(args.out, exist_ok=True)
    with open(os.path.join(args.out, "index.html"), "w", encoding="utf-8") as handle:
        handle.write(page)
    shutil.copy(os.path.join(STATIC, "style.css"), os.path.join(args.out, "style.css"))
    open(os.path.join(args.out, ".nojekyll"), "w").close()
    if args.forward_pages:
        shutil.copy(os.path.join(STATIC, "link.js"), os.path.join(args.out, "link.js"))
        for mode in ("add-catalog", "install-plugin"):
            os.makedirs(os.path.join(args.out, mode), exist_ok=True)
            with open(os.path.join(args.out, mode, "index.html"), "w", encoding="utf-8") as handle:
                handle.write(render_forward(mode))


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--index", required=True)
    parser.add_argument("--address", required=True, help="the catalog address the buttons give droidtop")
    parser.add_argument("--registry", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--link-host", default=LINK_HOST)
    parser.add_argument("--forward-pages", action="store_true", help="also write /add-catalog and /install-plugin (droidtop.github.io only)")
    args = parser.parse_args(argv)
    if not args.address.startswith("https://"):
        parser.error("--address must be an https address")
    build(args)
    return 0


if __name__ == "__main__":
    sys.exit(main())
