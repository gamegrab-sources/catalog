"use strict";
// The link pages (/add-catalog, /install-plugin): validate what the link carries, then offer
// "Open in droidtop" and "Copy address". The page only forwards; the review and its Accept are in the app.
(function (root) {
  var MAX = 2048;
  var ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;

  // A catalog address: an https URL with a host and no embedded credentials. Anything else is null.
  function httpsAddress(value) {
    if (typeof value !== "string") return null;
    var text = value.trim();
    if (text.length === 0 || text.length > MAX) return null;
    var url;
    try { url = new URL(text); } catch (error) { return null; }
    if (url.protocol !== "https:" || !url.hostname || url.username || url.password) return null;
    return url.href;
  }

  function pluginId(value) {
    return typeof value === "string" && ID.test(value) ? value : null;
  }

  function addCatalogLink(address) {
    return "droidtop://add-catalog?address=" + encodeURIComponent(address);
  }

  function installPluginLink(address, id) {
    return "droidtop://install-plugin?" + (address ? "catalog=" + encodeURIComponent(address) + "&" : "") + "id=" + encodeURIComponent(id);
  }

  // What a page URL's query asks for: {mode, address, id, link} or {mode, error}.
  function parse(mode, search) {
    var params = new URLSearchParams(search);
    if (mode === "add-catalog") {
      var address = httpsAddress(params.get("address") || params.get("url"));
      if (!address) return { mode: mode, error: "This is not a catalog link: it has no https catalog address." };
      return { mode: mode, address: address, link: addCatalogLink(address) };
    }
    var id = pluginId(params.get("id"));
    if (!id) return { mode: mode, error: "This is not a plugin link: it names no valid plugin." };
    var raw = params.get("catalog");
    var catalog = null;
    if (raw !== null && raw !== "") {
      catalog = httpsAddress(raw);
      if (!catalog) return { mode: mode, error: "This is not a plugin link: its catalog address is not an https address." };
    }
    return { mode: mode, address: catalog, id: id, link: installPluginLink(catalog, id) };
  }

  var api = { httpsAddress: httpsAddress, pluginId: pluginId, addCatalogLink: addCatalogLink, installPluginLink: installPluginLink, parse: parse };
  if (typeof module !== "undefined" && module.exports) { module.exports = api; return; }

  function el(name, className, text) {
    var node = document.createElement(name);
    if (className) node.className = className;
    if (text !== undefined) node.textContent = text;
    return node;
  }

  function show() {
    var app = document.getElementById("app");
    var mode = document.body.getAttribute("data-mode");
    var result = parse(mode, window.location.search);
    app.textContent = "";
    if (result.error) {
      app.appendChild(el("p", "error", result.error));
      app.appendChild(el("p", "note", "Nothing was done. Ask whoever sent you the link for a new one."));
      return;
    }
    var panel = el("div", "panel");
    if (mode === "install-plugin") {
      panel.appendChild(el("p", "", "Plugin: " + result.id));
      panel.appendChild(el("p", "note", result.address ? "From the catalog below." : "From droidtop's own catalog."));
    } else {
      panel.appendChild(el("p", "", "A catalog is asking to be added to droidtop. droidtop shows its notice and asks you before it adds anything."));
    }
    if (result.address) {
      var label = el("label", "", "Catalog address");
      label.setAttribute("for", "address");
      var input = el("input");
      input.id = "address";
      input.readOnly = true;
      input.value = result.address;
      panel.appendChild(label);
      panel.appendChild(input);
    }
    var actions = el("p", "actions");
    var open = el("a", "btn primary", mode === "install-plugin" ? "Open in droidtop" : "Open in droidtop");
    open.href = result.link;
    actions.appendChild(open);
    var status = el("p", "note");
    status.setAttribute("role", "status");
    if (result.address) {
      var copy = el("button", "btn", "Copy address");
      copy.type = "button";
      copy.addEventListener("click", function () {
        var done = function () { status.textContent = "Copied."; };
        var fallback = function () {
          var field = document.getElementById("address");
          field.focus();
          field.select();
          try { status.textContent = document.execCommand("copy") ? "Copied." : "Select the address above and copy it."; }
          catch (error) { status.textContent = "Select the address above and copy it."; }
        };
        if (navigator.clipboard && navigator.clipboard.writeText) navigator.clipboard.writeText(result.address).then(done, fallback);
        else fallback();
      });
      actions.appendChild(copy);
    }
    panel.appendChild(actions);
    panel.appendChild(status);
    app.appendChild(panel);
    app.appendChild(el("p", "note", "Nothing happens when you press Open in droidtop? Then droidtop is not installed on this device. It is an Android app."
      + (result.address ? " You can copy the address and paste it under Settings > Plugins > Add > More catalogs." : "")));
  }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", show); else show();
})(this);
