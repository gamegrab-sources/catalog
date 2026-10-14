"use strict";
// node --test generator/test_link.js
const test = require("node:test");
const assert = require("node:assert");
const link = require("./static/link.js");

test("only https addresses without credentials pass", () => {
  assert.strictEqual(link.httpsAddress("https://github.com/gamegrab-sources/catalog"), "https://github.com/gamegrab-sources/catalog");
  assert.strictEqual(link.httpsAddress("  https://example.com/index.json "), "https://example.com/index.json");
  for (const bad of ["http://example.com/x", "javascript:alert(1)", "droidtop://add-catalog?address=x", "https://user:pw@example.com/x", "//example.com", "", null, undefined, "https://" + "a".repeat(2100) + ".com"]) {
    assert.strictEqual(link.httpsAddress(bad), null, String(bad));
  }
});

test("add-catalog builds an encoded droidtop link", () => {
  const r = link.parse("add-catalog", "?address=https%3A%2F%2Fgithub.com%2Fo%2Fc");
  assert.strictEqual(r.link, "droidtop://add-catalog?address=https%3A%2F%2Fgithub.com%2Fo%2Fc");
  assert.ok(link.parse("add-catalog", "?address=http%3A%2F%2Fx").error);
  assert.ok(link.parse("add-catalog", "").error);
  assert.ok(link.parse("add-catalog", "?address=javascript%3Aalert(1)").error);
});

test("an address cannot smuggle a second parameter", () => {
  const r = link.parse("add-catalog", "?address=" + encodeURIComponent("https://example.com/x&id=evil"));
  assert.strictEqual(r.link.split("?")[1].split("&").length, 1);
});

test("install-plugin needs a valid id and an https or absent catalog", () => {
  assert.strictEqual(link.parse("install-plugin", "?id=droidtop.retroarch").link, "droidtop://install-plugin?id=droidtop.retroarch");
  assert.strictEqual(
    link.parse("install-plugin", "?catalog=https%3A%2F%2Fexample.com%2Findex.json&id=a.b").link,
    "droidtop://install-plugin?catalog=https%3A%2F%2Fexample.com%2Findex.json&id=a.b",
  );
  assert.ok(link.parse("install-plugin", "?id=..%2F..%2Fx").error);
  assert.ok(link.parse("install-plugin", "?catalog=http%3A%2F%2Fx&id=a.b").error);
  assert.ok(link.parse("install-plugin", "").error);
});
