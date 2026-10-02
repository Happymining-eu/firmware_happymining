#!/usr/bin/env node
/*
 * Drives dashboard/static/seal.js under Node for test_seal_js.py. No npm package: WebCrypto is
 * globalThis.crypto.subtle.
 *
 * Reads one JSON object on standard input and writes one JSON object on standard output.
 *
 *   {"mode": "seal", "items": [{"public_key": "hmk1.…", "name": "…", "text": "…"}, …]}
 *     Each item seals "text" (a string, sealed as UTF-8), or "bytes_b64" (bytes), or "value" (any
 *     JSON value, to check what is refused). Answer: {"results": [{"ok": true, "sealed": "…"} or
 *     {"ok": false, "error": "…"}]}.
 *
 *   {"mode": "form", "forms": [{"key": "hmk1.…" or null, "fields": {name: {"type", "value"}},
 *                               "secrets": [{"value": "…", "attrs": {…}}]}]}
 *     Runs sealForm() on a minimal stand-in for a form element (the subset of the DOM seal.js
 *     uses). Answer: {"results": [{"ok", "error", "count", "fields": {name: value},
 *     "secrets": [value, …]}]}.
 */
"use strict";

const path = require("path");

const sealer = require(process.env.HM_SEAL_JS || path.resolve(__dirname, "../../../dashboard/static/seal.js"));

function fakeInput(type, value, attrs, name) {
  return {
    type,
    name: name || "",
    value,
    disabled: false,
    attrs: { ...(attrs || {}) },
    getAttribute(attribute) {
      return Object.prototype.hasOwnProperty.call(this.attrs, attribute) ? this.attrs[attribute] : null;
    },
  };
}

function fakeForm(spec) {
  const fields = {};
  for (const [name, field] of Object.entries(spec.fields || {})) {
    fields[name] = fakeInput(field.type || "hidden", field.value || "", {}, name);
  }
  const secrets = (spec.secrets || []).map((secret) => fakeInput("password", secret.value || "", secret.attrs));
  return {
    fields,
    secrets,
    elements: {
      namedItem(name) {
        return Object.prototype.hasOwnProperty.call(fields, name) ? fields[name] : null;
      },
    },
    getAttribute(attribute) {
      return attribute === "data-seal-key" ? spec.key || null : null;
    },
    querySelectorAll(selector) {
      if (selector !== "input[data-seal-target]") {
        throw new Error("unexpected selector " + selector);
      }
      return secrets.filter((input) => input.getAttribute("data-seal-target") !== null);
    },
  };
}

function plaintextOf(item) {
  if (Object.prototype.hasOwnProperty.call(item, "text")) {
    return item.text;
  }
  if (Object.prototype.hasOwnProperty.call(item, "bytes_b64")) {
    return new Uint8Array(Buffer.from(item.bytes_b64, "base64"));
  }
  return item.value;
}

async function sealItems(items) {
  const results = [];
  for (const item of items) {
    try {
      results.push({ ok: true, sealed: await sealer.seal(item.public_key, item.name, plaintextOf(item)) });
    } catch (error) {
      results.push({ ok: false, error: String(error && error.message ? error.message : error) });
    }
  }
  return results;
}

async function sealForms(forms) {
  const results = [];
  for (const spec of forms) {
    const form = fakeForm(spec);
    let ok = true;
    let error = "";
    let count = 0;
    try {
      count = await sealer.sealForm(form);
    } catch (problem) {
      ok = false;
      error = String(problem && problem.message ? problem.message : problem);
    }
    const fields = {};
    for (const [name, field] of Object.entries(form.fields)) {
      fields[name] = field.value;
    }
    results.push({ ok, error, count, fields, secrets: form.secrets.map((input) => input.value) });
  }
  return results;
}

async function main() {
  const chunks = [];
  for await (const chunk of process.stdin) {
    chunks.push(chunk);
  }
  const request = JSON.parse(Buffer.concat(chunks).toString("utf8"));
  let results;
  if (request.mode === "seal") {
    results = await sealItems(request.items);
  } else if (request.mode === "form") {
    results = await sealForms(request.forms);
  } else {
    throw new Error("unknown mode");
  }
  process.stdout.write(JSON.stringify({ results }));
}

main().catch((error) => {
  process.stderr.write(String(error && error.stack ? error.stack : error) + "\n");
  process.exit(1);
});
