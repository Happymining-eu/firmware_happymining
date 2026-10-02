/*
 * HappyMining OS: secrets are sealed in the browser, for one machine (docs/appliance.md, section 5).
 *
 *   public key = "hmk1." + base64url( uncompressed P-256 point, 65 bytes )
 *   blob       = "hmseal1." + base64url( ephemeral_public(65) || AES-256-GCM ciphertext || tag(16) )
 *   key        = HKDF-SHA256( ikm  = ECDH(ephemeral_private, machine_public) (32-byte x coordinate),
 *                             salt = ephemeral_public(65) || machine_public(65),
 *                             info = "happymining-seal-v1", length = 32 )
 *   nonce      = 12 zero bytes (each key is used once), AAD = the secret's name (UTF-8)
 *   plaintext  = 1 to 4096 bytes; names = ^[a-z][a-z0-9_.-]{0,62}$
 *
 * Reference implementation: api/happymining/sealing.py. Test: tests/appliance/seal_js/.
 *
 * On the appliance page a password field has no name attribute: without this script nothing
 * secret is ever submitted. When its form is submitted, each filled password field is sealed with
 * the machine's public key (the form's data-seal-key) under the exact name the server stores the
 * secret as (the field's data-seal-name; or data-seal-name-template with "{id}" replaced by the
 * value of the form field named in data-seal-name-field), the sealed value is put into the hidden
 * input named in data-seal-target, and the password field is cleared. The server accepts sealed
 * values only (sealing.check_sealed); it cannot open them.
 *
 * Loaded as a classic script by the page (the Content-Security-Policy allows scripts from this
 * origin only, so there is no inline script and no inline handler), and as a CommonJS module by the
 * Node test. Uses WebCrypto only.
 */
(function (root, factory) {
  "use strict";
  var api = factory(root);
  if (typeof module === "object" && module && module.exports) {
    module.exports = api;
  } else {
    root.HappyMiningSeal = api;
  }
  if (typeof document !== "undefined" && document && typeof document.addEventListener === "function") {
    api.install(document);
  }
})(typeof globalThis !== "undefined" ? globalThis : this, function (root) {
  "use strict";

  var SEAL_PREFIX = "hmseal1.";
  var KEY_PREFIX = "hmk1.";
  var INFO = "happymining-seal-v1";
  var POINT_LEN = 65;
  var MAX_SECRET_BYTES = 4096;
  var NAME_RE = /^[a-z][a-z0-9_.-]{0,62}$/;
  var ID_RE = /^[a-z][a-z0-9-]{0,30}$/;
  var B64URL_RE = /^[A-Za-z0-9_-]+$/;

  function SealError(message) {
    var error = new Error(message);
    error.name = "SealError";
    return error;
  }

  function subtle() {
    var c = root.crypto;
    if (!c || !c.subtle) {
      throw SealError(
        "This browser cannot encrypt on this page: WebCrypto is only available over HTTPS. " +
          "Nothing was sent."
      );
    }
    return c.subtle;
  }

  function utf8(text) {
    return new TextEncoder().encode(text);
  }

  function concat(a, b) {
    var out = new Uint8Array(a.length + b.length);
    out.set(a, 0);
    out.set(b, a.length);
    return out;
  }

  function b64urlEncode(bytes) {
    var binary = "";
    for (var i = 0; i < bytes.length; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  function b64urlDecode(text) {
    if (typeof text !== "string" || !B64URL_RE.test(text) || text.length % 4 === 1) {
      throw SealError("not base64url");
    }
    var padded = text.replace(/-/g, "+").replace(/_/g, "/");
    while (padded.length % 4 !== 0) {
      padded += "=";
    }
    var binary = atob(padded);
    var out = new Uint8Array(binary.length);
    for (var i = 0; i < binary.length; i++) {
      out[i] = binary.charCodeAt(i);
    }
    return out;
  }

  /** The 65 bytes of a machine's sealing key ("hmk1." + base64url of an uncompressed point). */
  function parsePublicKey(value) {
    var raw;
    try {
      if (typeof value !== "string" || value.indexOf(KEY_PREFIX) !== 0) {
        throw SealError("prefix");
      }
      raw = b64urlDecode(value.slice(KEY_PREFIX.length));
    } catch (_) {
      throw SealError("not a valid machine sealing key");
    }
    if (raw.length !== POINT_LEN || raw[0] !== 0x04) {
      throw SealError("not a valid machine sealing key");
    }
    return raw;
  }

  function plaintextBytes(plaintext) {
    var data;
    if (typeof plaintext === "string") {
      data = utf8(plaintext);
    } else if (plaintext instanceof Uint8Array) {
      data = plaintext;
    } else {
      throw SealError("a secret is text or bytes");
    }
    if (data.length < 1 || data.length > MAX_SECRET_BYTES) {
      throw SealError("a secret is 1 to " + MAX_SECRET_BYTES + " bytes (UTF-8)");
    }
    return data;
  }

  /**
   * Seal `plaintext` (a string, sealed as UTF-8, or a Uint8Array) under `name` for the machine
   * whose public key is `publicKey`. Resolves to "hmseal1.…". Rejects with a SealError, and seals
   * nothing, when the name, the secret or the key is not acceptable.
   */
  async function seal(publicKey, name, plaintext) {
    if (typeof name !== "string" || !NAME_RE.test(name)) {
      throw SealError("secret names are lower-case letters, digits, dot, dash and underscore");
    }
    var data = plaintextBytes(plaintext);
    var machineRaw = parsePublicKey(publicKey);
    var s = subtle();
    var machineKey;
    try {
      // Refused here when the point is not on the curve.
      machineKey = await s.importKey("raw", machineRaw, { name: "ECDH", namedCurve: "P-256" }, false, []);
    } catch (_) {
      throw SealError("not a valid machine sealing key");
    }
    var ephemeral = await s.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
    var ephemeralRaw = new Uint8Array(await s.exportKey("raw", ephemeral.publicKey));
    var shared = await s.deriveBits({ name: "ECDH", public: machineKey }, ephemeral.privateKey, 256);
    var hkdf = await s.importKey("raw", shared, "HKDF", false, ["deriveKey"]);
    var key = await s.deriveKey(
      { name: "HKDF", hash: "SHA-256", salt: concat(ephemeralRaw, machineRaw), info: utf8(INFO) },
      hkdf,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt"]
    );
    var sealed = new Uint8Array(
      await s.encrypt(
        { name: "AES-GCM", iv: new Uint8Array(12), additionalData: utf8(name), tagLength: 128 },
        key,
        data
      )
    );
    return SEAL_PREFIX + b64urlEncode(concat(ephemeralRaw, sealed));
  }

  // --- the forms of the appliance page -----------------------------------------------------

  function namedField(form, name) {
    if (!name || !form.elements || typeof form.elements.namedItem !== "function") {
      return null;
    }
    return form.elements.namedItem(name);
  }

  /** The name the server stores this field's secret under. */
  function secretName(form, input) {
    var fixed = input.getAttribute("data-seal-name");
    if (fixed) {
      return fixed;
    }
    var template = input.getAttribute("data-seal-name-template");
    var fieldName = input.getAttribute("data-seal-name-field");
    if (template && fieldName) {
      var field = namedField(form, fieldName);
      var id = field && typeof field.value === "string" ? field.value.trim() : "";
      if (!ID_RE.test(id)) {
        throw SealError(
          "Enter a valid id first (a lower-case letter, then lower-case letters, digits or -): " +
            "the secret is sealed under a name that contains it. Nothing was sent."
        );
      }
      return template.split("{id}").join(id);
    }
    throw SealError("This field does not say which secret it is. Nothing was sent.");
  }

  function sealTargets(form) {
    return Array.prototype.slice.call(form.querySelectorAll("input[data-seal-target]"));
  }

  /**
   * Seal every filled secret field of `form` into its hidden input and clear the field.
   * Resolves to the number of secrets sealed. On any problem every hidden secret input is left
   * empty, no field is cleared, and the promise rejects: the form must not be submitted then.
   */
  async function sealForm(form) {
    var key = form.getAttribute("data-seal-key") || "";
    var inputs = sealTargets(form);
    var jobs = [];
    var targets = [];
    function emptyAll() {
      targets.forEach(function (target) {
        target.value = "";
      });
    }
    // First every hidden input that receives a secret is emptied, so that nothing stale or
    // half-done can be submitted whatever goes wrong afterwards.
    inputs.forEach(function (input) {
      var target = namedField(form, input.getAttribute("data-seal-target"));
      if (target && target.type === "hidden") {
        targets.push(target);
      }
    });
    emptyAll();
    try {
      inputs.forEach(function (input) {
        var target = namedField(form, input.getAttribute("data-seal-target"));
        if (!target || target.type !== "hidden") {
          throw SealError("This form is missing the field a sealed secret goes into. Nothing was sent.");
        }
        if (input.value === "") {
          return; // left empty: the server keeps what it has
        }
        if (!key) {
          throw SealError(
            "The machine has not reported its sealing key yet, so no secret can be sent. Nothing was sent."
          );
        }
        jobs.push({ input: input, target: target, name: secretName(form, input) });
      });
      for (var i = 0; i < jobs.length; i++) {
        jobs[i].target.value = await seal(key, jobs[i].name, jobs[i].input.value);
      }
    } catch (error) {
      emptyAll();
      throw error;
    }
    jobs.forEach(function (job) {
      job.input.value = "";
    });
    return jobs.length;
  }

  function showError(form, message) {
    var box = form.querySelector("[data-seal-error]");
    if (!box) {
      return;
    }
    box.textContent = message;
    if (message) {
      box.removeAttribute("hidden");
    } else {
      box.setAttribute("hidden", "");
    }
  }

  function attach(form) {
    var busy = false;
    if (typeof root.addEventListener === "function") {
      // A page restored from the back/forward cache may be submitted again.
      root.addEventListener("pageshow", function () {
        busy = false;
      });
    }
    form.addEventListener("submit", function (event) {
      event.preventDefault();
      if (busy) {
        return;
      }
      busy = true;
      showError(form, "");
      sealForm(form).then(
        function () {
          // The submit event is not fired again by this call.
          HTMLFormElement.prototype.submit.call(form);
        },
        function (error) {
          busy = false;
          showError(form, error && error.message ? error.message : "The secret could not be sealed.");
        }
      );
    });
  }

  function install(doc) {
    function ready() {
      var forms = Array.prototype.slice.call(doc.querySelectorAll("form"));
      forms.forEach(function (form) {
        if (!form.querySelector("input[data-seal-target]")) {
          return;
        }
        if (!root.crypto || !root.crypto.subtle) {
          sealTargets(form).forEach(function (input) {
            input.disabled = true;
          });
          showError(form, "Secrets can only be entered over HTTPS: this browser offers no WebCrypto here.");
        }
        attach(form);
      });
    }
    if (doc.readyState === "loading") {
      doc.addEventListener("DOMContentLoaded", ready);
    } else {
      ready();
    }
  }

  return {
    seal: seal,
    sealForm: sealForm,
    secretName: secretName,
    parsePublicKey: parsePublicKey,
    install: install,
    SEAL_PREFIX: SEAL_PREFIX,
    MAX_SECRET_BYTES: MAX_SECRET_BYTES,
  };
});
