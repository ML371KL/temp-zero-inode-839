/**
 * The pipeline's envelope format, implemented once for the harness.
 *
 * The checks need to do two things the page cannot do for them: read the fixture, so
 * an assertion can be stated in terms of what the payload actually says rather than
 * in terms of numbers copied into the test; and write a new envelope, so a payload
 * with an impossible schema version or a poisoned string can be served to the same
 * page without a second fixture to keep in step.
 *
 * Deliberately WebCrypto and zlib rather than a library: this is the same AES-GCM,
 * the same PBKDF2 and the same gzip the browser does, so a mismatch here is a real
 * mismatch and not a difference between two implementations of the format.
 */

import { webcrypto } from "node:crypto";
import { gunzipSync, gzipSync } from "node:zlib";

// The pipeline's domain separator, byte for byte. Stated as a constant instead of
// being read out of the envelope for the same reason app.js states it: an envelope
// that vouches for its own AAD authenticates nothing.
export const AAD = "temp-zero-inode-839:portfolio:v1";

const encoder = new TextEncoder();

async function deriveKey(password, saltBase64, iterations, hash, usages) {
  const material = await webcrypto.subtle.importKey(
    "raw",
    encoder.encode(password),
    "PBKDF2",
    false,
    ["deriveKey"],
  );
  return webcrypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: Buffer.from(saltBase64, "base64"),
      iterations,
      hash,
    },
    material,
    { name: "AES-GCM", length: 256 },
    false,
    usages,
  );
}

export async function decryptEnvelope(envelope, password) {
  const key = await deriveKey(
    password,
    envelope.kdf.salt,
    envelope.kdf.iterations,
    envelope.kdf.hash,
    ["decrypt"],
  );
  const plain = await webcrypto.subtle.decrypt(
    {
      name: "AES-GCM",
      iv: Buffer.from(envelope.cipher.iv, "base64"),
      additionalData: encoder.encode(AAD),
      tagLength: 128,
    },
    key,
    Buffer.from(envelope.ciphertext, "base64"),
  );
  const body = Buffer.from(plain);
  return JSON.parse(
    String(envelope.compression || "none") === "gzip"
      ? gunzipSync(body).toString("utf8")
      : body.toString("utf8"),
  );
}

/**
 * Reseal a payload under the fixture's own key parameters.
 *
 * The salt and the iteration count are carried over from the source envelope so the
 * variant opens with the same password, and — more to the point — so the page's
 * "remember this device" key id (`salt:iterations:hash`) is the same one. A variant
 * with a fresh salt would silently exercise the key-miss path instead of whatever the
 * check meant to look at.
 */
export async function encryptEnvelope(source, payload, password) {
  const key = await deriveKey(
    password,
    source.kdf.salt,
    source.kdf.iterations,
    source.kdf.hash,
    ["encrypt"],
  );
  const iv = webcrypto.getRandomValues(new Uint8Array(12));
  // mtime 0 for the same reason the pipeline passes it: a gzip header carrying the
  // build time makes two otherwise identical bodies differ.
  const body = gzipSync(Buffer.from(JSON.stringify(payload), "utf8"), { mtime: 0 });
  const ciphertext = await webcrypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv,
      additionalData: encoder.encode(AAD),
      tagLength: 128,
    },
    key,
    body,
  );
  return {
    ...source,
    cipher: {
      ...source.cipher,
      iv: Buffer.from(iv).toString("base64"),
    },
    compression: "gzip",
    // Left deliberately stale. The page never verifies it — only the publication gate
    // in the private repository does — and a variant claiming a digest of a payload it
    // does not contain is a fair test that the page really does not care.
    ciphertext: Buffer.from(ciphertext).toString("base64"),
  };
}


/**
 * The live quote layer's envelope: AES-GCM under a raw key, with no KDF at all.
 *
 * The key is random and travels inside the payload, so there is nothing to derive
 * here — which is the whole point of the design: the browser gets the key only after
 * it has already opened the payload, and the quote agent that writes these objects
 * never holds the dashboard password.
 *
 * Its own AAD, deliberately different from the payload's. A scenario below serves a
 * payload envelope on this route to prove the page refuses it, and that refusal is
 * exactly what the separate domain buys.
 */
export const LIVE_QUOTES_AAD = "temp-zero-inode-839:quotes:v1";

export function liveQuotesKey() {
  return webcrypto.getRandomValues(new Uint8Array(32));
}

export async function encryptLiveQuotes(snapshot, rawKey, { aad = LIVE_QUOTES_AAD } = {}) {
  const key = await webcrypto.subtle.importKey(
    "raw", rawKey, { name: "AES-GCM" }, false, ["encrypt"],
  );
  const iv = webcrypto.getRandomValues(new Uint8Array(12));
  const body = gzipSync(Buffer.from(JSON.stringify(snapshot), "utf8"), { mtime: 0 });
  const ciphertext = await webcrypto.subtle.encrypt(
    { name: "AES-GCM", iv, additionalData: encoder.encode(aad), tagLength: 128 },
    key,
    body,
  );
  return {
    format: "ibkr-quotes-aes-gcm",
    version: 1,
    cipher: {
      name: "AES-GCM",
      iv: Buffer.from(iv).toString("base64"),
      aad: Buffer.from(aad, "utf8").toString("base64"),
    },
    compression: "gzip",
    ciphertext: Buffer.from(ciphertext).toString("base64"),
  };
}
