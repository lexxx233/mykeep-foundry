// sign.js — ed25519 + SHA-256 helpers that MUST byte-match Foundry's Go verifier
// (internal/registry/sign.go, index.go). The Go side verifies:
//   source signature: ed25519 over  `${name}\n${version}\n${sourceSHAhex}`
//   index  signature: ed25519 over  the exact index.json bytes served
// so these helpers reproduce that framing exactly.

const enc = new TextEncoder();

// hex lowercase SHA-256, matching Go's sourceSHA256 / zipSHA256.
export async function sha256hex(bytes) {
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

// importPrivateKey loads the registry signing key from a Worker secret. The secret is the
// 32-byte ed25519 seed, base64-encoded (set with: wrangler secret put REGISTRY_SIGNING_KEY).
export async function importPrivateKey(seedB64) {
  const seed = Uint8Array.from(atob(seedB64), (c) => c.charCodeAt(0));
  // WebCrypto wants PKCS8; wrap the raw seed in the fixed Ed25519 PKCS8 prefix.
  const pkcs8 = new Uint8Array([
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70,
    0x04, 0x22, 0x04, 0x20, ...seed,
  ]);
  return crypto.subtle.importKey("pkcs8", pkcs8, { name: "Ed25519" }, false, ["sign"]);
}

async function sign(key, bytes) {
  const sig = await crypto.subtle.sign({ name: "Ed25519" }, key, bytes);
  return new Uint8Array(sig);
}

// signSource produces the per-artifact source signature the Go client re-verifies.
export async function signSource(key, name, version, source) {
  const sourceSHA = await sha256hex(enc.encode(source));
  const msg = enc.encode(`${name}\n${version}\n${sourceSHA}`);
  return { sig: await sign(key, msg), sourceSHA };
}

// signIndex signs the exact index bytes that will be served.
export async function signIndex(key, indexBytes) {
  return sign(key, indexBytes);
}

// b64 encodes bytes as base64 (Go unmarshals []byte JSON fields from base64).
export function b64(bytes) {
  let s = "";
  for (const byte of bytes) s += String.fromCharCode(byte);
  return btoa(s);
}
