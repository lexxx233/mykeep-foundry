// gen.mjs — emits a Worker-produced tool.zip + ed25519 source signature into argv[2], so
// Foundry's Go consumer can prove it unpacks the hand-rolled zip and verifies the
// WebCrypto signature. Run: node cloudflare/interop/gen.mjs <outdir>
import { writeFileSync } from "node:fs";
import { join } from "node:path";
import { makeZip } from "../src/zip.js";
import { signSource, b64 } from "../src/sign.js";

const outdir = process.argv[2];
if (!outdir) {
  console.error("usage: gen.mjs <outdir>");
  process.exit(2);
}

const manifest = {
  name: "interop",
  version: "1.0.0",
  description: "interop fixture",
  capabilities: { storage: { namespace: "interop" } },
};
const source = `async function run(input){ return "hi " + input.name; }`;
const canonicalManifest = JSON.stringify(manifest);

const { publicKey, privateKey } = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
const rawPub = new Uint8Array(await crypto.subtle.exportKey("raw", publicKey));
const { sig } = await signSource(privateKey, manifest.name, manifest.version, source);
const zip = makeZip([
  ["manifest.json", canonicalManifest],
  ["tool.js", source],
]);

writeFileSync(join(outdir, "tool.zip"), Buffer.from(zip));
writeFileSync(
  join(outdir, "meta.json"),
  JSON.stringify({
    pubkey_b64: b64(rawPub),
    source_sig_b64: b64(sig),
    name: manifest.name,
    version: manifest.version,
  })
);
console.log("ok");
