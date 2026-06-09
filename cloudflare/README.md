# Foundry marketplace (Cloudflare)

The off-binary half of Foundry's open marketplace: a Cloudflare Worker that takes
third-party tool submissions, reviews them with **Kimi K2.6** on Workers AI, signs the
ones that pass with the registry's ed25519 key, and publishes them to a signed catalog in
R2. The Foundry binary installs from that catalog and verifies every signature against a
**pinned** public key (`internal/registry`), so this service is a *convenience*, not a
trust root — and the AI review is defense-in-depth, never the sole control.

## Pipeline

```
POST /v1/submit {manifest, source}
  → validate + size-cap + per-author daily rate-limit (D1) + content-hash dedupe
  → review (Kimi K2.6, @cf/moonshotai/kimi-k2.6, JSON-schema verdict)
      reject → stored, not published
      flag   → queued in D1 `flagged` for a human decision
      pass   → ed25519-sign (name|version|source-sha) → write tool.zip to R2
               → merge + re-sign v1/index.json → done
GET  /v1/index.json | /v1/index.json.sig | /v1/tools/.../tool.zip   (served from R2)
```

Defense-in-depth (no single gate): AI review at submission **+** registry signing **+** the
runtime WASM sandbox **+** capability grants **+** the human's install-time consent. A
`pass` means "we found nothing", not "safe to run unsupervised".

## One-time setup

```sh
cd cloudflare
npm i -g wrangler            # or: npx wrangler ...

# 1. R2 bucket (artifacts + signed index) and its custom domain (foundry.mykeep.ai)
wrangler r2 bucket create foundry-registry

# 2. D1 (rate-limit + flag queue)
wrangler d1 create foundry-marketplace          # paste the id into wrangler.jsonc
wrangler d1 execute foundry-marketplace --file schema.sql

# 3. The registry signing key (ed25519). Generate a 32-byte seed, keep the PUBLIC key to
#    pin into the binary (internal/registry registryPubKeys), and store the SEED as a secret:
wrangler secret put REGISTRY_SIGNING_KEY        # paste base64 of the 32-byte seed

# 4. Deploy
wrangler deploy
```

Generate a keypair (Go, so the public key drops straight into the binary):

```go
pub, priv, _ := ed25519.GenerateKey(rand.Reader)
fmt.Println("seed(base64):", base64.StdEncoding.EncodeToString(priv.Seed()))
fmt.Printf("pinned pubkey: %#v\n", []byte(pub))
```

## Signature compatibility

`src/sign.js` reproduces the Go verifier's framing exactly:
- **source signature** — ed25519 over `` `${name}\n${version}\n${sha256hex(source)}` `` (Go:
  `registry.signedMessage` / `sourceSHA256`).
- **index signature** — ed25519 over the exact `index.json` bytes served (Go:
  `verifyIndex` checks the raw fetched bytes).

The Go side already has tests that verify these signatures (`internal/registry`), so the
contract is validated from the consumer end; this Worker just produces matching bytes.

## Notes / production hardening (deferred)
- Split into submit/review/publish Workers + a queue if review latency or AI cost warrants
  (v1 runs the pipeline inline on the submit request).
- Hold the signing key offline and have it sign only the index, with a hot key for
  artifacts, once operational maturity warrants.
- Serve `index.json` + artifacts from the R2 **custom domain** (Cache-fronted), not the
  Worker, at scale; the Worker's `GET /v1/...` mirror is for a self-contained pipeline.
