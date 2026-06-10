# Foundry marketplace (Cloudflare)

The off-binary half of Foundry's open marketplace: a Cloudflare Worker that takes
third-party tool submissions, runs them through an **AI exploit review** (Workers AI, model
chosen at deploy time — see below), signs them with the registry's ed25519 key, and publishes
them to a signed catalog in R2. The Foundry binary installs from that catalog and verifies every signature against a
**pinned** public key (`internal/registry`), so this service is a *convenience*, not a
trust root — and the AI review is defense-in-depth, never the sole control.

## Pipeline

```
POST /v1/submit {manifest, source}
  → validate + size-cap + per-author daily rate-limit (D1) + content-hash dedupe
  → AI exploit review (Workers AI, REVIEW_MODEL, JSON-schema verdict)
      reject → stored, NEVER published     (malware / sandbox-escape — the only hard block)
      flag   → published UNVERIFIED + queued in D1 `flagged` for a human  (installable, warned)
      pass   → published VERIFIED
      (publish = ed25519-sign (name|version|source-sha) → write tool.zip to R2
               → merge + re-sign v1/index.json → regenerate v1/catalog.json → done)
GET  /v1/index.json | /v1/index.json.sig | /v1/catalog.json | /v1/tools/.../tool.zip   (R2)
```

**Open submission.** Anyone can publish. The registry signs *every* published tool
(integrity + provenance); `verified` is separate metadata recording whether AI review
passed. Rejected submissions (malware) are never published; flagged ones publish as
**unverified** and are installable with a warning. `verified` only changes the badge — never
installability. The runtime triad (sandbox + grants + human consent) is the safety floor for
every published tool; a `pass` means "we found nothing", not "safe to run unsupervised".

`v1/catalog.json` is the human-readable companion the browse web app
(`lexxx233/mykeep-marketplace`) reads — derived from the same signed index, so the badge it
shows can't drift from what the binary installs.

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

# 4. The review model id — kept out of public source so it isn't handed to attackers.
#    Set it as a secret (any Workers-AI model id); review.js falls back to a generic
#    default if unset.
wrangler secret put REVIEW_MODEL                # e.g. a Workers-AI model id

# 5. Deploy
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
