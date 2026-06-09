<div align="center">

# 🧰 mykeep · Foundry

### A portable, local platform that gives any AI agent new tools — and the backend they run on.

**Status: v1 implemented.** A working Go implementation is in place — JS tools run in a
QuickJS-on-WASM sandbox (pure Go, zero CGo) with hard time/memory limits; an encrypted
backend (kv/queue/cache/blob); brokered, SSRF-guarded HTTP + Vault-by-reference; a
capability-grant model; an ed25519-signed marketplace with install-on-demand and a
Kimi-K2.6 AI exploit-review Worker; a two-plane REST API + hardened GUI; and suite
integration. Runs standalone or as the fourth component of the [mykeep](https://mykeep.ai) suite.

[mykeep.ai](https://mykeep.ai) · **Personal · Private · Portable**

</div>

---

Foundry is the **"do more"** component of [mykeep](https://mykeep.ai) — a portable suite of
local capabilities that any AI agent can plug into, all living on a USB stick. You bring the
agent (Claude Code, Cursor, anything with a fetch/shell tool); mykeep hands it foreign powers
it doesn't ship with — local, private, vendor-neutral, no install.

Where the **Capsule** makes an agent *know* you and **Vault** lets it *act as*
you, **Foundry** lets it *do more*: load plug-and-play skills and tools off the stick, and run
them on a backend that's already on the stick too.

## The problem

Agents are good at reasoning and short on capabilities. Today you bolt those on with cloud MCP
servers, per-host installs, or Docker — none of which fit "plug a stick into any machine and
go." And most tools need somewhere to keep state: a database, a queue, a cache, a blob store.
Making every tool bring its own backend is heavy and not portable.

## The idea: a backend-in-a-box for agent tools

Foundry is one local server that provides two things:

1. **A sandboxed tool runtime.** Tools and skills are loaded off the stick and run in a
   **WebAssembly sandbox** — via the pure-Go [wazero](https://github.com/tetratelabs/wazero)
   runtime, so there's no CGo and the same binary runs on Windows, macOS, and Linux.
   Untrusted code from a USB stick executes with only the capabilities you grant it. This is
   what makes "plug-and-play tools from a stick" both safe *and* portable in one move.

2. **The infrastructure those tools run on.** A small, encrypted, local substrate —
   **database, queue, cache, object storage** — exposed to tools as host functions, reusing
   the same encrypted SQLite store the Capsule is built on. Tools get persistence, work
   queues, and storage without a cloud or a second process.

A tool declares what it needs — network hosts, storage, a credential from Vault — and
you approve it once. Foundry enforces the grant.

## How an agent uses it

The same shape as the rest of mykeep: a **loopback REST API + a pasted guide** — the
zero-install floor that works with any agent that can make an HTTP call.

```
GET  /v1/foundry/guide          → the paste-able operating manual
GET  /v1/foundry/tools          → the catalog (each tool's name, description, params_schema)
POST /v1/foundry/tools/{name}   → run a granted tool; Foundry sandboxes it, brokers its
                                  capabilities, and returns the result
```

The agent (USE plane, `X-Foundry-Token`, loopback unless `--lan`) can list and run granted
tools but never install, grant, or author them — that's the human's control plane
(`/api/foundry/*`, loopback-only). A tool author writes JavaScript; the host functions are a
`foundry` global (`foundry.kv/queue/cache/blob`, `foundry.http.fetch`, `foundry.vault.fetch`,
`foundry.log`), each enforced in Go against the tool's grant.

No client configuration required. For hosts that want native tool-use, Foundry can *also*
present the same catalog over MCP — but that's an optional accelerator, never a requirement.
mykeep's rule: **REST + guide is the universal baseline; MCP, hooks, and SDKs are opt-in per
host.**

## Where it fits

Foundry composes with its siblings, all on the same stick, under one password:

- **[Capsule](https://github.com/lexxx233/mykeep-capsule)** — tools that need to
  remember read and write the agent's memory.
- **Vault** — tools that take authenticated actions get scoped, sealed credentials *by
  reference*; the raw key never enters the tool or the agent's context.

## Design principles

- **Portable first** — pure Go, zero CGo, one static binary, six targets. Lives on the stick
  beside its data; no host install.
- **Private by default** — everything sealed at rest with the suite's whole-DB AES-256-GCM
  encryption; no cloud round-trips.
- **The agent reasons, mykeep provides** — Foundry runs tools and infrastructure; it does no
  LLM reasoning of its own.
- **Capability-scoped** — tools get exactly the powers you grant, enforced by the sandbox.

## Build / run

```sh
go build ./cmd/foundry      # or: make build  ->  bin/foundry
go test ./...               # the Go suite
make guard                  # prove zero CGo in the dependency graph
make cross                  # cross-compile all six win/mac/linux × amd64/arm64 targets
./bin/foundry               # gui (default): first launch sets a password, then serves
./bin/foundry serve         # headless: unlock via $MYKEEP_FOUNDRY_PASSPHRASE / stdin
```

The marketplace edge (submission → Kimi-K2.6 review → sign → publish) lives in
`cloudflare/` and deploys with `wrangler` — see `cloudflare/README.md`. The Foundry binary
verifies every artifact against a **pinned** ed25519 registry key, so the service is a
convenience, not a trust root; AI review is defense-in-depth, never the sole control (the
WASM sandbox + capability grant + human consent are the floor).

---

<div align="center">
<sub>A component of <a href="https://mykeep.ai">mykeep</a> · Personal · Private · Portable · © 2026 Domu Inc</sub>
</div>
