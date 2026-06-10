<div align="center">

# 🧰 mykeep · Foundry

### A portable, local platform that gives any AI agent new tools — and the backend they run on.

![status](https://img.shields.io/badge/status-v1%20implemented-2ea043)
![pure Go · no CGo](https://img.shields.io/badge/pure%20Go-no%20CGo-00ADD8)
![sandbox](https://img.shields.io/badge/sandbox-QuickJS%20on%20WASM-654FF0)

[mykeep.ai](https://mykeep.ai) · **Secured · Private · Portable**

</div>

---

Foundry is the **"does more"** component of [mykeep](https://mykeep.ai). You bring the agent
(Claude Code, Cursor, anything with a fetch or shell tool); Foundry hands it powers it doesn't
ship with — load plug-and-play tools off the drive and run them on a backend that's already on
the drive too. Local, private, vendor-neutral, no install.

## The problem

Agents are good at reasoning and short on capabilities. Today you bolt those on with cloud MCP
servers, per-host installs, or Docker — none of which fit "plug a drive into any machine and go."
And most tools need somewhere to keep state: a database, a queue, a cache, a blob store. Making
every tool bring its own backend is heavy and not portable.

## The idea: a backend-in-a-box for agent tools

One local server providing two things:

1. **A sandboxed tool runtime.** Tools are JavaScript, compiled to QuickJS bytecode and run in a
   **WebAssembly sandbox** via the pure-Go [wazero](https://github.com/tetratelabs/wazero)
   runtime — no CGo, same binary on every OS, with hard time and memory limits. Untrusted code
   from a drive executes with only the capabilities you grant it.
2. **The infrastructure those tools run on.** A small, encrypted, local substrate — **database,
   queue, cache, object storage** — exposed to tools as host functions, reusing the same
   encrypted SQLite store Capsule is built on. Persistence without a cloud or a second process.

A tool *declares* what it needs — network hosts, storage, a credential from Vault — and you
approve it once. Foundry enforces the grant at every host-function boundary, in Go, never in JS.

## How an agent uses it

The same shape as the rest of mykeep: a **loopback REST API + a pasted guide.**

```
GET  /v1/foundry/guide          → the paste-able operating manual
GET  /v1/foundry/tools          → the catalog (each tool's name, description, params_schema)
POST /v1/foundry/tools/{name}   → run a granted tool; Foundry sandboxes it, brokers its
                                  capabilities, and returns the result
```

The agent (USE plane, `X-Foundry-Token`, loopback unless `--lan`) can list and run *granted*
tools — but never install, grant, or author them. That's the human's control plane
(`/api/foundry/*`, loopback-only). A tool author writes JavaScript against a `foundry` global
(`foundry.kv/queue/cache/blob`, `foundry.http.fetch`, `foundry.vault.fetch`, `foundry.log`),
each call enforced in Go against the tool's grant.

> For hosts that want native tool-use, Foundry can *also* present the same catalog over MCP — an
> optional accelerator, never a requirement. The rule: **REST + guide is the universal baseline;
> MCP, hooks, and SDKs are opt-in per host.**

## The marketplace

Anyone can publish. The registry signs **every** published tool (integrity + provenance); a tool
that clears an **AI exploit review** earns a **Verified** badge.

- `reject` → never published (the only hard block: malware / sandbox-escape)
- `flag` → published **unverified**, installable with a warning
- `pass` → published **verified**

The Foundry binary verifies every artifact against a **pinned** ed25519 registry key, so the
service is a convenience, not a trust root. AI review is defense-in-depth, never the sole
control — the WASM sandbox + capability grant + human consent are the floor. Browse published
tools at [the marketplace web app](https://github.com/lexxx233/mykeep-marketplace); the
submission edge (submit → review → sign → publish) lives in
[`cloudflare/`](cloudflare/README.md).

## Quick start

```sh
go build ./cmd/foundry      # or: make build  ->  bin/foundry

./bin/foundry               # GUI (default): first launch sets a password, then serves
./bin/foundry serve         # headless: unlock via MYKEEP_FOUNDRY_PASSPHRASE / stdin
```

| Make target | What it does |
|---|---|
| `go test ./...` | the Go suite |
| `make guard` | prove zero CGo in the dependency graph |
| `make cross` | all six win/mac/linux × amd64/arm64 targets |

## Design principles

- **Portable first** — pure Go, zero CGo, one static binary, six targets. Lives on the drive
  beside its data; no host install.
- **Private by default** — sealed at rest with the suite's whole-DB AES-256-GCM encryption; no
  cloud round-trips.
- **Capability-scoped** — tools get exactly the powers you grant, enforced by the sandbox.
- **The agent reasons, mykeep provides** — Foundry runs tools and infrastructure; it does no LLM
  reasoning of its own.

## Where it fits

Foundry is one of four mykeep components — all on one drive, under one password. Its tools that
need to remember read and write **Capsule**; its tools that take authenticated actions get
scoped, sealed credentials from **Vault** by reference (the raw key never enters the tool).

| | Component | Your agent can… |
|---|---|---|
| 🧠 | **[Capsule](https://github.com/lexxx233/mykeep-capsule)** | **know** you — encrypted, portable memory |
| 🔐 | **[Vault](https://github.com/lexxx233/mykeep-vault)** | **act as** you — a secrets broker that acts by reference |
| 🔮 | **[Showstone](https://github.com/lexxx233/mykeep-showstone)** | **see** the web — a contained browser it drives over REST |
| 🧰 | **Foundry** (this repo) | **do** more — sandboxed tools + the backend they run on |

---

<div align="center">
<sub>A component of <a href="https://mykeep.ai">mykeep</a> · Secured · Private · Portable · © 2026 Domu Inc</sub>
</div>
