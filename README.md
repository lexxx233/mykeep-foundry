<div align="center">

# 🧰 mykeep · Foundry

### A portable, local platform that gives any AI agent new tools — and the backend they run on.

**Status: vision / design.** No code yet — this repo holds the design while the
[Memory Capsule](https://github.com/lexxx233/mykeep-memory-capsule) (component #1) ships.

[mykeep.ai](https://mykeep.ai) · **Personal · Private · Portable**

</div>

---

Foundry is the **"do more"** component of [mykeep](https://mykeep.ai) — a portable suite of
local capabilities that any AI agent can plug into, all living on a USB stick. You bring the
agent (Claude Code, Cursor, anything with a fetch/shell tool); mykeep hands it foreign powers
it doesn't ship with — local, private, vendor-neutral, no install.

Where the **Memory Capsule** makes an agent *know* you and **SecretVault** lets it *act as*
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
   the same encrypted SQLite store the Memory Capsule is built on. Tools get persistence, work
   queues, and storage without a cloud or a second process.

A tool declares what it needs — network hosts, storage, a credential from SecretVault — and
you approve it once. Foundry enforces the grant.

## How an agent uses it

The same shape as the rest of mykeep: a **loopback REST API + a pasted guide** — the
zero-install floor that works with any agent that can make an HTTP call.

```
GET  /v1/tools          → the catalog (each tool's name, description, parameter schema)
POST /v1/tools/{name}   → run a tool; Foundry sandboxes it, brokers its capabilities,
                          and returns the result
```

No client configuration required. For hosts that want native tool-use, Foundry can *also*
present the same catalog over MCP — but that's an optional accelerator, never a requirement.
mykeep's rule: **REST + guide is the universal baseline; MCP, hooks, and SDKs are opt-in per
host.**

## Where it fits

Foundry composes with its siblings, all on the same stick, under one password:

- **[Memory Capsule](https://github.com/lexxx233/mykeep-memory-capsule)** — tools that need to
  remember read and write the agent's memory.
- **SecretVault** — tools that take authenticated actions get scoped, sealed credentials *by
  reference*; the raw key never enters the tool or the agent's context.

## Design principles

- **Portable first** — pure Go, zero CGo, one static binary, six targets. Lives on the stick
  beside its data; no host install.
- **Private by default** — everything sealed at rest with the suite's whole-DB AES-256-GCM
  encryption; no cloud round-trips.
- **The agent reasons, mykeep provides** — Foundry runs tools and infrastructure; it does no
  LLM reasoning of its own.
- **Capability-scoped** — tools get exactly the powers you grant, enforced by the sandbox.

---

<div align="center">
<sub>A component of <a href="https://mykeep.ai">mykeep</a> · Personal · Private · Portable · © 2026 Domu Inc</sub>
</div>
