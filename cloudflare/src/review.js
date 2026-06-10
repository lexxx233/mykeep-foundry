// review.js — the AI exploit-review gate. A submitted tool's source + manifest are read by
// an LLM under a constrained JSON schema, producing a gating verdict. This is
// defense-in-DEPTH, never the sole control: the runtime sandbox, the capability grant, and
// the human's install-time consent are the actual floor. A `pass` is "we found nothing", not
// "safe to run unsupervised".
//
// The reviewing model is supplied at deploy time via the REVIEW_MODEL binding, NOT hardcoded
// here — naming it publicly would only help an attacker tailor a bypass against it.

// Fallback only — set REVIEW_MODEL as a Worker variable in production so the model name never
// lives in the public source.
const DEFAULT_MODEL = "@cf/meta/llama-3.1-8b-instruct";

export const VERDICT_SCHEMA = {
  type: "object",
  required: ["verdict", "risk_score", "categories", "rationale"],
  properties: {
    verdict: { type: "string", enum: ["pass", "flag", "reject"] },
    risk_score: { type: "integer", minimum: 0, maximum: 100 },
    categories: {
      type: "array",
      items: {
        type: "string",
        enum: [
          "exfiltration", "capability_overreach", "obfuscation", "network_abuse",
          "credential_harvest", "prompt_injection", "sandbox_escape_attempt",
          "supply_chain", "resource_abuse", "benign",
        ],
      },
    },
    findings: {
      type: "array",
      items: {
        type: "object",
        properties: {
          category: { type: "string" },
          severity: { type: "string", enum: ["low", "med", "high", "critical"] },
          evidence: { type: "string" },
        },
      },
    },
    capability_consistency: {
      type: "string",
      enum: ["consistent", "under_declared", "over_declared"],
    },
    rationale: { type: "string" },
  },
};

const SYSTEM_PROMPT = `You are a security reviewer for an open marketplace of JavaScript "tools" that run in a
capability-sandboxed runtime. Each tool declares the capabilities it needs in a manifest
(network hosts, vault credentials, storage, limits) and may only call a fixed host API:
foundry.kv/queue/cache/blob (storage), foundry.http.fetch (egress to DECLARED hosts only),
foundry.vault.fetch (authenticated calls by reference; the secret is never exposed),
foundry.log, console.log. There is no other I/O, no eval of remote code, no raw sockets.

Review the SOURCE against the MANIFEST and report, as structured JSON only:
- exfiltration: shipping user data or credentials to attacker-controlled hosts, beaconing,
  encoding tricks, staging-then-shipping via storage.
- capability_overreach / capability_consistency: code that reaches hosts, reads credentials,
  or uses storage BEYOND what the manifest declares (under_declared is a strong reject signal).
- obfuscation: eval/new Function, base64/hex-built host calls, string-assembled identifiers
  designed to defeat static reading.
- credential_harvest: attempts to coax the raw secret out of the by-reference vault model.
- sandbox_escape_attempt: probing host functions for unintended powers, prototype pollution.
- resource_abuse: unbounded loops/allocation aimed at exceeding the granted limits.

Score risk 0-100. Be specific in findings.evidence. Output ONLY JSON matching the schema.`;

// Decision policy: high risk or any critical finding → reject; medium or a capability
// mismatch → flag (human-in-the-loop); otherwise pass. Thresholds are tunable.
export function decide(verdict) {
  const critical = (verdict.findings || []).some((f) => f.severity === "critical");
  if (verdict.risk_score >= 70 || critical) return "reject";
  if (
    verdict.risk_score >= 30 ||
    verdict.capability_consistency === "under_declared" ||
    verdict.capability_consistency === "over_declared"
  ) {
    return "flag";
  }
  return "pass";
}

// review runs the configured LLM over the submission and returns the (schema-valid) verdict
// plus the policy decision. The model's own `verdict` field is advisory; `decision` is
// authoritative. The model id comes from the REVIEW_MODEL Worker variable (see DEFAULT_MODEL).
export async function review(env, manifest, source) {
  const out = await env.AI.run(env.REVIEW_MODEL || DEFAULT_MODEL, {
    messages: [
      { role: "system", content: SYSTEM_PROMPT },
      { role: "user", content: JSON.stringify({ manifest, source }) },
    ],
    response_format: { type: "json_schema", json_schema: VERDICT_SCHEMA },
  });
  const verdict = typeof out.response === "string" ? JSON.parse(out.response) : out.response;
  return { verdict, decision: decide(verdict) };
}
