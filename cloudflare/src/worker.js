// worker.js — the Foundry marketplace edge. One Worker handles the open-submission
// pipeline (validate → AI review → sign → publish) and serves the signed catalog + tool
// artifacts from R2. The ed25519 signing key lives ONLY as a Worker secret and never
// leaves the edge; the matching public key is pinned into the Foundry binary.
//
// Bindings (wrangler.jsonc): AI (Workers AI), BUCKET (R2), DB (D1, rate-limit),
// secret REGISTRY_SIGNING_KEY (base64 ed25519 seed).

import { review } from "./review.js";
import { importPrivateKey, signSource, signIndex, sha256hex, b64 } from "./sign.js";
import { makeZip } from "./zip.js";

const MAX_SOURCE = 256 * 1024; // 256 KiB
const MAX_MANIFEST = 32 * 1024;
const DAILY_LIMIT = 20; // submissions per author per day (protects the AI budget)

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    try {
      if (request.method === "POST" && url.pathname === "/v1/submit") return await submit(request, env);
      // Catalog + artifacts are normally served straight from R2's custom domain; the
      // Worker mirrors them so the pipeline is self-contained for testing.
      if (request.method === "GET" && url.pathname.startsWith("/v1/")) return await serve(env, url.pathname.slice(4));
      return json({ error: "not_found" }, 404);
    } catch (e) {
      return json({ error: "internal", detail: String(e && e.message || e) }, 500);
    }
  },
};

async function submit(request, env) {
  const body = await request.json().catch(() => null);
  if (!body || typeof body.source !== "string" || typeof body.manifest !== "object") {
    return json({ error: "bad_request" }, 400);
  }
  const { manifest, source } = body;
  if (source.length > MAX_SOURCE) return json({ error: "source_too_large" }, 413);
  if (JSON.stringify(manifest).length > MAX_MANIFEST) return json({ error: "manifest_too_large" }, 413);
  if (!manifest.name || !manifest.version || !manifest.author) {
    return json({ error: "manifest_requires_name_version_author" }, 400);
  }

  // Rate-limit + content-hash dedupe BEFORE spending any AI budget (the real DoS surface).
  const author = String(manifest.author);
  if (await overDailyLimit(env, author)) return json({ error: "rate_limited" }, 429);
  const submissionHash = await sha256hex(new TextEncoder().encode(JSON.stringify(manifest) + "\0" + source));
  const cached = await getCachedVerdict(env, submissionHash);
  const { verdict, decision } = cached || (await review(env, manifest, source));
  if (!cached) await cacheVerdict(env, submissionHash, { verdict, decision });

  // Persist the full review report regardless of outcome (forensic record).
  const id = `${author}/${manifest.name}`;
  await env.BUCKET.put(`reviews/${id}/${manifest.version}.json`, JSON.stringify({ verdict, decision }, null, 2));

  // Open-submission model:
  //   reject → never published (malware / sandbox-escape — the only hard block)
  //   flag   → published UNVERIFIED + queued for a human (installable with a warning)
  //   pass   → published VERIFIED
  // The runtime triad (sandbox + grants + human consent) is the safety floor for both
  // published outcomes; AI review only decides the `verified` badge, never installability.
  if (decision === "reject") return json({ status: "rejected", verdict }, 200);

  if (decision === "flag") {
    await env.DB.prepare(
      "INSERT OR REPLACE INTO flagged(id, version, submitted_at, verdict) VALUES(?,?,?,?)"
    ).bind(id, manifest.version, Date.now(), JSON.stringify(verdict)).run();
    const published = await publish(env, id, author, manifest, source, verdict, false);
    return json({ status: "published_unverified", verdict, published }, 200);
  }

  // pass → sign + publish, verified
  const published = await publish(env, id, author, manifest, source, verdict, true);
  return json({ status: "published", verdict, published }, 200);
}

async function publish(env, id, author, manifest, source, verdict, verified) {
  const key = await importPrivateKey(env.REGISTRY_SIGNING_KEY);
  const canonicalManifest = JSON.stringify(manifest);
  const { sig: sourceSig } = await signSource(key, manifest.name, manifest.version, source);

  // tool.zip = manifest.json + tool.js (matches the Go unpackTool reader).
  const zip = await makeZip([
    ["manifest.json", canonicalManifest],
    ["tool.js", source],
  ]);
  const artifact = `tools/${id}/${manifest.version}/tool.zip`;
  await env.BUCKET.put(artifact, zip);
  const zipSHA = await sha256hex(zip);

  // Merge into the index, bump generated_at, re-sign, write atomically-ish.
  const index = (await loadIndex(env)) || { schema: 1, generated_at: "", tools: [] };
  const generatedAt = new Date().toISOString();
  upsertVersion(index, {
    id, author, name: manifest.name, version: manifest.version,
    artifact, zip_sha256: zipSHA, source_sig: b64(sourceSig), verified,
    manifest: canonicalManifest,
    // The reviewing model is intentionally omitted from public output — see review.js.
    review: { verdict: verdict.verdict, risk_score: verdict.risk_score, reviewed_at: generatedAt },
  });
  index.generated_at = generatedAt;
  const indexBytes = new TextEncoder().encode(JSON.stringify(index));
  const indexSig = await signIndex(key, indexBytes);
  await env.BUCKET.put("v1/index.json", indexBytes);
  await env.BUCKET.put("v1/index.json.sig", indexSig);

  // catalog.json — the human-readable companion the browse web app reads. Derived from
  // the same signed index, so the badge it shows can't drift from what the binary installs.
  const catalog = buildCatalog(index, generatedAt);
  await env.BUCKET.put("v1/catalog.json", new TextEncoder().encode(JSON.stringify(catalog)));

  return { artifact, zip_sha256: zipSHA, verified };
}

// upsertVersion inserts the tool/version into the catalog, keeping `latest` current.
function upsertVersion(index, v) {
  let tool = index.tools.find((t) => t.id === v.id);
  if (!tool) {
    tool = { id: v.id, author: v.author, name: v.name, latest: v.version, versions: [] };
    index.tools.push(tool);
  }
  tool.versions = tool.versions.filter((x) => x.version !== v.version);
  tool.versions.push({
    version: v.version, artifact: v.artifact, zip_sha256: v.zip_sha256,
    source_sig: v.source_sig, manifest: JSON.parse(v.manifest), review: v.review, verified: v.verified,
  });
  tool.latest = v.version; // simplistic; a real impl would semver-compare
}

// buildCatalog flattens the signed index into the CatalogTool[] the browse app consumes
// (one row per tool at its latest version), surfacing the plain-English capability summary.
function buildCatalog(index, generatedAt) {
  return index.tools.map((t) => {
    const v = t.versions.find((x) => x.version === t.latest) || t.versions[t.versions.length - 1];
    const m = v.manifest || {};
    const caps = m.capabilities || {};
    return {
      id: t.id, name: t.name, author: t.author, version: v.version,
      description: m.description || "", role: "tools",
      verified: !!v.verified,
      review: v.review ? { verdict: v.review.verdict, risk_score: v.review.risk_score, reviewed_at: v.review.reviewed_at || generatedAt } : undefined,
      capabilities: {
        hosts: (caps.network && caps.network.hosts) || [],
        vault_creds: (caps.vault && caps.vault.credentials) || [],
        storage: caps.storage && caps.storage.namespace
          ? { namespace: caps.storage.namespace, quota_mb: caps.storage.quota_bytes ? Math.round(caps.storage.quota_bytes / (1024 * 1024)) : undefined }
          : undefined,
      },
      published_at: generatedAt,
    };
  });
}

async function loadIndex(env) {
  const obj = await env.BUCKET.get("v1/index.json");
  return obj ? JSON.parse(await obj.text()) : null;
}

async function serve(env, key) {
  const obj = await env.BUCKET.get(key);
  if (!obj) return json({ error: "not_found" }, 404);
  const ct = key.endsWith(".json") ? "application/json"
    : key.endsWith(".sig") ? "application/octet-stream"
    : key.endsWith(".zip") ? "application/zip" : "application/octet-stream";
  return new Response(obj.body, { headers: { "content-type": ct, "cache-control": "public, max-age=60" } });
}

async function overDailyLimit(env, author) {
  const dayStart = Math.floor(Date.now() / 86400000) * 86400000;
  const row = await env.DB.prepare("SELECT count FROM rate WHERE author=? AND day=?").bind(author, dayStart).first();
  const count = row ? row.count : 0;
  if (count >= DAILY_LIMIT) return true;
  await env.DB.prepare(
    "INSERT INTO rate(author, day, count) VALUES(?,?,1) ON CONFLICT(author,day) DO UPDATE SET count=count+1"
  ).bind(author, dayStart).run();
  return false;
}

async function getCachedVerdict(env, hash) {
  const obj = await env.BUCKET.get(`submissions/${hash}.json`);
  return obj ? JSON.parse(await obj.text()) : null;
}
async function cacheVerdict(env, hash, v) {
  await env.BUCKET.put(`submissions/${hash}.json`, JSON.stringify(v));
}

function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), { status, headers: { "content-type": "application/json" } });
}
