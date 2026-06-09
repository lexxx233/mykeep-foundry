// bootstrap.js — the in-sandbox half of Foundry's host ABI. It builds the `foundry`
// global the tool calls, marshals each call to the Go host over a tiny newline-delimited
// JSON protocol (requests out on fd 1, responses in on fd 0), and runs the tool's
// run(input). Host calls are async (Promise/await): a response only arrives after the Go
// driver yields it to the event loop, so `await foundry.kv.get(k)` is the contract.
(function () {
  // This quickjs-ng build has no TextEncoder/TextDecoder, so we do our own UTF-8 on the
  // read side and let std.out.puts handle encoding on the write side.

  // send writes one framed JSON message to stdout (the Go frameWriter parses it).
  function send(obj) {
    std.out.puts(JSON.stringify(obj) + "\n");
    std.out.flush();
  }

  // utf8decode turns a byte array (one complete line, no trailing newline) into a string.
  function utf8decode(b) {
    var s = "", i = 0;
    while (i < b.length) {
      var c = b[i++];
      if (c < 0x80) s += String.fromCharCode(c);
      else if (c < 0xe0) s += String.fromCharCode(((c & 0x1f) << 6) | (b[i++] & 0x3f));
      else if (c < 0xf0) s += String.fromCharCode(((c & 0x0f) << 12) | ((b[i++] & 0x3f) << 6) | (b[i++] & 0x3f));
      else {
        var cp = ((c & 0x07) << 18) | ((b[i++] & 0x3f) << 12) | ((b[i++] & 0x3f) << 6) | (b[i++] & 0x3f);
        cp -= 0x10000;
        s += String.fromCharCode(0xd800 + (cp >> 10), 0xdc00 + (cp & 0x3ff));
      }
    }
    return s;
  }

  // Route console.* through framed log lines (raw console would corrupt the fd-1 protocol).
  globalThis.console = {
    log: function () { send({ t: "log", level: "info", msg: join(arguments) }); },
    info: function () { send({ t: "log", level: "info", msg: join(arguments) }); },
    warn: function () { send({ t: "log", level: "warn", msg: join(arguments) }); },
    error: function () { send({ t: "log", level: "error", msg: join(arguments) }); },
  };
  function join(args) {
    var parts = [];
    for (var i = 0; i < args.length; i++) {
      var a = args[i];
      parts.push(typeof a === "string" ? a : safeStringify(a));
    }
    return parts.join(" ");
  }
  function safeStringify(v) { try { return JSON.stringify(v); } catch (e) { return String(v); } }

  // Pending host calls, keyed by id; resolved when the matching response frame arrives.
  var pending = new Map();
  var nextId = 1;
  function hostCall(op, args) {
    return new Promise(function (resolve, reject) {
      var id = nextId++;
      pending.set(id, { resolve: resolve, reject: reject });
      send({ t: "call", id: id, op: op, args: args === undefined ? null : args });
    });
  }

  // Response reader: accumulate stdin bytes, split on the newline byte (0x0A, which never
  // appears inside a UTF-8 sequence), UTF-8 decode each complete line, resolve/reject by id.
  var pendingBytes = [];
  var rb = new Uint8Array(65536);
  os.setReadHandler(0, function () {
    var n = os.read(0, rb.buffer, 0, rb.length);
    if (n <= 0) return;
    for (var i = 0; i < n; i++) pendingBytes.push(rb[i]);
    var nl;
    while ((nl = pendingBytes.indexOf(10)) >= 0) {
      var lineBytes = pendingBytes.slice(0, nl);
      pendingBytes = pendingBytes.slice(nl + 1);
      if (lineBytes.length === 0) continue;
      var msg;
      try { msg = JSON.parse(utf8decode(lineBytes)); } catch (e) { continue; }
      var p = pending.get(msg.id);
      if (!p) continue;
      pending.delete(msg.id);
      if (msg.error !== undefined && msg.error !== null) p.reject(new Error(msg.error));
      else p.resolve(msg.value);
    }
  });

  // The capability surface. Every method is async and brokered by the Go host, which
  // enforces the tool's granted capabilities — the JS side is never trusted to self-limit.
  globalThis.foundry = {
    echo: function (v) { return hostCall("echo", v); }, // M1 round-trip probe
    log: function (level, msg) { send({ t: "log", level: String(level), msg: String(msg) }); },
    kv: {
      get: function (k) { return hostCall("kv.get", { key: k }); },
      set: function (k, v) { return hostCall("kv.set", { key: k, value: v }); },
      del: function (k) { return hostCall("kv.del", { key: k }); },
    },
    cache: {
      get: function (k) { return hostCall("cache.get", { key: k }); },
      set: function (k, v, ttl) { return hostCall("cache.set", { key: k, value: v, ttl_seconds: ttl }); },
    },
    queue: {
      push: function (n, m) { return hostCall("queue.push", { name: n, msg: m }); },
      pop: function (n) { return hostCall("queue.pop", { name: n }); },
    },
    blob: {
      put: function (n, b) { return hostCall("blob.put", { name: n, data: b }); },
      get: function (n) { return hostCall("blob.get", { name: n }); },
    },
    http: { fetch: function (req) { return hostCall("http.fetch", req); } },
    vault: { fetch: function (req) { return hostCall("vault.fetch", req); } },
  };

  // __run drives the tool: parse the input env, call run(input), and emit exactly one
  // terminal frame (result or error) so the Go driver knows the invocation is complete.
  globalThis.__run = function () {
    var input = {};
    try { input = JSON.parse(std.getenv("FOUNDRY_INPUT") || "{}"); } catch (e) {}
    Promise.resolve()
      .then(function () {
        if (typeof run !== "function") throw new Error("tool defines no run(input) function");
        return run(input);
      })
      .then(function (v) { send({ t: "result", value: v === undefined ? null : v }); })
      .catch(function (e) { send({ t: "error", error: String((e && e.message) || e) }); });
  };
})();
