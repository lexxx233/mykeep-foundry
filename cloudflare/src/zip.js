// zip.js — a minimal STORED (uncompressed) zip writer. Cloudflare Workers have no zip
// library, so the marketplace builds tool.zip by hand; Foundry's Go side reads it with
// archive/zip, so the headers + CRC-32 must be exactly right.

const CRC_TABLE = (() => {
  const t = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    t[n] = c >>> 0;
  }
  return t;
})();

function crc32(bytes) {
  let c = 0xffffffff;
  for (const b of bytes) c = CRC_TABLE[(c ^ b) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

// makeZip builds a zip from [name, stringContent] entries.
export function makeZip(entries) {
  const enc = new TextEncoder();
  const files = [];
  const chunks = [];
  let offset = 0;
  for (const [name, content] of entries) {
    const data = enc.encode(content);
    const nameBytes = enc.encode(name);
    const crc = crc32(data);
    const local = new Uint8Array(30 + nameBytes.length);
    const dv = new DataView(local.buffer);
    dv.setUint32(0, 0x04034b50, true); // local file header signature
    dv.setUint16(4, 20, true); // version needed
    dv.setUint16(6, 0, true); // flags
    dv.setUint16(8, 0, true); // method 0 = stored
    dv.setUint16(10, 0, true); // mod time
    dv.setUint16(12, 0, true); // mod date
    dv.setUint32(14, crc, true);
    dv.setUint32(18, data.length, true); // compressed size
    dv.setUint32(22, data.length, true); // uncompressed size
    dv.setUint16(26, nameBytes.length, true);
    dv.setUint16(28, 0, true); // extra len
    local.set(nameBytes, 30);
    chunks.push(local, data);
    files.push({ nameBytes, crc, size: data.length, offset });
    offset += local.length + data.length;
  }
  const central = [];
  let cdSize = 0;
  for (const f of files) {
    const c = new Uint8Array(46 + f.nameBytes.length);
    const dv = new DataView(c.buffer);
    dv.setUint32(0, 0x02014b50, true); // central dir header signature
    dv.setUint16(4, 20, true); // version made by
    dv.setUint16(6, 20, true); // version needed
    dv.setUint32(16, f.crc, true);
    dv.setUint32(20, f.size, true);
    dv.setUint32(24, f.size, true);
    dv.setUint16(28, f.nameBytes.length, true);
    dv.setUint32(42, f.offset, true); // local header offset
    c.set(f.nameBytes, 46);
    central.push(c);
    cdSize += c.length;
  }
  const end = new Uint8Array(22);
  const edv = new DataView(end.buffer);
  edv.setUint32(0, 0x06054b50, true); // end-of-central-dir signature
  edv.setUint16(8, files.length, true);
  edv.setUint16(10, files.length, true);
  edv.setUint32(12, cdSize, true);
  edv.setUint32(16, offset, true); // central dir offset
  const all = [...chunks, ...central, end];
  const total = all.reduce((n, a) => n + a.length, 0);
  const out = new Uint8Array(total);
  let p = 0;
  for (const a of all) {
    out.set(a, p);
    p += a.length;
  }
  return out;
}
