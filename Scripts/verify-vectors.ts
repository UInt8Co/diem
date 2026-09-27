// Independent WebCrypto verifier for the committed Diem v3 wire vectors.
// deno run --allow-read Scripts/verify-vectors.ts
function assert(condition: unknown): asserts condition {
  if (!condition) throw new Error("Vector assertion failed");
}
function assertThrows(body: () => unknown) {
  try { body(); } catch { return; }
  throw new Error("Malformed encoding was accepted");
}

function hex(s: string): Uint8Array {
  assert(s.length % 2 === 0 && /^[0-9a-f]*$/.test(s));
  return Uint8Array.from(s.match(/../g) ?? [], x => parseInt(x, 16));
}
function equal(a: Uint8Array, b: Uint8Array) { return a.length === b.length && a.every((v, i) => v === b[i]); }
async function hash(b: Uint8Array) { return new Uint8Array(await crypto.subtle.digest("SHA-256", new Uint8Array(b))); }

type Value = bigint | string | Uint8Array | Value[] | Map<string, Value> | boolean | null;
function decode(input: Uint8Array): Value {
  assert(input.length <= 262144);
  let p = 0, items = 0;
  function byte() { assert(p < input.length); return input[p++]; }
  function read(depth: number): Value {
    assert(depth <= 16 && ++items <= 8192);
    const first = byte(), major = first >> 5, extra = first & 31;
    if (major === 7) { assert(extra >= 20 && extra <= 22); return extra === 22 ? null : extra === 21; }
    assert(major <= 5 && extra <= 27);
    let n = BigInt(extra);
    if (extra >= 24) {
      n = 0n;
      for (let i = 0; i < 1 << (extra - 24); i++) n = (n << 8n) | BigInt(byte());
      assert(n >= [24n, 256n, 65536n, 4294967296n][extra - 24]);
    }
    if (major === 0) return n;
    if (major === 1) return -1n - n;
    assert(n <= BigInt(input.length - p));
    if (major === 2 || major === 3) {
      const b = input.slice(p, p += Number(n));
      return major === 2 ? b : new TextDecoder("utf-8", { fatal: true }).decode(b);
    }
    if (major === 4) return Array.from({ length: Number(n) }, () => read(depth + 1));
    const map = new Map<string, Value>();
    let previous: Uint8Array | undefined;
    for (let i = 0; i < Number(n); i++) {
      const start = p;
      read(depth + 1);
      const key = input.slice(start, p);
      if (previous) {
        let order = previous.length - key.length;
        for (let j = 0; order === 0 && j < key.length; j++) order = previous[j] - key[j];
        assert(order < 0);
      }
      previous = key;
      map.set(Array.from(key).join(","), read(depth + 1));
    }
    return map;
  }
  const result = read(0);
  assert(p === input.length);
  return result;
}

function array(v: Value, length: number): Value[] { assert(Array.isArray(v) && v.length === length); return v; }
function bytes(v: Value): Uint8Array { assert(v instanceof Uint8Array); return v; }
function tagged(encoded: Uint8Array, tag: string, length: number) {
  const a = array(decode(encoded), length);
  assert(a[0] === tag && a[1] === 3n);
  return a;
}
// Signing keys are ["Diem/key", 3, purpose, algorithm, raw]: purpose 1 is identity, 2 is device.
const algorithms = new Map<bigint, { format: string; alg: Algorithm | EcdsaParams & EcKeyImportParams }>([
  [1n, { format: "raw", alg: { name: "Ed25519" } }],
  [2n, { format: "raw", alg: { name: "ECDSA", namedCurve: "P-256", hash: "SHA-256" } }],
  [5n, { format: "raw-public", alg: { name: "ML-DSA-65" } }],
]);
function signingKey(encodedKey: Uint8Array, purpose: bigint) {
  const key = array(decode(encodedKey), 5);
  assert(key[0] === "Diem/key" && key[1] === 3n && key[2] === purpose);
  const entry = algorithms.get(key[3] as bigint);
  assert(entry);
  return { ...entry, raw: bytes(key[4]) };
}
async function verify(encodedKey: Uint8Array, purpose: bigint, message: Uint8Array, signature: Uint8Array) {
  const { format, alg, raw } = signingKey(encodedKey, purpose);
  const imported = await crypto.subtle.importKey(format as "raw", new Uint8Array(raw), alg, false, ["verify"]);
  return crypto.subtle.verify(alg, imported, new Uint8Array(signature), new Uint8Array(message));
}
async function verifySigned(encodedKey: Uint8Array, purpose: bigint, message: Uint8Array, signature: Uint8Array) {
  assert(await verify(encodedKey, purpose, message, signature));
  const tampered = message.slice(); tampered[tampered.length - 1] ^= 1;
  assert(!await verify(encodedKey, purpose, tampered, signature));
}

const fixture = JSON.parse(await Deno.readTextFile(new URL("../Tests/Vectors/diem-v3.json", import.meta.url)));
assert(fixture.protocol === "Diem/v3");
for (const v of fixture.vectors) {
  const identityKey = hex(v.identityKey), deviceKey = hex(v.deviceKey);
  const identityID = hex(v.identityID), deviceID = hex(v.deviceID);
  assert(equal(await hash(identityKey), identityID) && equal(await hash(deviceKey), deviceID));
  // Each key serves one purpose.
  assertThrows(() => signingKey(identityKey, 2n));
  assertThrows(() => signingKey(deviceKey, 1n));

  const certificate = hex(v.certificateMessage);
  await verifySigned(identityKey, 1n, certificate, hex(v.certificateSignature));
  const c = tagged(certificate, "Diem/device", 7);
  assert(equal(bytes(c[2]), identityID) && c[3] === 1n && equal(bytes(c[4]), deviceKey));

  const content = hex(v.contentMessage);
  await verifySigned(deviceKey, 2n, content, hex(v.contentSignature));
  assert(!await verify(identityKey, 1n, content, hex(v.contentSignature)));
  const p = tagged(content, "Diem/profile-content", 10);
  assert(equal(bytes(p[2]), identityID) && p[3] === 1n && equal(bytes(p[4]), deviceID) && p[5] === 1n);
  const profile = tagged(hex(v.profile), "Diem/profile", 5);
  assert(equal(bytes(profile[2]), identityKey));

  const proof = hex(v.proofMessage);
  await verifySigned(deviceKey, 2n, proof, hex(v.proofSignature));
  const q = tagged(proof, "Diem/proof", 5);
  assert(equal(bytes(q[2]), identityID) && equal(bytes(q[3]), deviceID));
  assert(equal(bytes(q[4]), new TextEncoder().encode("cross-language proof")));

  const s = tagged(hex(v.sealedIdentityKey), "Diem/sealed-identity-key", 6);
  assert(equal(bytes(s[2]), identityKey));
  const recipient = array(decode(bytes(s[3])), 5);
  assert(recipient[0] === "Diem/key" && recipient[1] === 3n && recipient[2] === 3n);
}
for (const malformed of ["a200010002", "1800", "0000", "9fff"]) {
  assertThrows(() => decode(hex(malformed)));
}
console.log(`Verified ${fixture.vectors.length} Diem v3 vectors with WebCrypto.`);
