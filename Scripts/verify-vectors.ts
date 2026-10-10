// Independent WebCrypto verifier for the committed Diem v4 wire vectors.
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

type Value = bigint | string | Uint8Array | Value[] | Map<string | bigint, Value> | boolean | null;
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
    const map = new Map<string | bigint, Value>();
    let previous: Uint8Array | undefined;
    for (let i = 0; i < Number(n); i++) {
      const start = p;
      const decodedKey = read(depth + 1);
      assert(typeof decodedKey === "string" || typeof decodedKey === "bigint");
      const key = input.slice(start, p);
      if (previous) {
        let order = previous.length - key.length;
        for (let j = 0; order === 0 && j < key.length; j++) order = previous[j] - key[j];
        assert(order < 0);
      }
      previous = key;
      map.set(decodedKey, read(depth + 1));
    }
    return map;
  }
  const result = read(0);
  assert(p === input.length);
  return result;
}

function record(v: Value, required: number): Record<number, Value> {
  assert(v instanceof Map);
  const fields: Record<number, Value> = {};
  for (const [key, value] of v) { assert(typeof key === "bigint" && key >= 0n); fields[Number(key)] = value; }
  for (let key = 0; key < required; key++) assert(key in fields);
  return fields;
}
function bytes(v: Value): Uint8Array { assert(v instanceof Uint8Array); return v; }
function tagged(encoded: Uint8Array, tag: string, length: number, version = 3n) {
  const a = record(decode(encoded), length);
  assert(a[0] === tag && a[1] === version);
  return a;
}
// Integer-keyed signing records: purpose 1 is identity, 2 is device.
const algorithms = new Map<bigint, { format: string; alg: Algorithm | EcdsaParams & EcKeyImportParams }>([
  [1n, { format: "raw", alg: { name: "Ed25519" } }],
  [2n, { format: "raw", alg: { name: "ECDSA", namedCurve: "P-256", hash: "SHA-256" } }],
  [5n, { format: "raw-public", alg: { name: "ML-DSA-65" } }],
]);
function signingKey(encodedKey: Uint8Array, purpose: bigint) {
  const key = record(decode(encodedKey), 5);
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

const fixture = JSON.parse(await Deno.readTextFile(new URL("../Tests/Vectors/diem-v4.json", import.meta.url)));
assert(fixture.protocol === "Diem/v4");
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
  const p = tagged(content, "Diem/profile-content", 10, 4n);
  assert(equal(bytes(p[2]), identityID) && p[3] === 1n && equal(bytes(p[4]), deviceID) && p[5] === 1n);
  // Domains are Diem's; application fields start at key 16.
  assert(Array.isArray(p[9]) && p[9].length === 1 && p[9][0] === "vectors.example");
  assert(equal(bytes(p[16]), new TextEncoder().encode("cross-language profile")));
  const profile = tagged(hex(v.profile), "Diem/profile", 5, 4n);
  assert(equal(bytes(profile[2]), identityKey));

  const proof = hex(v.proofMessage);
  await verifySigned(deviceKey, 2n, proof, hex(v.proofSignature));
  const q = tagged(proof, "Diem/proof", 5);
  assert(equal(bytes(q[2]), identityID) && equal(bytes(q[3]), deviceID));
  assert(equal(bytes(q[4]), new TextEncoder().encode("cross-language proof")));

  const s = tagged(hex(v.sealedIdentityKey), "Diem/sealed-identity-key", 6);
  assert(equal(bytes(s[2]), identityKey));
  const recipient = record(decode(bytes(s[3])), 5);
  assert(recipient[0] === "Diem/key" && recipient[1] === 3n && recipient[2] === 3n);
}
for (const malformed of ["a200010002", "1800", "0000", "9fff"]) {
  assertThrows(() => decode(hex(malformed)));
}
console.log(`Verified ${fixture.vectors.length} Diem v4 vectors with WebCrypto.`);

// Paper device keys: BIP 39 English words over the entropy, HKDF-SHA256 seeds per algorithm.
const words = (await Deno.readTextFile(new URL("../Sources/Diem/PaperWords.swift", import.meta.url)))
  .split('"""')[1].trim().split(/\s+/);
const wordlist = new TextEncoder().encode(words.join("\n") + "\n");
assert(Array.from(await hash(wordlist), b => b.toString(16).padStart(2, "0")).join("")
  === "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda");
async function phrase(entropy: Uint8Array) {
  const bits = Array.from([...entropy, (await hash(entropy))[0]], b => b.toString(2).padStart(8, "0")).join("");
  return Array.from({ length: 24 }, (_, i) => words[parseInt(bits.slice(i * 11, i * 11 + 11), 2)]).join(" ");
}
const paper = JSON.parse(await Deno.readTextFile(new URL("../Tests/Vectors/paper-device-key.json", import.meta.url)));
assert(paper.protocol === "Diem/paper-device-key/1");
for (const v of paper.vectors) {
  const entropy = hex(v.entropy);
  assert(await phrase(entropy) === v.phrase);
  const ikm = await crypto.subtle.importKey("raw", new Uint8Array(entropy), "HKDF", false, ["deriveBits"]);
  for (const code of [1n, 5n]) {
    const context = record(decode(hex(v.context[`${code}`])), 4);
    assert(context[0] === "Diem/paper-device-key" && context[1] === 1n && context[2] === 2n && context[3] === code);
    const seed = new Uint8Array(await crypto.subtle.deriveBits(
      { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(), info: new Uint8Array(hex(v.context[`${code}`])) }, ikm, 256));
    assert(equal(seed, hex(v.seed[`${code}`])));
    const deviceKey = hex(v.deviceKey[`${code}`]);
    const { raw } = signingKey(deviceKey, 2n);
    if (code === 1n) {
      const pkcs8 = new Uint8Array([0x30, 0x2e, 2, 1, 0, 0x30, 5, 6, 3, 0x2b, 0x65, 0x70, 4, 0x22, 4, 0x20, ...seed]);
      const key = await crypto.subtle.importKey("pkcs8", pkcs8, "Ed25519", true, ["sign"]);
      const x = (await crypto.subtle.exportKey("jwk", key)).x!;
      assert(equal(Uint8Array.from(atob(x.replace(/-/g, "+").replace(/_/g, "/")), c => c.charCodeAt(0)), raw));
    } else {
      // WebCrypto cannot export an ML-DSA public key from its seed; sign and verify instead.
      const key = await crypto.subtle.importKey("raw-seed" as "raw", seed, { name: "ML-DSA-65" }, false, ["sign"]);
      const message = new TextEncoder().encode("paper device key");
      await verifySigned(deviceKey, 2n, message,
        new Uint8Array(await crypto.subtle.sign({ name: "ML-DSA-65" }, key, message)));
    }
  }
}
console.log(`Verified ${paper.vectors.length} paper device key vectors with WebCrypto.`);
