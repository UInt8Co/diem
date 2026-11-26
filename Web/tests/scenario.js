import {createDiem} from '../dist/diem.js';
import {exerciseHosting} from './hosting.js';
import {exerciseProfiles} from './profiles.js';
import {exerciseSeeds} from './seeds.js';
import {owner} from './signers.js';
import {exerciseLinkCustody} from './link-custody.js';

function check(condition, message) { if(!condition) throw new Error(message); }
async function rejects(action) {
  let rejected = false;
  try { await action(); } catch { rejected = true; }
  check(rejected, 'Expected request rejection');
}
export async function run({engine, realm}) {
  const instantiate = WebAssembly.instantiateStreaming;
  let memory, diem;
  WebAssembly.instantiateStreaming = async(...args) => {
    const result = await instantiate(...args);
    memory = result.instance.exports.memory;
    return result;
  };
  try { diem = await createDiem(new URL('../dist/diem.wasm', import.meta.url)); }
  finally { WebAssembly.instantiateStreaming = instantiate; }
  const absent = seed => {
    const heap = new Uint8Array(memory.buffer);
    for(let offset = heap.indexOf(seed[0]); offset >= 0; offset = heap.indexOf(seed[0], offset + 1)) {
      check(!seed.every((byte, index) => heap[offset + index] === byte), 'Identity entropy retained in the main WASM heap');
    }
  };
  const alice = await owner(diem), bob = await owner(diem);
  const base = {now: 1_800_000_000, domain: 'alice.example.org'};
  await exerciseProfiles({diem, check, rejects, alice, base});
  await exerciseHosting({diem, check, base, alice, bob});
  await exerciseSeeds({diem, check, rejects, base, absent, engine, realm});
  await exerciseLinkCustody(diem, check, rejects, absent, {engine, realm});
  check(Object.keys(globalThis).every(name => !/diem|bridge|swift/i.test(name)), 'Global bridge callbacks leaked');
  absent(alice.seed); absent(bob.seed);
  return {realm: typeof document === 'undefined' ? 'worker' : 'window'};
}
