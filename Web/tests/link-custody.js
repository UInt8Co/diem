import {decode, encode} from './cbor.js';
import {owner as makeOwner, signProfile, signers, utf8} from './signers.js';
import {storedCustody} from './seeds.js';

// Exercise real Window/worker-generated devices without serializing signing secrets.
export async function exerciseLinkCustody(diem, check, rejects, absent, context) {
  const instantiate = WebAssembly.instantiateStreaming;
  const isolated = [];
  if(typeof Worker !== 'function') WebAssembly.instantiateStreaming = async(...args) => {
    const result = await instantiate(...args);
    isolated.push(result.instance.exports.memory);
    return result;
  };
  try { await linkCustody(diem, check, rejects, absent, context); }
  finally { WebAssembly.instantiateStreaming = instantiate; }
  if(typeof Worker !== 'function') {
    check(isolated.length > 0, 'SharedWorker links use separate WASM instances');
    for(const memory of isolated) {
      check(new Uint8Array(memory.buffer).every(byte => byte === 0), 'Disposable link heap is wiped on success, failure and cancellation');
    }
  }
}

async function linkCustody(diem, check, rejects, absent, context) {
  const owner = await makeOwner(diem);
  const domain = 'linked.example', now = Math.floor(Date.now() / 1000) - 60;
  const profileFor = devices => signProfile({identity: owner.identity, devices: [owner.device, ...devices],
    domains: [domain], notBefore: now});
  for(const transfer of [false, true]) {
    const begun = await diem.deviceLink.begin('Real worker');
    try {
      check(Object.keys(begun.session).join() === 'destroy', 'Link handle exposes no private keys');
      const inspected = await diem.deviceLink.inspect(begun.parameter, begun.request);
      check(decode(inspected.device)[3] === 2 && inspected.verifies.join() === '1,2', 'Joining device is P-256 and verifies both algorithms');
      const input = {code: begun.parameter, request: begun.request, profile: await profileFor([]), domain};
      await rejects(() => diem.deviceLink.respond(input)); // The profile must certify the new key.
      // The fixture signer certifies the joining device from its public key alone.
      const joining = {publicKey: decode(inspected.device)[4]};
      const profile = await profileFor([joining]);
      await rejects(() => diem.deviceLink.respond({...input, profile, domain: 'other.example'}));
      const applications = {'org.example.app': encode(utf8('grant field'))};
      const response = await diem.deviceLink.respond({...input, profile, applications,
        seed: transfer ? owner.seed : undefined});
      const opened = await diem.deviceLink.open(begun.session, response);
      check(!!opened.seed === transfer, 'Seed transfer requires explicit approval');
      check(opened.domain === domain && opened.profile.every((v, i) => v === profile[i]), 'Exact published profile');
      check(Object.keys(opened.applications).join() === 'org.example.app' &&
        opened.applications['org.example.app'].every((v, i) => v === applications['org.example.app'][i]), 'Grant application fields preserved');
      check(opened.device.privateKey.extractable === false, 'Joining signer stays non-extractable after worker completion');
      check(JSON.stringify(Array.from(opened.device.publicKey)) === JSON.stringify(Array.from(joining.publicKey)), 'Returned signer matches requested device');
      if(transfer) check(opened.seed.every((v, i) => v === owner.seed[i]), 'Grant transfers the root entropy');
      const persisted = await storedCustody(opened.seed ?? new Uint8Array(32), opened.device, check, context);
      const linked = signers(undefined, persisted);
      const message = new Uint8Array([4, 5, 6]);
      check(await linked.verify(persisted.publicKey, message, await linked.sign('device', message)), 'Custodied joining signer signs');
      if(transfer) {
        const identity = await diem.seeds.identity(opened.seed, owner.identity.publicKey);
        check(identity.id === owner.identity.id, 'Transferred seed manages the identity');
      }
      opened.seed?.fill(0);
      await rejects(() => diem.deviceLink.open(begun.session, response));
    } finally { begun.session.destroy(); }
  }
  const failed = await diem.deviceLink.begin('Failure is fatal');
  await rejects(() => diem.deviceLink.open(failed.session, new Uint8Array(65537)));
  await rejects(() => diem.deviceLink.open(failed.session, []));
  failed.session.destroy();
  const cancelled = await diem.deviceLink.begin('Cancelled');
  cancelled.session.destroy();
  await rejects(() => diem.deviceLink.open(cancelled.session, []));
  absent(owner.seed);
  owner.seed.fill(0);
}
