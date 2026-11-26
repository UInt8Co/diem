import {encode, decode} from './cbor.js';
import {signProfile, utf8} from './signers.js';

const fromHex = text => new Uint8Array(text.match(/../g).map(pair => parseInt(pair, 16)));
const equal = (a, b) => a.length === b.length && a.every((v, i) => v === b[i]);

export async function exerciseProfiles({diem, check, rejects, alice, base}) {
  const verifier = {verify: alice.verify};
  const rejectsWith = async(action, message) => {
    try { await action(); } catch(error) {
      check(String(error).includes(message), `Expected ${message}, got ${error}`);
      return;
    }
    throw new Error(`Expected ${message} rejection`);
  };
  // Diem's committed cross-language vectors (Ed25519 and P-256), with one application field.
  const fixture = await (await fetch('/vectors/diem-v5.json')).json();
  for(const vector of fixture.vectors.filter(vector => vector.algorithm === 1 || vector.algorithm === 2)) {
    const info = await diem.verifyProfile(fromHex(vector.profile), fixture.now, verifier);
    check(info.id === vector.identityID && info.signer === vector.deviceID && info.generation === '1' &&
      info.revision === '1' && info.notBefore === String(fixture.now) && !info.lapsed, `Vector ${vector.algorithm} facts`);
    check(info.domains.join() === 'vectors.example' && info.devices.length === 1 &&
      equal(info.devices[0].key, fromHex(vector.deviceKey)), `Vector ${vector.algorithm} domains and devices`);
    check(Object.keys(info.applications).join() === fixture.application &&
      equal(info.applications[fixture.application], encode(utf8('cross-language profile'))), `Vector ${vector.algorithm} raw application value`);
  }

  // Independently signed profiles: several applications, a P-256 signer and lapse boundaries.
  const second = await diem.deviceKeys.generate();
  const applications = {'org.example.notes': {0: 'notes', 1: [1, 2]}, 'com.example': utf8('opaque')};
  const profile = await signProfile({identity: alice.identity, devices: [alice.device, second],
    domains: ['alice.example.org', 'alias.example.org'], applications, notBefore: base.now, revision: 3,
    generation: 2, previous: new Uint8Array(32).fill(9)});
  const info = await diem.verifyProfile(profile, base.now, verifier);
  check(info.id === alice.identity.id && info.generation === '2' && info.revision === '3' &&
    info.expiresAt === String(base.now + 86_400) && info.domains.join() === 'alice.example.org,alias.example.org', 'Profile facts');
  check(info.devices.length === 2 && info.devices[1].expiresAt === String(base.now + 30 * 86_400) &&
    info.signer === info.devices[0].id, 'Device list and signer');
  check(Object.keys(info.applications).join() === 'com.example,org.example.notes' &&
    equal(info.applications['org.example.notes'], encode(applications['org.example.notes'])), 'Application IDs and raw values');
  for(const [now, lapsed] of [[base.now - 1, true], [base.now, false], [base.now + 86_399, false], [base.now + 86_400, true],
    [base.now + 400 * 86_400, true]]) {
    check((await diem.verifyProfile(profile, now, verifier)).lapsed === lapsed, `Validity boundary ${now}`);
  }

  // Tampering, signature and structure failures.
  const corrupt = profile.slice(); corrupt[corrupt.length - 1] ^= 1;
  await rejectsWith(() => diem.verifyProfile(corrupt, base.now, verifier), 'invalidSignature');
  await rejectsWith(() => diem.verifyProfile(profile, base.now, {verify: async() => false}), 'invalidSignature');
  await rejects(() => diem.verifyProfile(profile, base.now, {verify: async() => { throw new Error('Verifier refused'); }}));
  const unsigned = decode(profile); unsigned[1] = 4;
  await rejectsWith(() => diem.verifyProfile(encode(unsigned), base.now, verifier), 'invalidEncoding');
  const invalidID = await signProfile({identity: alice.identity, devices: [alice.device], notBefore: base.now,
    applications: {'Not.An.ID': 1}});
  await rejectsWith(() => diem.verifyProfile(invalidID, base.now, verifier), 'invalidEncoding');
  for(const [encoding, now, candidate] of [[profile, -1, verifier], [profile, 1.5, verifier], [profile, base.now, {}], [[256], base.now, verifier]]) {
    await rejects(() => diem.verifyProfile(encoding, now, candidate));
  }
  check((await diem.verifyProfile(profile, base.now, verifier)).id === info.id, 'Runtime survives rejections');
  return {profile, second};
}
