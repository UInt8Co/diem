import {encode, Raw} from './cbor.js';

export async function verify(key, message, signature) {
  const algorithm = key.length === 32 ? 'Ed25519' : {name: 'ECDSA', namedCurve: 'P-256'};
  const publicKey = await crypto.subtle.importKey('raw', new Uint8Array(key), algorithm, false, ['verify']);
  return crypto.subtle.verify(key.length === 32 ? 'Ed25519' : {name: 'ECDSA', hash: 'SHA-256'},
    publicKey, new Uint8Array(signature), new Uint8Array(message));
}

export function signers(identity, device) {
  return {
    random: n => crypto.getRandomValues(new Uint8Array(n)),
    publicKey: role => role === 'identity' ? identity?.publicKey.slice(-32) ?? new Uint8Array() : device.publicKey,
    sign: async(role, bytes) => new Uint8Array(await crypto.subtle.sign(
      role === 'identity' ? 'Ed25519' : {name: 'ECDSA', hash: 'SHA-256'},
      role === 'identity' ? identity.signer : device.privateKey, new Uint8Array(bytes))),
    verify
  };
}

/** A seed-derived identity with one P-256 device. */
export async function owner(diem) {
  const seed = diem.seeds.generate().entropy;
  const identity = await diem.seeds.identity(seed);
  const device = await diem.deviceKeys.generate();
  return {...signers(identity, device), seed, identity, device};
}

const sha256 = async bytes => new Uint8Array(await crypto.subtle.digest('SHA-256', new Uint8Array(bytes)));
const sign = async(key, message) => new Uint8Array(await crypto.subtle.sign(
  key.algorithm.name === 'Ed25519' ? 'Ed25519' : {name: 'ECDSA', hash: 'SHA-256'}, key, new Uint8Array(message)));
const deviceEncoding = device => new Uint8Array(encode({0: 'Diem/key', 1: 3, 2: 2, 3: 2, 4: device.publicKey}));
export const utf8 = text => new TextEncoder().encode(text);

/**
 * Independently signs a Diem v5 profile: Ed25519 identity from `diem.seeds.identity`,
 * P-256 devices, the first device signing. `applications` maps IDs to CBOR values.
 */
export async function signProfile({identity, devices, domains = [], applications = {}, notBefore,
  lifetime = 86_400, deviceLifetime = 30 * 86_400, revision = 1, generation = 1, previous = new Uint8Array()}) {
  const identityID = await sha256(identity.publicKey);
  const certificates = [];
  for(const device of devices) {
    const message = encode({0: 'Diem/device', 1: 3, 2: identityID, 3: generation, 4: deviceEncoding(device),
      5: notBefore, 6: notBefore + deviceLifetime});
    certificates.push(new Uint8Array(encode({0: new Uint8Array(message), 1: await sign(identity.signer, message)})));
  }
  const content = encode({0: 'Diem/profile-content', 1: 5, 2: identityID, 3: generation,
    4: await sha256(deviceEncoding(devices[0])), 5: revision, 6: previous, 7: notBefore, 8: notBefore + lifetime,
    9: domains, ...Object.fromEntries(Object.entries(applications).map(([id, value]) => [id, new Raw(encode(value))]))});
  const signed = encode({0: new Uint8Array(content), 1: await sign(devices[0].privateKey, content)});
  return new Uint8Array(encode({0: 'Diem/profile', 1: 5, 2: identity.publicKey, 3: certificates, 4: new Uint8Array(signed)}));
}
