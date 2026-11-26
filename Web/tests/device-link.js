import {createDiem} from '../dist/diem.js';
import {encode, decode} from './cbor.js';

const check = (condition, message) => { if(!condition) throw new Error(message); };
const fromHex = text => new Uint8Array(text.match(/../g).map(pair => parseInt(pair, 16)));
const base64url = value => btoa(String.fromCharCode(...value)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
async function rejects(action, message) {
  try { await action(); } catch { return; }
  throw new Error(`Expected rejection: ${message}`);
}
// Diem's native fixed vector (Tests/DiemTests/DeviceLinkTests.swift): an Ed25519 device,
// P-256 recipient scalar 1, label "Interop desktop", verifies [Ed25519], secret 00…0f.
const nativeRequest = fromHex('a60078184469656d2f6465766963652d6c696e6b2d726571756573740101025834a500684469656d2f6b6579010302020301045820ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c035855a500684469656d2f6b6579010302030304045841046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5046f496e7465726f70206465736b746f70058101');
const nativeParameter = 'pAB1RGllbS9kZXZpY2UtbGluay1jb2RlAQECWCB5bcYJnJBPHhK7cueBvy1EMTEFUMlXUSCW-tfJj2X8kQNQAAECAwQFBgcICQoLDA0ODw';

/** Request binding, QR parsing and bounds; round trips run in link-custody.js. */
export async function run() {
  const diem = await createDiem(new URL('../dist/diem.wasm', import.meta.url));
  const inspected = await diem.deviceLink.inspect(nativeParameter, nativeRequest);
  check(inspected.label === 'Interop desktop' && inspected.verifies.join() === '1' &&
    JSON.stringify(Array.from(inspected.device)) === JSON.stringify(Array.from(decode(nativeRequest)[2])), 'Native request inspects exactly');
  for(const label of ['', 'é'.repeat(33), 'a'.repeat(65)]) {
    await rejects(() => diem.deviceLink.begin(label), 'label UTF-8 bounds');
  }
  for(const label of ['a', 'é'.repeat(32)]) {
    const started = await diem.deviceLink.begin(label);
    check((await diem.deviceLink.inspect(started.parameter, started.request)).label === label, 'Valid label boundary');
    started.session.destroy();
  }
  for(const parameter of ['', 'A', nativeParameter + '=', ' ' + nativeParameter, nativeParameter + '\n', '+' + nativeParameter, 'x'.repeat(5463)]) {
    await rejects(() => diem.deviceLink.inspect(parameter, nativeRequest), 'malformed QR text');
  }
  const code = decode(fromHex('a400754469656d2f6465766963652d6c696e6b2d636f64650101025820796dc6099c904f1e12bb72e781bf2d4431310550c957512096fad7c98f65fc910350000102030405060708090a0b0c0d0e0f'));
  for(const index of [0, 31]) {
    const tampered = structuredClone(code); tampered[2][index] ^= 1;
    await rejects(() => diem.deviceLink.inspect(base64url(encode(tampered)), nativeRequest), `digest byte ${index}`);
  }
  const substituted = await diem.deviceLink.begin('Relay substitution');
  await rejects(() => diem.deviceLink.inspect(nativeParameter, substituted.request), 'relay swaps the request');
  for(const [key, value] of [[0, 'Blah/device-link-request'], [1, 2], [4, ''], [5, []], [5, [1, 1]]]) {
    const request = decode(nativeRequest); request[key] = value;
    const encoding = new Uint8Array(encode(request));
    const matching = structuredClone(code); matching[2] = new Uint8Array(await crypto.subtle.digest('SHA-256', encoding));
    await rejects(() => diem.deviceLink.inspect(base64url(encode(matching)), encoding), 'invalid request even with matching digest');
  }
  const future = decode(nativeRequest); future[99] = 'future'; future['org.example.app'] = 1;
  const extended = new Uint8Array(encode(future));
  const futureCode = structuredClone(code); futureCode[2] = new Uint8Array(await crypto.subtle.digest('SHA-256', extended));
  check((await diem.deviceLink.inspect(base64url(encode(futureCode)), extended)).label === 'Interop desktop', 'Unknown request keys accepted');
  // The approving side checks the QR binding and the approval's shape before any worker runs.
  const input = {code: nativeParameter, request: substituted.request, profile: [], domain: 'example.org'};
  await rejects(() => diem.deviceLink.respond(input), 'respond checks the request digest');
  await rejects(() => diem.deviceLink.respond({...input, request: nativeRequest, seed: new Uint8Array(31)}), 'seed length');
  await rejects(() => diem.deviceLink.respond({...input, request: nativeRequest, applications: {'org.example.app': new Uint8Array(65537)}}), 'field bounds');
  for(const response of [new Uint8Array(65537), [256]]) {
    const begun = await diem.deviceLink.begin('Bounds');
    await rejects(() => diem.deviceLink.open(begun.session, response), 'response bounds');
    await rejects(() => diem.deviceLink.open(begun.session, []), 'failure is fatal for the session');
    begun.session.destroy();
  }
  substituted.session.destroy();
  return {realm: typeof document === 'undefined' ? 'worker' : 'window'};
}
