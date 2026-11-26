// Diem's JavaScript API over a runtime's BridgeJS exports. An application's runtime spreads
// this object into its own client and adds its operations.
import {bytes, validTime} from './bytes.js';
import {deviceKeys} from './crypto-support.js';
import {seeds} from './seeds.js';
import {hosting} from './hosting.js';
import {deviceLink} from './device-links.js';
import {diemLinkProtocol} from './device-link-protocol.js';

/**
 * `exports` must include DiemWeb's `@JS` functions; `wasmURL` is reloaded by link realms.
 * `deviceLinkProtocol` and `deviceLinkWorker` replace the generic device link.
 */
export function diemClient(exports, wasmURL, {deviceLinkProtocol = diemLinkProtocol, deviceLinkWorker} = {}) {
  return {
    seeds: seeds(),
    deviceKeys,
    hosting: hosting(exports),
    deviceLink: deviceLink(exports, wasmURL, deviceLinkProtocol, deviceLinkWorker),
    async verifyProfile(encoding, now, crypto) {
      if(!validTime(now) || typeof crypto?.verify !== 'function') {
        throw new TypeError('Invalid profile verification request');
      }
      return profileInfo(await exports.verifyDiemProfile(bytes(encoding, 'profile'), now, crypto));
    }
  };
}

/** DiemProfileInfo with byte arrays as Uint8Array and application fields keyed by ID. */
export function profileInfo(info) {
  return {...info, devices: info.devices.map(device => ({...device, key: new Uint8Array(device.key)})),
    applications: Object.fromEntries(info.applications.map(field => [field.id, new Uint8Array(field.value)]))};
}
