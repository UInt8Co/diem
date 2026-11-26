// The standalone runtime: DiemWeb's BridgeJS exports plus the generic `ProfileRecord`
// profile and device-link exports, which applications replace with their own.
import {init} from './.build-embedded/plugins/PackageToJS/outputs/Package/index.js';
import {bytes, validTime} from './bytes.js';
import {diemClient} from './client.js';
import {diemLinkProtocol} from './device-link-protocol.js';

/** Works in Window, DedicatedWorker and SharedWorker; no DOM or global callbacks. */
export async function createDiem(wasmURL = new URL('./diem.wasm', import.meta.url)) {
  const {exports} = await init({module: fetch(wasmURL), getImports: () => ({})});
  return {
    ...diemClient(exports, wasmURL, {deviceLinkProtocol: diemLinkProtocol}),
    async verifyProfile(encoding, now, crypto) {
      if(!validTime(now) || typeof crypto?.verify !== 'function') {
        throw new TypeError('Invalid profile verification request');
      }
      return profileInfo(await exports.verifyDiemProfile(bytes(encoding, 'profile'), now, crypto));
    }
  };
}

/** DiemProfileInfo with byte arrays as Uint8Array and application fields keyed by ID. */
function profileInfo(info) {
  return {...info, devices: info.devices.map(device => ({...device, key: new Uint8Array(device.key)})),
    applications: Object.fromEntries(info.applications.map(field => [field.id, new Uint8Array(field.value)]))};
}
