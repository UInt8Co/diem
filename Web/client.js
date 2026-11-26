// Diem's JavaScript API over a runtime's BridgeJS exports. An application's runtime spreads
// this object into its own client and adds its operations.
import {deviceKeys} from './crypto-support.js';
import {seeds} from './seeds.js';
import {hosting} from './hosting.js';
import {deviceLink} from './device-links.js';

/**
 * `exports` must include DiemWeb's `@JS` functions; `wasmURL` is reloaded by link realms.
 * `deviceLinkProtocol` calls the runtime's own device-link exports (see
 * device-link-protocol.js) and `deviceLinkWorker` replaces the link worker's URL.
 */
export function diemClient(exports, wasmURL, {deviceLinkProtocol, deviceLinkWorker}) {
  return {
    seeds: seeds(),
    deviceKeys,
    hosting: hosting(exports),
    deviceLink: deviceLink(exports, wasmURL, deviceLinkProtocol, deviceLinkWorker)
  };
}
