// The link realm's side of device linking: one disposable WASM instance per session.
import {deviceKeys} from './crypto-support.js';
import {linkBackend} from './link-crypto.js';
import {wipe} from './device-link-protocol.js';

/**
 * Returns `createLinkInstance(wasmURL, signal)` for an application's WASM. `init` is the
 * PackageToJS `init` of that WASM, whose exports include `beginDeviceLink`,
 * `destroyDeviceLink` and the protocol's open and respond functions.
 * A SharedWorker cannot spawn workers; its fallback owns a separate, wipeable WASM heap.
 */
export function linkInstanceFactory(init, protocol) {
  return async function createLinkInstance(wasmURL, signal) {
    let native = await init({module: fetch(wasmURL, {signal}), getImports: () => ({})});
    let session, device, closed = false, active = false;
    const dispose = () => {
      if(active || !native) return;
      const current = native, ending = session;
      native = undefined;
      session = device = undefined;
      try { if(ending) current.exports.destroyDeviceLink(ending); }
      finally { new Uint8Array(current.instance.exports.memory.buffer).fill(0); }
    };
    return {
      destroy() { closed = true; dispose(); },
      async call(operation, input) {
        if(closed || active) throw new Error('Device-link session ended');
        active = true;
        let opened, seed, returned = false;
        try {
          let result;
          if(operation === 'begin' && !session) {
            device = await deviceKeys.generate();
            result = await native.exports.beginDeviceLink(input.label, await linkBackend(device));
            session = result.session;
            result = {request: result.request, parameter: result.parameter};
          } else if(operation === 'open' && session) {
            const current = session;
            session = undefined;
            opened = await protocol.open(native.exports, current, input);
            seed = opened.seed == null ? undefined : new Uint8Array(opened.seed);
            result = {...opened, seed, device};
          } else if(operation === 'respond' && !session) {
            result = await protocol.respond(native.exports, input.input, await linkBackend());
          } else { throw new Error('Device-link session ended'); }
          if(closed) throw new Error('Device-link session ended');
          returned = true;
          return result;
        } finally {
          opened?.seed?.fill(0);
          if(!returned) { seed?.fill(0); wipe(protocol, opened); }
          wipe(protocol, input.input);
          active = false;
          if(operation !== 'begin' || !returned) closed = true;
          if(closed) dispose();
        }
      }
    };
  };
}

/** Serves link requests when this module runs as a DedicatedWorker; elsewhere a no-op. */
export function serveLinkWorker(createLinkInstance, protocol) {
  if(typeof DedicatedWorkerGlobalScope === 'undefined' || !(globalThis instanceof DedicatedWorkerGlobalScope)) return;
  let state;
  globalThis.onmessage = async({data}) => {
    let result, keep = false;
    try {
      state ??= await createLinkInstance(data.wasmURL);
      result = await state.call(data.operation, data);
      keep = data.operation === 'begin';
      globalThis.postMessage({id: data.id, result}, result.seed ? [result.seed.buffer] : []);
    } catch(error) {
      keep = false;
      globalThis.postMessage({id: data.id, error: error.message || String(error)});
    } finally {
      // A transferred seed is detached here; anything cloned is wiped.
      if(result?.seed?.byteLength) result.seed.fill(0);
      wipe(protocol, {...result, seed: undefined});
      wipe(protocol, data.input);
      if(!keep) { state?.destroy(); state = undefined; globalThis.close(); }
    }
  };
}
