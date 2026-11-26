// The main realm's side of device linking. Plaintext seeds and the joining device's HPKE
// recipient live only in a disposable link realm: a DedicatedWorker running the
// application's link worker, or, where workers cannot be spawned (SharedWorker), a
// separate WASM instance whose heap is wiped.
import {diemLinkProtocol, linkBytes, linkParameter, wipe} from './device-link-protocol.js';

/**
 * The `deviceLink` API. `exports` are the client's BridgeJS exports (only `inspectDeviceLink`
 * runs there); `wasmURL` is loaded again in each link realm. `workerURL` must name a module
 * that exports `createLinkInstance` (see device-link-session.js) and serves link requests
 * when it runs as a DedicatedWorker.
 */
export function deviceLink(exports, wasmURL, protocol = diemLinkProtocol,
  workerURL = new URL('./device-link-worker.js', import.meta.url)) {
  const sessions = new WeakMap();
  const now = () => Math.floor(Date.now() / 1000);
  return {
    async begin(label) {
      if(typeof label !== 'string' || new TextEncoder().encode(label).length < 1 ||
        new TextEncoder().encode(label).length > 64) throw new TypeError('Invalid device-link label');
      const worker = linkWorker(wasmURL, workerURL, protocol);
      const {call, destroy} = worker;
      let opening = false;
      try {
        const result = await call('begin', {label});
        const session = Object.freeze({destroy});
        sessions.set(session, {
          async open(...args) {
            let opened;
            try {
              if(opening) throw new Error('Device-link session ended');
              opening = true;
              opened = await call('open', {...protocol.openInput(...args), now: now()});
              return protocol.opened(opened);
            } finally {
              wipe(protocol, opened);
              destroy(); sessions.delete(session);
            }
          }
        });
        return {request: new Uint8Array(result.request), parameter: result.parameter, session};
      } catch(error) { destroy(); throw error; }
    },
    async open(session, ...args) {
      const state = sessions.get(session);
      if(!state) throw new Error('Device-link session ended');
      return state.open(...args);
    },
    async respond(input) {
      const request = {...protocol.respondInput(input), now: now()};
      let worker;
      try {
        worker = linkWorker(wasmURL, workerURL, protocol);
        return new Uint8Array(await worker.call('respond', {input: request}));
      } finally { wipe(protocol, request); worker?.destroy(); }
    },
    async inspect(parameter, request) {
      const inspected = exports.inspectDeviceLink(linkParameter(parameter), linkBytes(request, 4096));
      return {...inspected, device: new Uint8Array(inspected.device)};
    }
  };
}

// Plaintext seeds use a disposable worker or isolated WASM heap, never the client's instance.
function linkWorker(wasmURL, url, protocol) {
  let objectURL, worker;
  const revoke = () => {
    if(objectURL) { URL.revokeObjectURL(objectURL); objectURL = undefined; }
  };
  try {
    if(typeof Worker === 'function') {
      if(globalThis.location && url.origin !== globalThis.location.origin) {
        objectURL = URL.createObjectURL(new Blob([`import ${JSON.stringify(url.href)};`], {type: 'text/javascript'}));
      }
      worker = new Worker(objectURL || url, {type: 'module'});
    } else worker = localLink(url, protocol);
  } catch(error) { revoke(); throw error; }
  const pending = new Map();
  let sequence = 0, closed = false;
  const destroy = () => {
    closed = true;
    revoke();
    worker.terminate();
    for(const {reject} of pending.values()) reject(new Error('Device-link session ended'));
    pending.clear();
  };
  worker.onmessage = ({data}) => {
    revoke();
    const call = pending.get(data.id);
    if(!call) { wipe(protocol, data.result); return; }
    pending.delete(data.id);
    data.error ? call.reject(new Error(data.error)) : call.resolve(data.result);
  };
  worker.onerror = event => {
    for(const {reject} of pending.values()) reject(new Error(event.message || 'Device-link worker failed'));
    destroy();
  };
  worker.onmessageerror = destroy;
  return {
    destroy,
    call(operation, input) {
      return new Promise((resolve, reject) => {
        if(closed) { reject(new Error('Device-link session ended')); return; }
        const id = ++sequence;
        pending.set(id, {resolve, reject});
        try { worker.postMessage({id, operation, ...input,
          wasmURL: new URL(wasmURL, globalThis.location?.href || import.meta.url).href}); }
        catch(error) { pending.delete(id); reject(error); destroy(); }
      });
    }
  };
}

function localLink(url, protocol) {
  let state, closed = false;
  const abort = new AbortController();
  const transport = {
    terminate() { closed = true; abort.abort(); state?.destroy(); },
    postMessage(data) {
      const ready = state ? Promise.resolve(state) : import(url.href).then(async module => {
        state = await module.createLinkInstance(data.wasmURL, abort.signal);
        if(closed) state.destroy();
        return state;
      });
      ready.then(value => value.call(data.operation, data)).then(result => {
        if(closed) { wipe(protocol, result); return; }
        transport.onmessage({data: {id: data.id, result}});
      }, error => {
        if(!closed) transport.onmessage({data: {id: data.id, error: error.message || String(error)}});
      });
    }
  };
  return transport;
}
