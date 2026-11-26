import assert from 'node:assert/strict';
import {test} from 'node:test';
import {deviceLink} from '../device-links.js';
import {diemLinkProtocol} from '../device-link-protocol.js';

const wasmURL = new URL('../dist/diem.wasm', import.meta.url);
const workerURL = new URL('../device-link-worker.js', import.meta.url);

test('approvals isolate seeds and application fields and clear bridge inputs on success and worker failures', async() => {
  const original = globalThis.Worker;
  const seed = new Uint8Array(32).fill(123), field = new Uint8Array([0x43, 1, 2, 3]);
  const instances = [];
  let failure;
  globalThis.Worker = class {
    constructor() {
      if(failure === 'create') throw new Error('injected');
      instances.push(this);
    }
    terminate() { this.ended = true; }
    postMessage(message) {
      this.input = message.input;
      if(failure === 'post') throw new Error('injected');
      queueMicrotask(() => {
        if(failure === 'error') this.onerror({message: 'injected'});
        else if(failure === 'clone') this.onmessageerror();
        else this.onmessage({data: {id: message.id, ...(failure === 'operation' ? {error: 'injected'} : {result: [1]})}});
      });
    }
  };
  const exports = new Proxy({}, {get() { throw new Error('Main WASM must not handle approval'); }});
  try {
    const links = deviceLink(exports, wasmURL, diemLinkProtocol, workerURL);
    for(failure of [undefined, 'operation', 'error', 'clone', 'post', 'create']) {
      const action = () => links.respond({seed, code: 'code', domain: 'example.org', request: [], profile: [],
        applications: {'org.example.app': field}});
      if(failure) await assert.rejects(action);
      else assert.deepEqual(await action(), new Uint8Array([1]));
      assert.ok(seed.every(byte => byte === 123) && field[0] === 0x43, 'caller keeps ownership');
      for(const worker of instances) {
        assert.equal(worker.ended, true);
        assert.ok(worker.input.seed.every(byte => byte === 0));
        assert.ok(worker.input.applications[0].value.every(byte => byte === 0));
      }
    }
    for(const applications of [[], {'Bad.ID': []}, {'org.example.app': [256]}, Object.fromEntries(Array.from({length: 17}, (_, i) => [`org.example.a${i}`, []]))]) {
      await assert.rejects(() => links.respond({code: 'code', domain: 'example.org', request: [], profile: [], applications}), TypeError);
    }
  } finally { globalThis.Worker = original; seed.fill(0); }
});

test('link opening clears its source secrets and ends its worker on success and conversion failure', async() => {
  const original = globalThis.Worker;
  let source, field, failure, worker;
  globalThis.Worker = class {
    constructor() { worker = this; }
    terminate() { this.ended = true; }
    postMessage(message) {
      const result = message.operation === 'begin' ? {request: [], parameter: 'code'} :
        {profile: failure ? Symbol() : [1], domain: 'example.org', seed: source = new Uint8Array(32).fill(123),
          applications: [{id: 'org.example.app', value: field = [7, 7]}]};
      queueMicrotask(() => this.onmessage({data: {id: message.id, result}}));
    }
  };
  try {
    const links = deviceLink({}, wasmURL, diemLinkProtocol, workerURL);
    for(failure of [false, true]) {
      const {session} = await links.begin('Desktop');
      const action = () => links.open(session, []);
      if(failure) await assert.rejects(action);
      else {
        const opened = await action();
        try {
          assert.ok(opened.seed.every(byte => byte === 123));
          assert.deepEqual(opened.applications, {'org.example.app': new Uint8Array([7, 7])});
        } finally { opened.seed.fill(0); }
      }
      assert.ok(source.every(byte => byte === 0) && field.every(byte => byte === 0));
      assert.equal(worker.ended, true);
      await assert.rejects(() => links.open(session, []));
    }
  } finally { globalThis.Worker = original; source?.fill(0); }
});
