import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';

export async function runDeviceLinkTests(page, engine) {
  const windowResult = await page.evaluate(async() => Promise.race([
    (await import('/tests/device-link.js')).run(),
    new Promise((_, reject) => setTimeout(() => reject(new Error('Device link Window timed out')), 30_000))
  ]));
  assert.equal(windowResult.realm, 'window');
  console.log(`PASS ${engine} device link Window`);
  for(const shared of [false, true]) {
    const result = await page.evaluate(shared => new Promise((resolve, reject) => {
      const worker = shared ? new SharedWorker('/tests/device-link-worker.js', {type: 'module'}) : new Worker('/tests/device-link-worker.js', {type: 'module'});
      const port = shared ? worker.port : worker;
      const timer = setTimeout(() => { cleanup(); reject(new Error('Device link worker timed out')); }, 30_000);
      const cleanup = () => { clearTimeout(timer); if(shared) port.close(); else worker.terminate(); };
      worker.onerror = event => { cleanup(); reject(new Error(event.message)); };
      port.onmessage = event => { cleanup(); event.data.error ? reject(new Error(event.data.error)) : resolve(event.data.result); };
      if(shared) port.start();
    }), shared);
    assert.equal(result.realm, 'worker');
    console.log(`PASS ${engine} device link ${shared ? 'SharedWorker' : 'DedicatedWorker'}`);
  }
  console.log(`PASS ${engine} device link Window, DedicatedWorker and SharedWorker: native requests, canonical records, request binding, bounds and rejection.`);
  await crossOriginLink(page.context().browser(), engine);
}

async function crossOriginLink(browser, engine) {
  const context = await browser.newContext();
  const page = await context.newPage();
  const runtime = 'https://diem-cdn.example/dist/diem.js';
  try {
    await page.route('https://diem-page.example/', route => route.fulfill({contentType: 'text/html',
      body: '<!doctype html><title>Cross-origin device link</title>'}));
    await context.route('https://diem-cdn.example/**', async route => {
      const path = new URL(route.request().url()).pathname;
      assert.ok(['/dist/diem.js', '/dist/device-link-worker.js', '/assets/link.wasm'].includes(path));
      await route.fulfill({body: await readFile(new URL(path.endsWith('.wasm') ? '../dist/diem.wasm' : '..' + path, import.meta.url)),
        contentType: path.endsWith('.wasm') ? 'application/wasm' : 'text/javascript',
        headers: {'Access-Control-Allow-Origin': '*'}});
    });
    await page.goto('https://diem-page.example/');
    const result = await page.evaluate(async runtime => {
      const client = await (await import(runtime)).createDiem('https://diem-cdn.example/assets/link.wasm');
      const create = URL.createObjectURL, revoke = URL.revokeObjectURL;
      const created = [], revoked = [];
      URL.createObjectURL = blob => { const url = create(blob); created.push(url); return url; };
      URL.revokeObjectURL = url => { revoked.push(url); revoke(url); };
      try {
        const begun = await client.deviceLink.begin('CDN desktop');
        try {
          const inspected = await client.deviceLink.inspect(begun.parameter, begun.request);
          return {label: inspected.label, verifies: inspected.verifies, bytes: begun.request.length, created, revoked};
        } finally { begun.session.destroy(); }
      } finally { URL.createObjectURL = create; URL.revokeObjectURL = revoke; }
    }, runtime);
    assert.equal(result.label, 'CDN desktop');
    assert.deepEqual(result.verifies, [1, 2]);
    assert.ok(result.bytes > 0);
    assert.equal(result.created.length, 1);
    assert.ok(result.created[0].startsWith('blob:https://diem-page.example/'));
    assert.deepEqual(result.revoked, result.created);
    console.log(`PASS ${engine} cross-origin Window device link: CDN worker, explicit WASM URL and blob revocation`);
  } finally {
    await context.close();
  }
}

// Standalone execution keeps failures in older suites from hiding these contract tests.
if(process.argv[1] && import.meta.url === (await import('node:url')).pathToFileURL(process.argv[1]).href) {
  const {createServer} = await import('node:http');
  const {readFile} = await import('node:fs/promises');
  const {chromium, webkit} = await import('@playwright/test');
  const engines = process.argv.slice(2).length ? process.argv.slice(2) : ['chromium'];
  const server = createServer(async(req, res) => {
    try {
      const path = new URL(req.url, 'http://localhost').pathname;
      if(!/^\/(dist|tests)\/[a-zA-Z0-9.-]+$/.test(path)) {
        res.setHeader('Content-Type', 'text/html');
        res.end('<!doctype html><title>Device link tests</title>'); return;
      }
      res.setHeader('Content-Type', path.endsWith('.wasm') ? 'application/wasm' : 'text/javascript');
      res.end(await readFile(new URL('..' + path, import.meta.url)));
    } catch { res.writeHead(404); res.end(); }
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  let browser;
  try {
    for(const name of engines) {
      const engine = {chromium, webkit}[name];
      if(!engine) throw new Error(`Unknown browser: ${name}`);
      browser = await engine.launch({headless: true, executablePath: process.env.DIEM_BROWSER_EXECUTABLE,
        ...(name === 'chromium' ? {args: ['--no-sandbox']} : {})});
      const page = await browser.newPage();
      page.on('pageerror', error => console.error(error));
      await page.goto(`http://127.0.0.1:${server.address().port}`);
      await runDeviceLinkTests(page, name);
      await browser.close(); browser = undefined;
    }
  } finally {
    await browser?.close();
    server.closeAllConnections();
    await new Promise(resolve => server.close(resolve));
  }
}
