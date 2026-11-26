# Diem for web clients

Diem's browser runtime runs Diem's canonical profile, hosting and device-link rules,
compiled from Swift to WebAssembly, in windows, dedicated workers and shared workers.
BridgeJS generates the JavaScript ABI. WebCrypto signs with seed-derived Ed25519 identity
keys and non-extractable ECDSA P-256 device keys, and verifies both algorithms.
Applications own encrypted seed storage, platform key persistence, publication and user
consent.

The package has two halves. The `DiemWeb` Swift library exports the shared `@JS` API
(hosting and device-link sessions); the JavaScript modules beside this file wrap it. The
standalone runtime (`diem.js`, `diem.wasm`, `device-link-worker.js`) is DiemWeb plus the
`DiemWebRuntime` executable's generic `ProfileRecord` forms of profile verification and
device linking. An application builds its own runtime from the same Swift library and
JavaScript modules, supplies its own forms of those, and ships one WASM (see
[Building an application runtime](#building-an-application-runtime)).

```js
import {createDiem} from './diem.js';
const diem = await createDiem(new URL('./diem.wasm', import.meta.url));
const info = await diem.verifyProfile(bytes, Math.floor(Date.now() / 1000), {verify});
```

## API

`diem.d.ts` declares the API and `bridge-js.d.ts` the generated ABI. Bytes are arrays of
integers from 0 to 255; the runtime also accepts `Uint8Array`. Integers that may exceed
2^53 are decimal strings. Times are safe-integer Unix seconds. Failures reject with an
`Error` whose message is the `DiemError` case name (for example `invalidSignature`),
except hosting failures, which are objects with a `type` (see
[Profile hosting](#profile-hosting)), and invalid arguments, which are `TypeError`s.

Crypto callbacks belong to one operation: `random(count)`, `publicKey(role)` (raw
Ed25519 identity bytes, 32, or SEC1 P-256 device bytes, 65; an empty identity key for
device-only operations), `sign(role, message)` (Ed25519, or the WebCrypto fixed-width
64-byte ECDSA r‖s) and `verify(key, message, signature)`, which chooses the algorithm from
the key length. Operations call only the callbacks they need.

`verifyProfile(encoding, now, crypto)` verifies a stored public profile without domain
binding or private keys; only `crypto.verify` is required. Diem validates the record,
every device certificate and the content signature at the profile's `notBefore`. The
result has `id` (lowercase hex), `generation`, `revision`, `notBefore`, `expiresAt`,
`lapsed`, ordered `domains`, the `signer` device ID, `devices` (`{id, key, notBefore,
expiresAt}`, `key` being Diem's encoding) and `applications`: every application field
by reverse-DNS ID as the canonical CBOR encoding of its value, which the application
decodes itself. `lapsed` is true when `now < notBefore` or `now >= expiresAt`; such
profiles still verify because hosts return their latest stored profile after expiry.
This is a stateless check: callers bind the result to the expected identity and keep
monotonic generation/revision floors. Listed domains are signed claims, not proof of
current domain control.

## Profile hosting

`hosting.policy(domain, transport?)` returns `{domain, apex, names?}`. `apex` is always
boolean; `names` is present only for hosts serving child names and holds `labelPattern`,
`maxClaimsPerIdentity`, `maxUpdatesPerIdentityPerHour`, `claimGraceAfterExpiry` and
`proofOfWork: {algorithm, baseBits, bitsPerShorterCharacter, referenceLength}`.
An apex-only policy is `{domain: 'id.example', apex: true}`.
`hosting.plan(domain, labels, identity, transport?)` returns `invalid`, `taken`, `held`
or `needsProof` names, with the difficulty and puzzle for new names. Pass the lowercase
hex identity ID. Held names are unverified discovery hints; publication decides ownership.
Include the reserved wire label `"@"` in the label list to plan the apex, e.g.
`hosting.plan(domain, ['@', 'alice'], identity, transport?)`. The apex entry has
`label: '@'` and the same status/difficulty/puzzle fields as child entries. Status comes
from `GET /.well-known/diem/hosting/names/@`; claimed status fetches the apex profile
to distinguish `held` from `taken`. Apex work requires explicit host `requiredBits`;
missing difficulty rejects as `unsolvable`, with no label-length fallback.
`hosting.plan(domain, {apex: true}, identity, transport?)` is an alias for `['@']`.
`hosting.profile(domain, labelOrApex, transport?)` fetches raw profile bytes, or `null`
on 404. Pass a child label, `'@'` (canonical), or `{apex: true}`; verify bytes separately.
`hosting.solve(puzzle, {signal, start, stride, onProgress}?)` searches eight-byte counters
and yields between batches. `onProgress` reports cumulative attempts; difficulty describes
expected work, not a completion time. Applications can inject their own solver or distribute
counter strides among workers. Cancellation rejects with `type: 'cancelled'`.

Sign a revision listing the desired names and persist it before
`hosting.publish(domain, profile, {proofs, solver, transport, via}?)`.
Proofs map labels to nonce bytes and are sent as given for the host to check; a solver
answers one `proof-required` refusal, its nonces checked natively, and publication
retries once. Publication accepts any Diem profile, whatever its application fields, and
returns the identity in hex, revision as a decimal string and hosted domains in signed
order. Retry an unanswered PUT with the same saved bytes. `via` accepts a child label,
`'@'` (canonical), or `{apex: true}`. With no `via`, publication selects the first direct
child in signed domain order, then a listed apex. An apex claim lists the hosting domain
itself; explicit apex PUTs go to `https://<domain>/.well-known/diem/profile.cbor`. Apex
proofs use `proofs: {'@': nonce}` and `Diem-Hosting-Proof: @=<base64url nonce>`;
proof-required refusals for `@` invoke the solver and retry once, just like child names.
Puzzles bind the host, wire label `@` and identity. Validation accepts exactly `@` or a
lowercase DNS label. A string can select a formerly held name for a full release; a
completed full release may not be repeatable at that old name.

```js
const policy = await diem.hosting.policy('id.example');
if(policy.apex) {
  const plan = await diem.hosting.plan('id.example', ['@'], identityHex);
  await diem.hosting.publish('id.example', signedProfile, {via: '@',
    solver: puzzle => diem.hosting.solve(puzzle)});
  const bytes = await diem.hosting.profile('id.example', '@');
}
```

For discovery, probe the profile's first domain for a valid policy with `apex: true`,
then its parent for a policy with `names`, then use manual HTTPS publication. Unavailable,
invalid or mismatched policies move to the next step.

`hosting.fetchTransport({signal, timeout}?)` defaults to a 15-second timeout, refuses
redirects, omits credentials and referrers, disables caching and caps streamed responses at
262,144 bytes. Custom transports and solvers return promises; their errors propagate unchanged
(including `AbortError`). They must settle on cancellation so Swift can finish the operation.
Host refusals have `type: 'hostingProblem'`, wire `code`, `status`, `detail`, `labels` and
nullable `retryAfter` seconds. Client failures have a stable `type`; see `diem.d.ts`.

## Recovery words and custody

`seeds.generate()` returns `{words, entropy}`: 24 BIP 39 English recovery words and their
32-byte root. `seeds.restore(phrase)` returns the entropy, ignoring ASCII case and
whitespace and rejecting unknown words, a bad word count or checksum.
`seeds.words(entropy)` shows those words again. Words are the only backup; applications
show and verify them during creation and require device authentication or an explicit
confirmation before showing them again.

`await seeds.identity(entropy, identityPublicKey?)` derives Ed25519 with WebCrypto
HKDF-SHA256 as Diem's `IdentitySeed` does, optionally checks the expected Diem identity
encoding, then returns `{publicKey, id, signer}`. `publicKey` is Diem's encoded identity
key, `id` is its lowercase hex digest, and `signer` is a non-extractable Ed25519
CryptoKey. The word codec and public-key computation run in JavaScript; entropy never
enters the client's WASM instance. Intermediate buffers are cleared. Callers clear
entropy buffers when their operation ends. `Tests/Vectors/identity-seed.json` pins the
derivation.

`await deviceKeys.generate()` returns `{privateKey, publicKey}`. The private CryptoKey
is generated as ECDSA P-256 with `extractable:false` and `usages:['sign']`; the public
key is raw 65-byte SEC1. Persist the CryptoKey object in IndexedDB by structured clone.
Never export or serialize device private keys. A device key serves exactly one session.
WebCrypto custody is `KeyProtection.nonExportable`, without a hardware guarantee.
On Safari/WebKit, persist or transfer CryptoKeys only from a Window or DedicatedWorker;
a SharedWorker can hold them only in memory.

Store each account's seed encrypted with AES-GCM under a separate non-extractable
CryptoKey kept in IndexedDB. Use a new 12-byte random IV for each encryption. Applications
own storage transactions, local deletion, optional passcode locking and user consent.
Signing out deletes that account's device CryptoKey and encrypted seed.

```js
const {words, entropy} = diem.seeds.generate();
const identity = await diem.seeds.identity(entropy);
const device = await diem.deviceKeys.generate();
const backend = {
  random: n => crypto.getRandomValues(new Uint8Array(n)),
  publicKey: role => role === 'identity' ? identity.publicKey.slice(-32) : device.publicKey,
  sign: async(role, bytes) => new Uint8Array(await crypto.subtle.sign(
    role === 'identity' ? 'Ed25519' : {name:'ECDSA', hash:'SHA-256'},
    role === 'identity' ? identity.signer : device.privateKey, new Uint8Array(bytes))),
  verify: verifyRawPublicKey
};
```

Recovery fetches the current trusted profile, checks it with `verifyProfile`, derives
`seeds.identity(entropy, expectedIdentityPublicKey)`, generates a fresh device and has
the identity certify it; the application's runtime owns that signing operation.

## QR device linking

`deviceLink.begin(label)` returns `{request, parameter, session}`. Send `request` to the
approving device through the application's relay and put `parameter` in the QR URL under
the application's own parameter name. Labels are untrusted 1–64 UTF-8 bytes. Each session
generates a non-extractable P-256 device and an ephemeral P-256 HPKE recipient. Window and
dedicated-worker callers use a disposable module worker for each link session and
approval. SharedWorker cannot spawn a worker; it uses a separate WASM instance whose full
linear memory is wiped before release, after any in-flight operation settles. Plaintext
transfer seeds never enter the client's long-lived WASM instance. Vendor
`device-link-worker.js` beside `diem.js` and allow module workers under the Content
Security Policy described below. Call `session.destroy()` on cancellation.

The seed-holding approver calls `deviceLink.inspect(parameter, request)`, checks both
verification algorithms (identity Ed25519 = 1, device P-256 = 2), certifies `device`,
saves the new profile, and publishes its exact bytes before approving:

```js
const response = await diem.deviceLink.respond({
  code: parameter, request, profile: publishedProfile, domain,
  seed: allowThisDeviceToApproveSignIns ? entropy : undefined,
  applications: {'org.example.app': cborValue}
});
const opened = await diem.deviceLink.open(session, response);
// opened = {profile, domain, applications, device: {privateKey: CryptoKey, publicKey: Uint8Array},
//           seed?: Uint8Array}
```

Seed transfer is opt-in; the approval toggle defaults off. `applications` carries at most
16 grant fields, each a canonical CBOR value; Diem neither interprets nor restricts them,
and an application states its own rules (see below). `respond` checks the QR digest,
capabilities, current published authority and any transferred seed's identity binding.
The library cannot prove remote publication; callers own publication and consent.
`open` checks the listed domain, the device's certification in the current generation
and the optional seed binding. Success or failure ends the session. The returned device
is a CryptoKey handle; no device secret crosses the API. Persist the device and
optional encrypted seed before completing sign-in. The QR secret never reaches the
relay, which carries ciphertext only. The wire rules are in Diem's `DeviceLink.swift`.

## Building an application runtime

An application's runtime is one WASM holding DiemWeb's `@JS` API and its own, plus one
JavaScript bundle and one link worker built from Diem's modules. It does not link the
standalone runtime's generic `ProfileRecord` exports, so it pays only for its own profile
type.

**Swift.** Link the `DiemWeb` library into the application's web executable, keeping the
BridgeJS plugin on both. PackageToJS collects every linked target's BridgeJS skeleton,
so the application's WASM exports DiemWeb's functions as well. BridgeJS resolves `@JS`
types only within one package: to use DiemWeb's `@JS` structs in its own `@JS`
declarations, the application compiles DiemWeb as a target of its own package (its
`Sources/DiemWeb/bridge-js.config.json` exposes the types). Otherwise it maps DiemWeb's
public Swift values into its own `@JS` structs. All `@JS` names share one JavaScript
namespace, so the application must not reuse DiemWeb's exported names: the functions
`hostingPolicy`, `hostingPlan`, `hostingPublish`, `hostingProfile`, `inspectDeviceLink`,
`beginDeviceLink` and `destroyDeviceLink`, and the structs `Hosting*Info`,
`DeviceLinkInspection` and `DeviceLinkBeginning`. The standalone executable
(`Sources/DiemWebRuntime`) adds `verifyDiemProfile`, `openDiemDeviceLink`,
`respondToDiemDeviceLink` and the structs `DiemApplicationField`, `DiemDeviceInfo`,
`DiemProfileInfo`, `DiemDeviceLinkOpening` and `DiemDeviceLinkApproval`; they are a
reference for an application's own forms.

DiemWeb's public Swift support is `BrowserBackend` (the WebCrypto `CryptoBackend`),
`bytes(_:)`, `secretBytes(_:)`, `seconds(_:)`, `diemErrorCode(_:)`, `bridgeError(_:)` and
`hostingError(_:)`, the hosting callbacks `BrowserHostingHTTP` and `BrowserHostingSolver`,
and `WebDeviceLink`, whose `open` and `respond` take the application's profile type, its
`accept` check (the verified profile and the grant, before any seed is opened) and its
grant fields. An application's `@JS` open and respond call these with its own rules;
`begin`, `inspect` and `destroy` are DiemWeb's.

**JavaScript.** Bundle these modules into the application's entry points. Their export
names are stable:

| Module | Exports |
| --- | --- |
| `bytes.js` | `bytes(value, name, limit)`, `validTime(seconds)`, `idBytes(hex, name)` |
| `crypto-support.js` | `deviceKeys`, `signingBackend(identity, device)`, `verify`, `requireDevice`, `importIdentity`, `identityPublicKey` |
| `seeds.js`, `seed-words.js` | `seeds()`, `identityContext`; `seedWords` |
| `link-crypto.js` | `linkBackend(device?)`: the HPKE recipient and seed callbacks of a link realm |
| `hosting.js` | `hosting(exports)`, `fetchTransport(options)` |
| `client.js` | `diemClient(exports, wasmURL, {deviceLinkProtocol, deviceLinkWorker?})`: `seeds`, `deviceKeys`, `hosting`, `deviceLink` |
| `device-link-protocol.js` | `diemLinkProtocol`, `linkBytes`, `linkParameter`, `applicationFields`, `wipe` |
| `device-links.js` | `deviceLink(exports, wasmURL, protocol, workerURL?)` |
| `device-link-session.js` | `linkInstanceFactory(init, protocol)`, `serveLinkWorker(createLinkInstance, protocol)` |

`runtime.js` and `device-link-worker.js` are the standalone entry points: they import the
standalone build's generated `init`, so applications write their own two entries instead.
The application's runtime spreads `diemClient(exports, wasmURL, {deviceLinkProtocol})`
into its client and adds its operations (such as its own `verifyProfile`). Its
link worker module is
`export const createLinkInstance = linkInstanceFactory(init, protocol);
serveLinkWorker(createLinkInstance, protocol);` and must be served as
`device-link-worker.js` beside the runtime bundle, or passed as `deviceLinkWorker`.

A device-link protocol is `diemLinkProtocol` with any of its members replaced; an
application replaces at least `open` and `respond`, since its WASM lacks the generic
exports:
`openInput(...args)` validates the arguments after the session that `deviceLink.open`
receives, `respondInput(input)` the approval, and `opened(result)` shapes the result; in
the link realm, `open(exports, session, input)` and `respond(exports, input, backend)` call
the application's `@JS` functions (`input.now` is added by the machinery); and
`secrets(value)` lists the byte arrays to wipe once a value is delivered or abandoned.

esbuild resolves bare imports (`@noble/curves`, `@noble/hashes`, `@hpke/core`) from the
importing file's directory, so a bundle that reads these modules from a Diem checkout
must resolve them from the application's own `node_modules`, for example with
`nodePaths: ['<web>/node_modules']`. Use the versions in this package's `package.json`.

## Vendoring a release

Each successful `main` push that changes the web runtime or the Diem sources it builds
publishes a GitHub release named `web-YYYYMMDD-<sha4>`. Download a specific release and
verify `SHA256SUMS`. Vendor its matching `diem.js`, `device-link-worker.js`, `diem.wasm`, declarations and license files
together; retain the release tag and `manifest.json` with the checksums and source
revision.

Serve WASM as `application/wasm`. Supply an explicit WASM URL when relocating the
assets. The `.br` and `.gz` files require the corresponding `Content-Encoding`.
Consumers need no Swift toolchain or external runtime downloads.

When the runtime is served from another origin, device linking uses a disposable
`blob:` module worker that imports the absolute worker asset URL. Content Security
Policy must allow `worker-src blob:` as well as the runtime origin in `script-src`
and the WASM origin in `connect-src`; CDN assets require CORS headers. The blob URL
is revoked after the worker responds or when it is destroyed. Same-origin workers
and the isolated SharedWorker fallback keep their existing loading paths.

## Build and test

Install Swift 6.4, the `swift-6.4.0-RELEASE_wasm-embedded` SDK, Binaryen 133,
Node 24 and pnpm. From `Web/`:

```sh
pnpm install --frozen-lockfile
pnpm build
pnpm exec playwright install --with-deps chromium
pnpm test chromium
```

For Safari coverage, install Playwright WebKit on macOS with
`pnpm exec playwright install webkit`, then run `pnpm test webkit` against the same
`Web/dist/` package. `pnpm test` without browser arguments runs both engines.
CI builds once on Linux, checks Chromium there and checks the same artifacts with
WebKit on macOS. Linux WebKit uses a different cryptographic backend with intermittent
Ed25519 key-generation failures; macOS exercises Safari's native backend.

`DIEM_SWIFT`, `WASM_OPT` and `DIEM_BROWSER_EXECUTABLE` select installed tools (the
browser override applies to each requested browser; select one engine when overriding).
Build output is in `Web/dist/`. The build pins dependencies, runs the Node unit tests,
generates BridgeJS bindings, minimizes the Embedded Swift binary and enforces artifact
size limits. Browser tests run real WebCrypto operations in Window, DedicatedWorker and
SharedWorker: Diem's committed profile vectors and independently signed profiles,
profile hosting against an independent host, recovery words, non-extractable P-256
signatures, IndexedDB CryptoKey custody, and device-link round trips with seed transfer
and application fields. In WebKit SharedWorkers, tests require IndexedDB CryptoKey
writes to fail with `DataCloneError` and continue with in-memory keys.
The [release workflow](../.github/workflows/web-release.yml) owns CI tool installation,
testing and packaging.
