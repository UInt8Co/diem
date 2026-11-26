// Diem's web API. Applications that bundle Diem's modules into their own runtime reuse
// these declarations (see README.md, "Building an application runtime"). `DiemProfile`,
// `DiemDevice`, `DiemDeviceLinkOpened`, `DiemDeviceLinkApproval`, `DiemClient` and
// `createDiem` describe the standalone runtime's generic forms; applications declare their own.

/** Keys remain with the caller; callbacks belong to one operation only. */
export interface CryptoBackend {
  random(length: number): Uint8Array;
  /** Raw public bytes: Ed25519 (32) for identity, SEC1 P-256 (65) for device.
   * Return an empty identity key for device-only operations. */
  publicKey(role: 'identity' | 'device'): Uint8Array;
  /** Identity: Ed25519. Device: ECDSA with SHA-256, fixed-width 64-byte r‖s. */
  sign(role: 'identity' | 'device', bytes: number[]): Promise<Uint8Array>;
  verify(key: number[], data: number[], signature: number[]): Promise<boolean>;
}

/** A certified device. Times are exact decimal strings; the ID is lowercase hex. */
export interface DiemDevice {
  id: string;
  /** The device's Diem public-key encoding. */
  key: Uint8Array;
  notBefore: string;
  expiresAt: string;
}
/** Verified, application-independent profile facts. All integers are exact decimal
 * strings; IDs are lowercase hex. */
export interface DiemProfile {
  id: string;
  generation: string;
  revision: string;
  notBefore: string;
  expiresAt: string;
  /** True when now < notBefore or now >= expiresAt. Signatures still verify. */
  lapsed: boolean;
  domains: string[];
  /** The ID of the device that signed this revision. */
  signer: string;
  devices: DiemDevice[];
  /** Every application field by reverse-DNS ID, as the canonical CBOR of its value. */
  applications: Record<string, Uint8Array>;
}

/** One HTTP exchange. The default transport is `hosting.fetchTransport()`. */
export interface HostingHTTPRequest {method: 'GET' | 'HEAD' | 'PUT'; url: string;
  headers: Record<string, string>; body: number[] | null}
export interface HostingHTTPResponse {status: number; headers: Record<string, string>;
  body: Uint8Array | number[]}
export type HostingTransport = (request: HostingHTTPRequest) => Promise<HostingHTTPResponse>;

/** A proof-of-work puzzle: find a nonce (1–64 bytes) so that SHA-256(input ‖ nonce) has at
 * least `requiredBits` leading zero bits. `input` already binds domain, label and identity. */
export interface HostingPuzzle {label: string; input: number[]; requiredBits: number}
export type HostingSolver = (puzzle: HostingPuzzle) => Promise<Uint8Array | number[]>;

/** A DNS label targets a child; "@" (canonical) or {apex: true} targets the apex. */
export type HostingTarget = string | {apex: true};
export interface HostingPolicy {
  domain: string; apex: boolean;
  /** Present only when the host serves child names. */
  names?: HostingNamesPolicy;
}
export interface HostingNamesPolicy {
  labelPattern: string; maxClaimsPerIdentity: number;
  maxUpdatesPerIdentityPerHour: number; claimGraceAfterExpiry: number;
  proofOfWork: {algorithm: 'sha256-leading-zero-bits-v1'; baseBits: number;
    bitsPerShorterCharacter: number; referenceLength: number};
}
export interface HostingPlanName {
  label: string;
  status: 'invalid' | 'taken' | 'held' | 'needsProof';
  /** Set for needsProof. 0 means no proof is needed. */
  requiredBits: number | null;
  /** Set for needsProof with requiredBits > 0. */
  puzzle: HostingPuzzle | null;
}
export interface HostingPublished {identity: string; revision: string; domains: string[]}

export interface HostingProblemError {
  type: 'hostingProblem'; code: string; status: number; detail: string;
  labels: {label: string; reason: string; requiredBits: number | null}[];
  retryAfter: number | null;
}
export interface HostingClientError {
  type: 'invalidLabel' | 'nameTaken' | 'unsolvable' | 'invalidProof' | 'noHostedName'
    | 'hostNotListed' | 'domainMismatch' | 'publishedMismatch' | 'invalidResponse'
    | 'unexpectedStatus' | 'tooLarge' | 'cancelled' | 'unsupportedAlgorithm';
  /** Present for unexpectedStatus. */
  status?: number;
}

/** A platform-held P-256 signing key. Persist the CryptoKey by structured clone, never bytes. */
export interface DeviceKey {privateKey: CryptoKey; publicKey: Uint8Array}
/** The public key uses Diem's purpose-qualified encoding; signer is non-extractable Ed25519. */
export interface SeedIdentity {publicKey: Uint8Array; id: string; signer: CryptoKey}

export interface Seeds {
  generate(): {words: string[]; entropy: Uint8Array};
  /** ASCII-case-insensitive BIP 39 words; rejects bad words, count or checksum. */
  restore(phrase: string): Uint8Array;
  words(entropy: Uint8Array | number[]): string[];
  /** Optional identityPublicKey is a Diem encoding; rejects a mismatch. */
  identity(entropy: Uint8Array | number[], identityPublicKey?: Uint8Array | number[]): Promise<SeedIdentity>;
}

export interface Hosting {
  /** fetch with redirect:'error', credentials:'omit', cache:'no-store',
   * referrerPolicy:'no-referrer', a timeout (default 15 s) combined with `signal`, and a
   * streamed 262,144-byte response cap. */
  fetchTransport(options?: {signal?: AbortSignal; timeout?: number}): HostingTransport;
  policy(domain: string, transport?: HostingTransport): Promise<HostingPolicy>;
  /** `identity` is the lowercase hex identity ID. Ownership of claimed names is a hint
   * from the name's current profile; the host decides at publication. Include "@" in
   * labels for the apex; its difficulty must be supplied by the host. */
  plan(domain: string, labels: string[], identity: string,
    transport?: HostingTransport): Promise<HostingPlanName[]>;
  plan(domain: string, target: {apex: true}, identity: string,
    transport?: HostingTransport): Promise<HostingPlanName[]>;
  /** GET the child or apex profile bytes; null on 404. Does not verify signatures. */
  profile(domain: string, target: HostingTarget, transport?: HostingTransport): Promise<number[] | null>;
  /** Built-in single-threaded solver (@noble/hashes SHA-256 with a cloned prefix state,
   * 8-byte big-endian counters from `start` stepping by `stride`), yielding to the event
   * loop between batches. Rejects with type 'cancelled' when `signal` aborts.
   * Also usable as a HostingSolver: `puzzle => hosting.solve(puzzle)`. */
  solve(puzzle: HostingPuzzle, options?: {signal?: AbortSignal; start?: number;
    stride?: number; onProgress?: (attempts: number) => void}): Promise<number[]>;
  /** PUT the exact signed bytes. `via` defaults to the first direct child in signed
   * order, then a listed apex. "@" or {apex: true} selects
   * https://<domain>/.well-known/diem/profile.cbor. A string can also select a formerly
   * held name for release. Proofs map wire labels (including "@") to nonce bytes;
   * a solver answers one proof-required refusal and retries once.
   * Retry an unanswered PUT with the same saved bytes. */
  publish(domain: string, profile: Uint8Array | number[], options?: {via?: HostingTarget;
    proofs?: Record<string, number[]>; solver?: HostingSolver;
    transport?: HostingTransport}): Promise<HostingPublished>;
}

declare const deviceLinkSession: unique symbol;
export interface DeviceLinkSession {
  readonly [deviceLinkSession]: true;
  /** Releases the HPKE recipient, signer handle and WASM session; pending operations reject. */
  destroy(): void;
}
export interface DeviceLinkInspection {device: Uint8Array; label: string; verifies: number[]}
/** The joining side's result; applications extend it with their grant fields. */
export interface DeviceLinkOpened {
  profile: Uint8Array;
  domain: string;
  device: DeviceKey;
  /** The transferred 32-byte root, only when the approving device allowed it. Encrypt at rest. */
  seed?: Uint8Array;
}
export interface DiemDeviceLinkOpened extends DeviceLinkOpened {
  /** The grant's application fields by ID, as canonical CBOR values. */
  applications: Record<string, Uint8Array>;
}
export interface DiemDeviceLinkApproval {
  code: string;
  request: Uint8Array | number[];
  profile: Uint8Array | number[];
  domain: string;
  seed?: Uint8Array;
  /** At most 16 application fields by ID, each a canonical CBOR value. */
  applications?: Record<string, Uint8Array | number[]>;
}
/** `Open` is the arguments after the session; applications choose their own. */
export interface DeviceLink<Open extends unknown[], Opened extends DeviceLinkOpened, Approval> {
  /** Non-extractable P-256 device + fresh P-256 HPKE recipient; safe in any worker realm. */
  begin(label: string): Promise<{request: Uint8Array; parameter: string; session: DeviceLinkSession}>;
  /** Consumes the session on success or failure. */
  open(session: DeviceLinkSession, ...args: Open): Promise<Opened>;
  /** Call after certifying and publishing the exact profile. Supplying seed transfers approval authority. */
  respond(input: Approval): Promise<Uint8Array>;
  /** Checks the QR digest before decoding the public request. Check verifies before certifying. */
  inspect(parameter: string, request: Uint8Array | number[]): Promise<DeviceLinkInspection>;
}

export interface DiemClient {
  seeds: Seeds;
  deviceKeys: {generate(): Promise<DeviceKey>};
  hosting: Hosting;
  deviceLink: DeviceLink<[response: Uint8Array | number[]], DiemDeviceLinkOpened, DiemDeviceLinkApproval>;
  /** Verifies stored public profiles, including lapsed ones, without domain binding.
   * Callers own identity pinning and persistent generation/revision floors. */
  verifyProfile(encoding: number[] | Uint8Array, now: number, crypto: Pick<CryptoBackend, 'verify'>): Promise<DiemProfile>;
}
export function createDiem(wasmURL?: string | URL): Promise<DiemClient>;
