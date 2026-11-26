// What an application's device link exchanges: Diem's generic form, which applications
// replace piece by piece (see README.md, "Device linking for applications").

/** Copies an Array or Uint8Array of at most `limit` bytes. */
export function linkBytes(value, limit) {
  if(!(value instanceof Uint8Array || Array.isArray(value)) || value.length > limit) {
    throw new TypeError('Invalid device-link bytes');
  }
  for(const byte of value) {
    if(!Number.isInteger(byte) || byte < 0 || byte > 255) throw new TypeError('Invalid device-link bytes');
  }
  return Array.from(value);
}

/** A QR parameter: at most the base64url length of a 4,096-byte code. */
export function linkParameter(value) {
  if(typeof value !== 'string' || value.length > 5462) throw new TypeError('Invalid device-link parameter');
  return value;
}

const applicationID = /^(?=.{1,253}$)[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/;

/** {id: bytes} → [{id, value}] of canonical CBOR values; Swift checks the encodings. */
export function applicationFields(value, limit = 65536) {
  if(value == null) return [];
  if(typeof value !== 'object' || Array.isArray(value)) throw new TypeError('Invalid application fields');
  const ids = Object.keys(value);
  if(ids.length > 16 || ids.some(id => !applicationID.test(id))) throw new TypeError('Invalid application fields');
  const fields = [];
  try {
    for(const id of ids.sort()) fields.push({id, value: linkBytes(value[id], limit)});
    return fields;
  } catch(error) { for(const field of fields) field.value.fill(0); throw error; }
}

/**
 * Diem's generic protocol. The main realm calls `openInput(...args)` with the arguments
 * after the session, `respondInput(input)` and `opened(result)`; the link realm calls
 * `open` and `respond` on the WASM exports. Both wipe `secrets(value)` once a value is
 * delivered or abandoned. Session start and teardown (`beginDeviceLink`,
 * `destroyDeviceLink`) are shared by every application.
 */
export const diemLinkProtocol = {
  openInput(response) {
    return {response: linkBytes(response, 65536)};
  },
  respondInput(input) {
    if(typeof input?.domain !== 'string' || input.domain.length > 253) throw new TypeError('Invalid device-link approval');
    let seed, applications = [], returned = false;
    try {
      const code = linkParameter(input.code), request = linkBytes(input.request, 4096), profile = linkBytes(input.profile, 65536);
      seed = input.seed == null ? null : linkBytes(input.seed, 32);
      if(seed != null && seed.length !== 32) throw new TypeError('Invalid identity seed');
      applications = applicationFields(input.applications);
      const result = {code, request, profile, domain: input.domain, seed, applications};
      returned = true;
      return result;
    } finally { if(!returned) { seed?.fill(0); for(const field of applications) field.value.fill(0); } }
  },
  opened(result) {
    return {profile: new Uint8Array(result.profile), domain: result.domain,
      applications: Object.fromEntries(result.applications.map(field => [field.id, new Uint8Array(field.value)])),
      ...(result.seed == null ? {} : {seed: new Uint8Array(result.seed)}), device: result.device};
  },
  open(exports, session, input) {
    return exports.openDiemDeviceLink(session, input.response, input.now);
  },
  respond(exports, input, backend) {
    return exports.respondToDiemDeviceLink(input, backend);
  },
  secrets(value) {
    return [value?.seed, ...(Array.isArray(value?.applications) ? value.applications.map(field => field?.value) : [])];
  }
};

/** Zeroes every secret byte array of `value` that `protocol` names. */
export function wipe(protocol, value) {
  for(const secret of protocol.secrets(value)) secret?.fill?.(0);
}
