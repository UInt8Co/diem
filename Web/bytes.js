// Input normalization shared by Diem's and applications' runtime adapters.

/** Copies an Array or Uint8Array of at most `limit` bytes into the plain Array BridgeJS takes. */
export function bytes(value, name, limit = 100_000) {
  if(!(Array.isArray(value) || value instanceof Uint8Array) || value.length > limit) throw new TypeError(`Invalid ${name} bytes`);
  const result = Array.from(value);
  if(!result.every(byte => Number.isInteger(byte) && byte >= 0 && byte <= 255)) throw new TypeError(`Invalid ${name} bytes`);
  return result;
}

/** Whole seconds from 0 to Number.MAX_SAFE_INTEGER. */
export function validTime(value) { return Number.isSafeInteger(value) && value >= 0; }

/** Lowercase-hex 32-byte IDs, such as identity IDs. */
export function idBytes(value, name) {
  if(typeof value !== 'string' || !/^[0-9a-f]{64}$/.test(value)) throw new TypeError(`Invalid ${name}`);
  return Array.from(value.match(/../g), pair => parseInt(pair, 16));
}
