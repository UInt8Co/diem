@_exported import Diem
import JavaScriptKit
import JavaScriptEventLoop

/// A ``CryptoBackend`` whose keys stay in JavaScript, usually as WebCrypto keys.
///
/// `crypto` supplies `random(count)`, `publicKey(role)` (`"identity"` or `"device"`: raw
/// Ed25519 or SEC1 P-256 bytes), `sign(role, message)` and `verify(key, message, signature)`.
/// Restoring an identity from its seed uses `restorePublicKey(raw)` and
/// `signRestored(raw, message)`; HPKE uses `encryptionPublicKey()`, `seal(recipient,
/// plaintext, context)` and `open(encapsulatedKey, ciphertext, context)`. An operation
/// needs only the callbacks it reaches. Diem owns every certificate, profile and wire rule.
///
/// The WASM target is single-threaded; each call retains its own callbacks.
public struct BrowserBackend: CryptoBackend, @unchecked Sendable {
  public let now: UInt64
  public let crypto: JSObject

  public init(now: UInt64, crypto: JSObject) {
    self.now = now
    self.crypto = crypto
  }

  public func randomBytes(count: Int) -> [UInt8] { bytes(crypto.random!(count)) }

  public func makePrivateKey(_ algorithm: PublicKey.Algorithm, for purpose: PublicKey.Purpose,
    restoring rawRepresentation: [UInt8]?) async throws -> PrivateKey {
    if let rawRepresentation {
      guard algorithm == .ed25519, purpose == .identity else { throw DiemError.unsupportedAlgorithm }
      let raw = bytes(try await JSPromise(crypto.restorePublicKey!(rawRepresentation).object!)!.value)
      return try PrivateKey(publicKey: PublicKey(purpose: purpose, algorithm: .ed25519,
        rawRepresentation: raw), protection: .software, rawRepresentation: rawRepresentation) { message in
        bytes(try await JSPromise(crypto.signRestored!(rawRepresentation, message).object!)!.value)
      }
    }
    guard algorithm == (purpose == .identity ? .ed25519 : .p256) else { throw DiemError.unsupportedAlgorithm }
    let role = purpose == .identity ? "identity" : "device"
    let raw = bytes(crypto.publicKey!(role))
    return try PrivateKey(publicKey: PublicKey(purpose: purpose, algorithm: algorithm,
      rawRepresentation: raw), protection: .nonExportable, rawRepresentation: nil) { message in
      let value = try await JSPromise(crypto.sign!(role, message).object!)!.value
      return bytes(value)
    }
  }

  public func isValidSignature(_ signature: [UInt8], for message: [UInt8], by key: PublicKey) async throws -> Bool {
    guard key.algorithm == .ed25519 || key.algorithm == .p256 else { throw DiemError.unsupportedAlgorithm }
    return try await JSPromise(crypto.verify!(
      key.rawRepresentation, message, signature).object!)!.value.boolean!
  }

  public func makeEncryptionKey(_ algorithm: EncryptionPublicKey.Algorithm,
    restoring rawRepresentation: [UInt8]?) async throws -> EncryptionPrivateKey {
    guard algorithm == .p256, rawRepresentation == nil else { throw DiemError.unsupportedAlgorithm }
    return try EncryptionPrivateKey(publicKey: EncryptionPublicKey(algorithm: .p256,
      rawRepresentation: bytes(crypto.encryptionPublicKey!())), protection: .software,
      rawRepresentation: nil) { box, context in
        secretBytes(try await JSPromise(crypto.open!(box.encapsulatedKey, box.ciphertext, context).object!)!.value)
      }
  }

  public func seal(_ plaintext: [UInt8], to key: EncryptionPublicKey, context: [UInt8]) async throws -> SealedBox {
    guard key.algorithm == .p256 else { throw DiemError.unsupportedAlgorithm }
    let box = try await JSPromise(crypto.seal!(key.rawRepresentation, plaintext, context).object!)!.value.object!
    return SealedBox(encapsulatedKey: bytes(box.encapsulatedKey), ciphertext: bytes(box.ciphertext))
  }
}

/// Copies a JavaScript array-like of bytes.
public func bytes(_ value: JSValue) -> [UInt8] {
  let array = JSObject.global.Array.from(value)
  return (0..<Int(array.length.number!)).map { UInt8(array[$0].number!) }
}

/// Copies a JavaScript byte array, then zeroes it.
public func secretBytes(_ value: JSValue) -> [UInt8] {
  let array = value.object!
  defer { _ = array.fill!(0) }
  return (0..<Int(array.length.number!)).map { UInt8(array[$0].number!) }
}

/// A JavaScript time in whole seconds, at most `Number.MAX_SAFE_INTEGER`.
public func seconds(_ value: Double) -> UInt64? {
  guard let time = UInt64(exactly: value), time <= 9_007_199_254_740_991 else { return nil }
  return time
}
