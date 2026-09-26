import DiemPortable

/// A private AES-256-GCM share key, distributed separately to each recipient's
/// wrapping key. This is private data; never place it in a public profile.
public struct EncryptedShare: Sendable, Identifiable {
  public let key: [UInt8]
  public let id: [UInt8]
  public var keyID: [UInt8] { id }
  public var hexID: String { id.hexString }

  public init(using crypto: any DeviceCrypto) {
    let key = crypto.randomBytes(count: 32)
    self.key = key
    self.id = Self.identifier(key, using: crypto)
  }
  public init(key: [UInt8], using crypto: any DeviceCrypto) throws {
    guard key.count == 32 else { throw DiemError.invalidKey }
    self.key = key
    self.id = Self.identifier(key, using: crypto)
  }
  private static func identifier(_ key: [UInt8], using crypto: any DeviceCrypto) -> [UInt8] {
    crypto.sha256(
      CBOR.array([.textString("Diem/share-key"), .unsignedInt(2), bytes(key)]).encode())
  }
  public func encrypt(_ payload: CBOR, using crypto: any DiemCryptoBackend) throws -> [UInt8] {
    try crypto.symmetricEncrypt(plaintext: CanonicalCBOR.encode(payload), key: key)
  }
  public func decrypt(_ ciphertext: [UInt8], using crypto: any DiemCryptoBackend) throws -> CBOR {
    try CanonicalCBOR.decode(crypto.symmetricDecrypt(ciphertext: ciphertext, key: key))
  }
  public func decrypt(_ message: EncryptedMessage, using crypto: any DiemCryptoBackend) throws
    -> CBOR
  {
    guard case .share(let keyID) = message.recipient, keyID == id else {
      throw DiemError.keyNotFound
    }
    return try decrypt(message.ciphertext, using: crypto)
  }
  public func invite(_ recipient: DevicePublicKey, using crypto: any DeviceCrypto) throws
    -> EncryptedMessage
  {
    try .encrypt(toCBOR(), to: recipient, using: crypto)
  }
  public func toCBOR() -> CBOR { .array([.textString("Diem/share"), .unsignedInt(2), bytes(key)]) }
  public func encode() -> [UInt8] { toCBOR().encode() }
  public init(cbor: CBOR, using crypto: any DeviceCrypto) throws {
    let a = try CanonicalCBOR.array(cbor.encode(), count: 3)
    guard try string(a[0]) == "Diem/share", try uint(a[1]) == 2 else { throw DiemError.invalidCBOR }
    try self.init(key: octets(a[2], count: 32), using: crypto)
  }
  public static func decode(_ encoded: [UInt8], using crypto: any DeviceCrypto) throws -> Self {
    try Self(cbor: CanonicalCBOR.decode(encoded), using: crypto)
  }
}
