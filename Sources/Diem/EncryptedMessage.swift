import DiemPortable

public struct EncryptedMessage: Sendable {
  public enum Recipient: Sendable, Equatable {
    case device(DevicePublicKey, encapsulatedKey: [UInt8])
    case share(keyID: [UInt8])
  }
  public let recipient: Recipient
  public let ciphertext: [UInt8]
  public init(recipient: Recipient, ciphertext: [UInt8]) {
    self.recipient = recipient
    self.ciphertext = ciphertext
  }
  public static func context(for key: DevicePublicKey) -> [UInt8] {
    CBOR.array([.textString("Diem/encrypted"), .unsignedInt(2), bytes(key.encoding)]).encode()
  }
  public static func encrypt(
    _ payload: CBOR, to recipient: DevicePublicKey,
    using crypto: any DeviceCrypto
  ) throws -> Self {
    guard !recipient.algorithm.isSigning else { throw DiemError.roleConfusion }
    let box = try crypto.seal(
      CanonicalCBOR.encode(payload), to: recipient, context: context(for: recipient))
    return Self(
      recipient: .device(recipient, encapsulatedKey: box.encapsulatedKey),
      ciphertext: box.ciphertext)
  }
  public static func encrypt(
    _ payload: CBOR, to share: EncryptedShare,
    using crypto: any DiemCryptoBackend
  ) throws -> Self {
    try Self(recipient: .share(keyID: share.id), ciphertext: share.encrypt(payload, using: crypto))
  }
  public func toCBOR() -> CBOR {
    let header: CBOR
    switch recipient {
    case .device(let key, let encapsulatedKey):
      header = .array([.unsignedInt(0), bytes(key.encoding), bytes(encapsulatedKey)])
    case .share(let id): header = .array([.unsignedInt(1), bytes(id)])
    }
    return .array([.textString("Diem/encrypted"), .unsignedInt(2), header, bytes(ciphertext)])
  }
  public func encode() -> [UInt8] { toCBOR().encode() }
  public static func decode(_ encoded: [UInt8]) throws -> Self {
    let a = try CanonicalCBOR.array(encoded, count: 4)
    guard try string(a[0]) == "Diem/encrypted", try uint(a[1]) == 2,
      let h = try a[2].arrayValue(), let kind = h.first
    else { throw DiemError.invalidCBOR }
    let ciphertext = try octets(a[3])
    switch try uint(kind) {
    case 0:
      guard h.count == 3 else { throw DiemError.invalidCBOR }
      let key = try DevicePublicKey.decode(octets(h[1]))
      guard !key.algorithm.isSigning else { throw DiemError.roleConfusion }
      return try Self(
        recipient: .device(key, encapsulatedKey: octets(h[2])),
        ciphertext: ciphertext)
    case 1:
      guard h.count == 2 else { throw DiemError.invalidCBOR }
      return try Self(recipient: .share(keyID: octets(h[1], count: 32)), ciphertext: ciphertext)
    default: throw DiemError.invalidCBOR
    }
  }
}
