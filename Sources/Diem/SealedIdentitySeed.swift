/// An identity seed encrypted to one encryption key, for storage or transfer.
public struct SealedIdentitySeed: Hashable, Sendable {
  /// CBOR field keys.
  public static let cborKeyTag: UInt64 = 0
  public static let cborKeyVersion: UInt64 = 1
  public static let cborKeyIdentityKey: UInt64 = 2
  public static let cborKeyRecipient: UInt64 = 3
  public static let cborKeyEncapsulatedKey: UInt64 = 4
  public static let cborKeyCiphertext: UInt64 = 5

  private var extensionFields: [UInt64: CBOR] = [:]

  public let identityKey: IdentityPublicKey
  /// The key that can open this box.
  public let recipient: EncryptionPublicKey
  public let box: SealedBox

  /// Decodes a sealed seed from its ``encoding``.
  public init(encoding: [UInt8]) throws(DiemError) {
    let a = try CBOR(decoding: encoding).recordValue(
      requiredKeys: Self.cborKeyTag..<(Self.cborKeyCiphertext + 1))
    guard a[Self.cborKeyTag]! == .text("Diem/sealed-identity-seed"),
      a[Self.cborKeyVersion]! == .unsigned(1)
    else {
      throw .invalidEncoding
    }
    identityKey = try IdentityPublicKey(
      PublicKey(encoding: a[Self.cborKeyIdentityKey]!.bytesValue()))
    recipient = try EncryptionPublicKey(encoding: a[Self.cborKeyRecipient]!.bytesValue())
    box = try SealedBox(
      encapsulatedKey: a[Self.cborKeyEncapsulatedKey]!.bytesValue(),
      ciphertext: a[Self.cborKeyCiphertext]!.bytesValue())
    extensionFields = a.filter { $0.key > Self.cborKeyCiphertext }
  }

  /// The canonical encoding.
  public var encoding: [UInt8] {
    CBOR.record(
      [
        Self.cborKeyTag: .text("Diem/sealed-identity-seed"), Self.cborKeyVersion: .unsigned(1),
        Self.cborKeyIdentityKey: .bytes(identityKey.key.encoding),
        Self.cborKeyRecipient: .bytes(recipient.encoding),
        Self.cborKeyEncapsulatedKey: .bytes(box.encapsulatedKey),
        Self.cborKeyCiphertext: .bytes(box.ciphertext),
      ], extensions: extensionFields
    ).encoded
  }

  /// The identity seed, decrypted with the recipient's `key`.
  public func open(with key: EncryptionPrivateKey, using backend: some CryptoBackend) async throws
    -> IdentitySeed
  {
    guard key.publicKey == recipient else { throw DiemError.identityMismatch }
    let secret = try await key.open(
      box, context: Self.context(identityKey: identityKey, recipient: recipient))
    do {
      let seed = try IdentitySeed(entropy: secret)
      _ = try await seed.identityKey(matching: identityKey, using: backend)
      return seed
    } catch {
      throw DiemError.decryptionFailed
    }
  }

  fileprivate init(identityKey: IdentityPublicKey, recipient: EncryptionPublicKey, box: SealedBox) {
    self.identityKey = identityKey
    self.recipient = recipient
    self.box = box
  }

  fileprivate static func context(identityKey: IdentityPublicKey, recipient: EncryptionPublicKey)
    -> [UInt8]
  {
    CBOR.record([
      Self.cborKeyTag: .text("Diem/sealed-identity-seed"), Self.cborKeyVersion: .unsigned(1),
      Self.cborKeyIdentityKey: .bytes(identityKey.key.encoding),
      Self.cborKeyRecipient: .bytes(recipient.encoding),
    ]).encoded
  }
}

extension IdentitySeed {
  /// This seed encrypted to `recipient`, bound to its derived identity.
  public func sealed(
    to recipient: EncryptionPublicKey, identity: IdentityPublicKey, using backend: some CryptoBackend
  ) async throws -> SealedIdentitySeed {
    _ = try await identityKey(matching: identity, using: backend)
    let context = SealedIdentitySeed.context(identityKey: identity, recipient: recipient)
    return SealedIdentitySeed(
      identityKey: identity, recipient: recipient,
      box: try await backend.seal(entropy, to: recipient, context: context))
  }
}
