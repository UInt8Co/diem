import CBOR

// MARK: - EncryptedMessage

/// A message whose payload has been encrypted either for a specific recipient (using HPKE)
/// or for an ``EncryptedShare`` (using symmetric encryption).
///
/// ## Encryption to a Profile
/// ```swift
/// let msg = try EncryptedMessage.encrypt(payload, to: recipientKey, using: backend)
/// ```
///
/// ## Encryption to an EncryptedShare
/// ```swift
/// let msg = try EncryptedMessage.encrypt(payload, to: share, using: backend)
/// ```
///
/// ## Decryption
/// Use ``Identity/decrypt(_:)`` or ``EncryptedShare/decrypt(_:using:)`` depending on the recipient type.
///
/// Serialised as a CBOR map with integer keys (see ``toCBOR()``).
public struct EncryptedMessage: Sendable {
  /// The recipient type for this encrypted message.
  public enum RecipientType: Sendable {
    /// Encrypted for a specific profile using HPKE.
    case profile(cryptoSet: CryptoSet, recipientKeyID: [UInt8], encapsulatedKey: [UInt8])
    /// Encrypted for an ``EncryptedShare`` using symmetric encryption.
    case share(crypto: EncryptedShare.Crypto, shareKeyID: [UInt8])
  }

  /// The recipient type and associated metadata.
  public let recipientType: RecipientType
  /// The HPKE or symmetric ciphertext (authenticated ciphertext including AEAD tag).
  public let ciphertext: [UInt8]

  public init(recipientType: RecipientType, ciphertext: [UInt8]) {
    self.recipientType = recipientType
    self.ciphertext = ciphertext
  }

  // Convenience properties for backward compatibility
  /// Which crypto set was used for encryption (only for Profile recipients).
  public var cryptoSet: CryptoSet? {
    if case .profile(let cs, _, _) = recipientType { return cs }
    return nil
  }

  /// The key ID of the recipient's key-agreement public key (only for Profile recipients).
  public var recipientKeyID: [UInt8]? {
    if case .profile(_, let keyID, _) = recipientType { return keyID }
    return nil
  }

  /// The HPKE encapsulated key (only for Profile recipients).
  public var encapsulatedKey: [UInt8]? {
    if case .profile(_, _, let encKey) = recipientType { return encKey }
    return nil
  }

  /// The share crypto algorithm (only for EncryptedShare recipients).
  public var shareCrypto: EncryptedShare.Crypto? {
    if case .share(let crypto, _) = recipientType { return crypto }
    return nil
  }

  /// The share key ID (only for EncryptedShare recipients).
  public var shareKeyID: [UInt8]? {
    if case .share(_, let keyID) = recipientType { return keyID }
    return nil
  }
}

// Backward compatibility initializer for Profile-based encryption
extension EncryptedMessage {
  public init(
    cryptoSet: CryptoSet,
    recipientKeyID: [UInt8],
    encapsulatedKey: [UInt8],
    ciphertext: [UInt8]
  ) {
    self.recipientType = .profile(
      cryptoSet: cryptoSet,
      recipientKeyID: recipientKeyID,
      encapsulatedKey: encapsulatedKey)
    self.ciphertext = ciphertext
  }
}

// MARK: - Encryption to Profile

extension EncryptedMessage {
  /// Encrypts a CBOR payload for the holder of `recipientPublicKey` using HPKE.
  ///
  /// - Parameters:
  ///   - payload: The CBOR value to encrypt.
  ///   - recipientPublicKey: A ``PublicKeyEntry`` whose ``PublicKeyEntry/keyType`` is ``KeyType/keyAgreement``.
  ///   - backend: The crypto backend to use.
  /// - Throws: ``DiemError/invalidKeyType`` if the key is not a key-agreement key,
  ///           ``DiemError/unsupportedCryptoSet(_:)`` if the backend can't handle the key's set.
  public static func encrypt<Backend: DiemCryptoBackend>(
    _ payload: CBOR,
    to recipientPublicKey: PublicKeyEntry,
    using backend: Backend
  ) throws -> EncryptedMessage {
    guard recipientPublicKey.keyType == .keyAgreement else { throw DiemError.invalidKeyType }
    guard backend.supportedCryptoSets.contains(recipientPublicKey.cryptoSet) else {
      throw DiemError.unsupportedCryptoSet(recipientPublicKey.cryptoSet)
    }
    let (encapsulatedKey, ciphertext) = try backend.hpkeEncrypt(
      plaintext: payload.encode(),
      recipientPublicKey: recipientPublicKey.rawBytes,
      cryptoSet: recipientPublicKey.cryptoSet)
    return EncryptedMessage(
      recipientType: .profile(
        cryptoSet: recipientPublicKey.cryptoSet,
        recipientKeyID: recipientPublicKey.id,
        encapsulatedKey: encapsulatedKey),
      ciphertext: ciphertext)
  }

  /// Encrypts `payload` for a `Profile`, using the first key-agreement key for `cryptoSet`.
  ///
  /// - Throws: ``DiemError/keyNotFound`` if no matching key-agreement key exists.
  public static func encrypt<Backend: DiemCryptoBackend>(
    _ payload: CBOR,
    to recipient: Profile,
    cryptoSet: CryptoSet,
    using backend: Backend
  ) throws -> EncryptedMessage {
    guard
      let kaKey = recipient.keys.first(where: {
        $0.keyType == .keyAgreement && $0.cryptoSet == cryptoSet
      })
    else {
      throw DiemError.keyNotFound
    }
    return try encrypt(payload, to: kaKey, using: backend)
  }

  /// Encrypts `payload` for a `Profile`, automatically negotiating the best shared crypto set.
  ///
  /// Picks the highest-priority crypto set that both the backend and the recipient support,
  /// preferring ``CryptoSet/pqc`` over ``CryptoSet/classic``.
  ///
  /// - Throws: ``DiemError/keyNotFound`` if no common crypto set can be found.
  public static func encrypt<Backend: DiemCryptoBackend>(
    _ payload: CBOR,
    to recipient: Profile,
    using backend: Backend
  ) throws -> EncryptedMessage {
    let recipientSets = Set(recipient.keys.filter { $0.keyType == .keyAgreement }.map { $0.cryptoSet })
    let cryptoSet = try CryptoSet.negotiate(between: backend.supportedCryptoSets, and: recipientSets)
    return try encrypt(payload, to: recipient, cryptoSet: cryptoSet, using: backend)
  }
}

// MARK: - Encryption to EncryptedShare

extension EncryptedMessage {
  /// Encrypts a CBOR payload for an ``EncryptedShare`` using symmetric encryption.
  ///
  /// - Parameters:
  ///   - payload: The CBOR value to encrypt.
  ///   - share: The encrypted share whose symmetric key will be used.
  ///   - backend: The crypto backend to use.
  /// - Returns: An encrypted message that can be decrypted by anyone with the share's key.
  /// - Throws: ``DiemError/encryptionFailed`` if encryption fails.
  public static func encrypt<Backend: DiemCryptoBackend>(
    _ payload: CBOR,
    to share: EncryptedShare,
    using backend: Backend
  ) throws -> EncryptedMessage {
    let ciphertext = try share.encrypt(payload, using: backend)
    return EncryptedMessage(
      recipientType: .share(crypto: share.crypto, shareKeyID: share.keyID),
      ciphertext: ciphertext)
  }
}

// MARK: - CBOR serialisation

extension EncryptedMessage {
  private enum Field: UInt64 {
    case recipientKeyID = 0
    case cryptoSet = 1
    case encapsulatedKey = 2
    case ciphertext = 3
    case shareKeyID = 4
    case shareCrypto = 5
  }

  /// Encodes this message as a CBOR map with integer keys.
  public func toCBOR() -> CBOR {
    switch recipientType {
    case .profile(let cryptoSet, let recipientKeyID, let encapsulatedKey):
      return .map([
        CBORMapPair(
          key: .unsignedInt(Field.recipientKeyID.rawValue),
          value: .byteString(ArraySlice(recipientKeyID))),
        CBORMapPair(
          key: .unsignedInt(Field.cryptoSet.rawValue),
          value: .unsignedInt(cryptoSet.rawValue)),
        CBORMapPair(
          key: .unsignedInt(Field.encapsulatedKey.rawValue),
          value: .byteString(ArraySlice(encapsulatedKey))),
        CBORMapPair(
          key: .unsignedInt(Field.ciphertext.rawValue),
          value: .byteString(ArraySlice(ciphertext))),
      ])
    case .share(let crypto, let shareKeyID):
      return .map([
        CBORMapPair(
          key: .unsignedInt(Field.shareKeyID.rawValue),
          value: .byteString(ArraySlice(shareKeyID))),
        CBORMapPair(
          key: .unsignedInt(Field.shareCrypto.rawValue),
          value: .unsignedInt(crypto.rawValue)),
        CBORMapPair(
          key: .unsignedInt(Field.ciphertext.rawValue),
          value: .byteString(ArraySlice(ciphertext))),
      ])
    }
  }

  /// Decodes an ``EncryptedMessage`` from a CBOR map.
  public static func fromCBOR(_ cbor: CBOR) throws -> EncryptedMessage {
    guard let pairs = try cbor.mapValue() else { throw DiemError.invalidCBOR }
    var recipientKeyID: [UInt8]?
    var cryptoSetRaw: UInt64?
    var encapsulatedKey: [UInt8]?
    var ciphertext: [UInt8]?
    var shareKeyID: [UInt8]?
    var shareCryptoRaw: UInt64?

    for pair in pairs {
      guard case .unsignedInt(let k) = pair.key else { continue }
      switch k {
      case Field.recipientKeyID.rawValue: recipientKeyID = pair.value.byteStringValue()
      case Field.cryptoSet.rawValue:
        if case .unsignedInt(let v) = pair.value { cryptoSetRaw = v }
      case Field.encapsulatedKey.rawValue: encapsulatedKey = pair.value.byteStringValue()
      case Field.ciphertext.rawValue: ciphertext = pair.value.byteStringValue()
      case Field.shareKeyID.rawValue: shareKeyID = pair.value.byteStringValue()
      case Field.shareCrypto.rawValue:
        if case .unsignedInt(let v) = pair.value { shareCryptoRaw = v }
      default: break
      }
    }

    guard let ciphertext else {
      throw DiemError.missingField("EncryptedMessage: ciphertext missing")
    }

    // Determine which type of message this is
    if let shareKeyID, let shareCryptoRaw {
      guard let shareCrypto = EncryptedShare.Crypto(rawValue: shareCryptoRaw) else {
        throw DiemError.invalidCBOR
      }
      return EncryptedMessage(
        recipientType: .share(crypto: shareCrypto, shareKeyID: shareKeyID),
        ciphertext: ciphertext)
    } else if let recipientKeyID, let cryptoSetRaw, let encapsulatedKey {
      guard let cryptoSet = CryptoSet(rawValue: cryptoSetRaw) else { throw DiemError.invalidCBOR }
      return EncryptedMessage(
        recipientType: .profile(
          cryptoSet: cryptoSet,
          recipientKeyID: recipientKeyID,
          encapsulatedKey: encapsulatedKey),
        ciphertext: ciphertext)
    } else {
      throw DiemError.missingField(
        "EncryptedMessage: either (shareKeyID + shareCrypto) or (recipientKeyID + cryptoSet + encapsulatedKey) required")
    }
  }

  /// Serialises this message to CBOR bytes.
  public func encode() -> [UInt8] { toCBOR().encode() }

  /// Deserialises an ``EncryptedMessage`` from CBOR bytes.
  public static func decode(_ bytes: [UInt8]) throws -> EncryptedMessage {
    let cbor: CBOR
    do { cbor = try CBOR.decode(bytes) } catch { throw DiemError.invalidCBOR }
    return try fromCBOR(cbor)
  }
}
