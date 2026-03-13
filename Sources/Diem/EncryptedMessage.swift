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
  public enum RecipientType: Sendable, Equatable {
    /// Encrypted for a specific key using HPKE.
    case key(cryptoSet: CryptoSet, keyID: [UInt8], encapsulatedKey: [UInt8])
    /// Encrypted for an ``EncryptedShare`` using symmetric encryption.
    case share(crypto: EncryptedShare.Crypto, keyID: [UInt8])
  }

  /// The recipient type and associated metadata.
  public let recipient: RecipientType
  /// The HPKE or symmetric ciphertext (authenticated ciphertext including AEAD tag).
  public let ciphertext: [UInt8]

  public init(recipient: RecipientType, ciphertext: [UInt8]) {
    self.recipient = recipient
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
      recipient: .key(
        cryptoSet: recipientPublicKey.cryptoSet,
        keyID: recipientPublicKey.id,
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
      recipient: .share(crypto: share.crypto, keyID: share.keyID),
      ciphertext: ciphertext)
  }
}

// MARK: - CBOR serialisation

extension EncryptedMessage {
  private enum Field: UInt64 {
    case recipient = 0
    case ciphertext = 1
  }

  private enum RecipientTypeTag: UInt64 {
    case key = 0
    case share = 1
  }

  private enum KeyField: UInt64 {
    case cryptoSet = 0
    case keyID = 1
    case encapsulatedKey = 2
  }

  private enum ShareField: UInt64 {
    case crypto = 0
    case keyID = 1
  }

  /// Encodes this message as a CBOR map with integer keys.
  public func toCBOR() -> CBOR {
    let recipientCBOR: CBOR
    switch recipient {
    case .key(let cryptoSet, let keyID, let encapsulatedKey):
      recipientCBOR = .tagged(
        RecipientTypeTag.key.rawValue,
        .map([
          CBORMapPair(
            key: .unsignedInt(KeyField.cryptoSet.rawValue),
            value: .unsignedInt(cryptoSet.rawValue)),
          CBORMapPair(
            key: .unsignedInt(KeyField.keyID.rawValue),
            value: .byteString(ArraySlice(keyID))),
          CBORMapPair(
            key: .unsignedInt(KeyField.encapsulatedKey.rawValue),
            value: .byteString(ArraySlice(encapsulatedKey))),
        ]))
    case .share(let crypto, let keyID):
      recipientCBOR = .tagged(
        RecipientTypeTag.share.rawValue,
        .map([
          CBORMapPair(
            key: .unsignedInt(ShareField.crypto.rawValue),
            value: .unsignedInt(crypto.rawValue)),
          CBORMapPair(
            key: .unsignedInt(ShareField.keyID.rawValue),
            value: .byteString(ArraySlice(keyID))),
        ]))
    }

    return .map([
      CBORMapPair(
        key: .unsignedInt(Field.recipient.rawValue),
        value: recipientCBOR),
      CBORMapPair(
        key: .unsignedInt(Field.ciphertext.rawValue),
        value: .byteString(ArraySlice(ciphertext))),
    ])
  }

  /// Decodes an ``EncryptedMessage`` from a CBOR map.
  public static func fromCBOR(_ cbor: CBOR) throws -> EncryptedMessage {
    guard let pairs = try cbor.mapValue() else { throw DiemError.invalidCBOR }
    var recipientCBOR: CBOR?
    var ciphertext: [UInt8]?

    for pair in pairs {
      guard case .unsignedInt(let k) = pair.key else { continue }
      switch k {
      case Field.recipient.rawValue:
        recipientCBOR = pair.value
      case Field.ciphertext.rawValue:
        ciphertext = pair.value.byteStringValue()
      default:
        break
      }
    }

    guard let recipientCBOR, let ciphertext else {
      throw DiemError.missingField("EncryptedMessage: recipient or ciphertext missing")
    }

    // Decode recipient type from tagged CBOR
    guard case .tagged(let tagRaw, let taggedValue) = recipientCBOR else {
      throw DiemError.invalidCBOR
    }

    let recipient: RecipientType
    switch tagRaw {
    case RecipientTypeTag.key.rawValue:
      guard let keyMap = try taggedValue.mapValue() else {
        throw DiemError.invalidCBOR
      }
      var cryptoSetRaw: UInt64?
      var keyID: [UInt8]?
      var encapsulatedKey: [UInt8]?

      for pair in keyMap {
        guard case .unsignedInt(let k) = pair.key else { continue }
        switch k {
        case KeyField.cryptoSet.rawValue:
          if case .unsignedInt(let v) = pair.value { cryptoSetRaw = v }
        case KeyField.keyID.rawValue:
          keyID = pair.value.byteStringValue()
        case KeyField.encapsulatedKey.rawValue:
          encapsulatedKey = pair.value.byteStringValue()
        default:
          break
        }
      }

      guard let cryptoSetRaw, let keyID, let encapsulatedKey else {
        throw DiemError.missingField(
          "EncryptedMessage.key: cryptoSet, keyID, or encapsulatedKey missing")
      }
      guard let cryptoSet = CryptoSet(rawValue: cryptoSetRaw) else {
        throw DiemError.invalidCBOR
      }
      recipient = .key(
        cryptoSet: cryptoSet, keyID: keyID, encapsulatedKey: encapsulatedKey)

    case RecipientTypeTag.share.rawValue:
      guard let shareMap = try taggedValue.mapValue() else {
        throw DiemError.invalidCBOR
      }
      var cryptoRaw: UInt64?
      var keyID: [UInt8]?

      for pair in shareMap {
        guard case .unsignedInt(let k) = pair.key else { continue }
        switch k {
        case ShareField.crypto.rawValue:
          if case .unsignedInt(let v) = pair.value { cryptoRaw = v }
        case ShareField.keyID.rawValue:
          keyID = pair.value.byteStringValue()
        default:
          break
        }
      }

      guard let cryptoRaw, let keyID else {
        throw DiemError.missingField("EncryptedMessage.share: crypto or keyID missing")
      }
      guard let crypto = EncryptedShare.Crypto(rawValue: cryptoRaw) else {
        throw DiemError.invalidCBOR
      }
      recipient = .share(crypto: crypto, keyID: keyID)

    default:
      throw DiemError.invalidCBOR
    }

    return EncryptedMessage(recipient: recipient, ciphertext: ciphertext)
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
