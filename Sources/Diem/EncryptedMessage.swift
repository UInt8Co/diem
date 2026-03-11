import CBOR

// MARK: - EncryptedMessage

/// A message whose payload has been encrypted for a specific recipient using HPKE.
///
/// The ``cryptoSet``, ``recipientKeyID``, and ``encapsulatedKey`` are stored in the clear;
/// only ``ciphertext`` is opaque.
///
/// ## Encryption
/// ```swift
/// let msg = try EncryptedMessage.encrypt(payload, to: recipientKey, using: backend)
/// ```
///
/// ## Decryption
/// Use ``Identity/decrypt(_:)`` on the recipient's identity.
///
/// Serialised as a CBOR map with integer keys (see ``toCBOR()``).
public struct EncryptedMessage: Sendable {
  /// Which crypto set was used for encryption.
  public let cryptoSet: CryptoSet
  /// The key ID of the recipient's key-agreement public key.
  public let recipientKeyID: [UInt8]
  /// The HPKE encapsulated key (enc), required for decryption.
  public let encapsulatedKey: [UInt8]
  /// The HPKE ciphertext (authenticated ciphertext including AEAD tag).
  public let ciphertext: [UInt8]

  public init(
    cryptoSet: CryptoSet,
    recipientKeyID: [UInt8],
    encapsulatedKey: [UInt8],
    ciphertext: [UInt8]
  ) {
    self.cryptoSet = cryptoSet
    self.recipientKeyID = recipientKeyID
    self.encapsulatedKey = encapsulatedKey
    self.ciphertext = ciphertext
  }
}

// MARK: - Encryption

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
      cryptoSet: recipientPublicKey.cryptoSet,
      recipientKeyID: recipientPublicKey.id,
      encapsulatedKey: encapsulatedKey,
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
}

// MARK: - CBOR serialisation

extension EncryptedMessage {
  private enum Field: UInt64 {
    case recipientKeyID = 0
    case cryptoSet = 1
    case encapsulatedKey = 2
    case ciphertext = 3
  }

  /// Encodes this message as a CBOR map with integer keys.
  public func toCBOR() -> CBOR {
    .map([
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
  }

  /// Decodes an ``EncryptedMessage`` from a CBOR map.
  public static func fromCBOR(_ cbor: CBOR) throws -> EncryptedMessage {
    guard let pairs = try cbor.mapValue() else { throw DiemError.invalidCBOR }
    var recipientKeyID: [UInt8]?
    var cryptoSetRaw: UInt64?
    var encapsulatedKey: [UInt8]?
    var ciphertext: [UInt8]?
    for pair in pairs {
      guard case .unsignedInt(let k) = pair.key else { continue }
      switch k {
      case Field.recipientKeyID.rawValue: recipientKeyID = pair.value.byteStringValue()
      case Field.cryptoSet.rawValue:
        if case .unsignedInt(let v) = pair.value { cryptoSetRaw = v }
      case Field.encapsulatedKey.rawValue: encapsulatedKey = pair.value.byteStringValue()
      case Field.ciphertext.rawValue: ciphertext = pair.value.byteStringValue()
      default: break
      }
    }
    guard let recipientKeyID, let cryptoSetRaw, let encapsulatedKey, let ciphertext else {
      throw DiemError.missingField(
        "EncryptedMessage: recipientKeyID, cryptoSet, encapsulatedKey, or ciphertext missing")
    }
    guard let cryptoSet = CryptoSet(rawValue: cryptoSetRaw) else { throw DiemError.invalidCBOR }
    return EncryptedMessage(
      cryptoSet: cryptoSet,
      recipientKeyID: recipientKeyID,
      encapsulatedKey: encapsulatedKey,
      ciphertext: ciphertext)
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
