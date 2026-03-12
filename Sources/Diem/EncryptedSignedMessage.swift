import CBOR

// MARK: - EncryptedSignedMessage

/// An ``EncryptedMessage`` whose plaintext payload is a ``SignedMessage``.
///
/// This is a convenience wrapper that combines encryption and signing into a
/// single type, making it easy to send authenticated, confidential messages.
///
/// ## Encrypting a signed message
/// ```swift
/// let signed = try senderIdentity.sign(payload)
/// let msg = try EncryptedSignedMessage.encrypt(signed, to: recipient, cryptoSet: .classic, using: backend)
/// ```
///
/// ## Decrypting and verifying in one step
/// ```swift
/// let signed = try msg.decryptAndVerify(using: recipientIdentity, senderProfile: sender)
/// let payload = signed.payload
/// ```
///
/// Serialised identically to a plain ``EncryptedMessage`` (CBOR map with integer keys).
public struct EncryptedSignedMessage: Sendable {
  /// The underlying encrypted message.
  public let message: EncryptedMessage

  public init(message: EncryptedMessage) {
    self.message = message
  }
}

// MARK: - Encryption

extension EncryptedSignedMessage {
  /// Encrypts a ``SignedMessage`` for the holder of `recipientPublicKey` using HPKE.
  ///
  /// - Parameters:
  ///   - signed: The signed message to encrypt.
  ///   - recipientPublicKey: A ``PublicKeyEntry`` whose ``PublicKeyEntry/keyType`` is
  ///     ``KeyType/keyAgreement``.
  ///   - backend: The crypto backend to use.
  /// - Throws: ``DiemError/invalidKeyType`` if the key is not a key-agreement key,
  ///           ``DiemError/unsupportedCryptoSet(_:)`` if the backend can't handle the key's set.
  public static func encrypt<Backend: DiemCryptoBackend>(
    _ signed: SignedMessage,
    to recipientPublicKey: PublicKeyEntry,
    using backend: Backend
  ) throws -> EncryptedSignedMessage {
    let inner = try EncryptedMessage.encrypt(signed.toCBOR(), to: recipientPublicKey, using: backend)
    return EncryptedSignedMessage(message: inner)
  }

  /// Encrypts a ``SignedMessage`` for a ``Profile``, using the first key-agreement key
  /// matching `cryptoSet`.
  ///
  /// - Throws: ``DiemError/keyNotFound`` if no matching key-agreement key exists.
  public static func encrypt<Backend: DiemCryptoBackend>(
    _ signed: SignedMessage,
    to recipient: Profile,
    cryptoSet: CryptoSet,
    using backend: Backend
  ) throws -> EncryptedSignedMessage {
    let inner = try EncryptedMessage.encrypt(
      signed.toCBOR(), to: recipient, cryptoSet: cryptoSet, using: backend)
    return EncryptedSignedMessage(message: inner)
  }

  /// Encrypts a ``SignedMessage`` for a ``Profile``, automatically negotiating the best
  /// shared crypto set.
  ///
  /// Picks the highest-priority crypto set that both the backend and the recipient support,
  /// preferring ``CryptoSet/pqc`` over ``CryptoSet/classic``.
  ///
  /// - Throws: ``DiemError/keyNotFound`` if no common crypto set can be found.
  public static func encrypt<Backend: DiemCryptoBackend>(
    _ signed: SignedMessage,
    to recipient: Profile,
    using backend: Backend
  ) throws -> EncryptedSignedMessage {
    let inner = try EncryptedMessage.encrypt(signed.toCBOR(), to: recipient, using: backend)
    return EncryptedSignedMessage(message: inner)
  }
}

// MARK: - Decrypt and verify

extension EncryptedSignedMessage {
  /// Decrypts the message and verifies the signature using the matching signing key from
  /// `senderProfile`.
  ///
  /// - Parameters:
  ///   - identity: The recipient's identity used for decryption.
  ///   - senderProfile: The sender's profile used to look up the signing key.
  /// - Returns: The verified ``SignedMessage``, whose ``SignedMessage/payload`` contains
  ///   the original CBOR.
  /// - Throws: ``DiemError/verificationFailed`` if the signature does not match,
  ///           ``DiemError/keyNotFound`` if no matching signing key is found in `senderProfile`,
  ///           or any error thrown by decryption.
  public func decryptAndVerify<Backend: DiemCryptoBackend>(
    using identity: Identity<Backend>,
    senderProfile: Profile
  ) throws -> SignedMessage {
    let cbor = try identity.decrypt(message)
    let signed = try SignedMessage.fromCBOR(cbor)
    guard try signed.verify(using: senderProfile, with: identity.backend) else {
      throw DiemError.verificationFailed
    }
    return signed
  }

  /// Decrypts the message and verifies the signature against a specific `signingKey`.
  ///
  /// - Parameters:
  ///   - identity: The recipient's identity used for decryption.
  ///   - signingKey: A ``PublicKeyEntry`` whose ``PublicKeyEntry/keyType`` is
  ///     ``KeyType/signing``.
  /// - Returns: The verified ``SignedMessage``, whose ``SignedMessage/payload`` contains
  ///   the original CBOR.
  /// - Throws: ``DiemError/verificationFailed`` if the signature does not match,
  ///           ``DiemError/invalidKeyType`` if `signingKey` is not a signing key,
  ///           or any error thrown by decryption.
  public func decryptAndVerify<Backend: DiemCryptoBackend>(
    using identity: Identity<Backend>,
    against signingKey: PublicKeyEntry
  ) throws -> SignedMessage {
    let cbor = try identity.decrypt(message)
    let signed = try SignedMessage.fromCBOR(cbor)
    guard try signed.verify(against: signingKey, using: identity.backend) else {
      throw DiemError.verificationFailed
    }
    return signed
  }

  /// Decrypts the message, verifies the signature using `senderProfile`, and returns the
  /// inner CBOR payload directly.
  ///
  /// Equivalent to `decryptAndVerify(using:senderProfile:).payload`.
  ///
  /// - Throws: ``DiemError/verificationFailed`` if the signature does not match,
  ///           ``DiemError/keyNotFound`` if no matching signing key is found in `senderProfile`,
  ///           or any error thrown by decryption.
  public func decryptAndVerifyPayload<Backend: DiemCryptoBackend>(
    using identity: Identity<Backend>,
    senderProfile: Profile
  ) throws -> CBOR {
    try decryptAndVerify(using: identity, senderProfile: senderProfile).payload
  }

  /// Decrypts the message, verifies the signature against `signingKey`, and returns the
  /// inner CBOR payload directly.
  ///
  /// Equivalent to `decryptAndVerify(using:against:).payload`.
  ///
  /// - Throws: ``DiemError/verificationFailed`` if the signature does not match,
  ///           ``DiemError/invalidKeyType`` if `signingKey` is not a signing key,
  ///           or any error thrown by decryption.
  public func decryptAndVerifyPayload<Backend: DiemCryptoBackend>(
    using identity: Identity<Backend>,
    against signingKey: PublicKeyEntry
  ) throws -> CBOR {
    try decryptAndVerify(using: identity, against: signingKey).payload
  }
}

// MARK: - CBOR serialisation

extension EncryptedSignedMessage {
  /// Encodes this message as a CBOR map with integer keys.
  ///
  /// The encoding is identical to that of the underlying ``EncryptedMessage``.
  public func toCBOR() -> CBOR { message.toCBOR() }

  /// Decodes an ``EncryptedSignedMessage`` from a CBOR map.
  public static func fromCBOR(_ cbor: CBOR) throws -> EncryptedSignedMessage {
    EncryptedSignedMessage(message: try EncryptedMessage.fromCBOR(cbor))
  }

  /// Serialises this message to CBOR bytes.
  public func encode() -> [UInt8] { message.encode() }

  /// Deserialises an ``EncryptedSignedMessage`` from CBOR bytes.
  public static func decode(_ bytes: [UInt8]) throws -> EncryptedSignedMessage {
    EncryptedSignedMessage(message: try EncryptedMessage.decode(bytes))
  }
}
