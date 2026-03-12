import CBOR

// MARK: - Identity

/// A full cryptographic identity comprising a public ``profile`` and private keys.
///
/// ``Identity`` is generic over a ``DiemCryptoBackend``, which decouples key generation and
/// crypto operations from the core data model.
///
/// Private keys are stored as raw bytes keyed by their public key ID, enabling identities
/// that carry keys for multiple crypto sets.
public struct Identity<Backend: DiemCryptoBackend>: Sendable {
  /// The public profile derived from this identity's key pairs.
  public let profile: Profile
  /// The crypto backend used for all operations.
  public let backend: Backend

  private let privateKeyStore: [[UInt8]: [UInt8]]
}

// MARK: - Initialisation

extension Identity {
  /// Creates a new identity by generating fresh key pairs for each supported crypto set.
  ///
  /// By default generates keys for every crypto set the backend reports as supported.
  /// Pass an explicit `cryptoSets` set to restrict generation to a subset.
  ///
  /// - Parameters:
  ///   - name: Human-readable name for the profile.
  ///   - cryptoSets: Crypto sets to generate keys for. Defaults to all supported by `backend`.
  ///   - createdAt: Optional Unix timestamp of creation.
  ///   - expiresAt: Optional Unix timestamp of expiry.
  ///   - extensions: Optional user-defined CBOR extensions.
  ///   - backend: The crypto backend to use.
  public init(
    name: String,
    cryptoSets: Set<CryptoSet>? = nil,
    createdAt: UInt64? = nil,
    expiresAt: UInt64? = nil,
    extensions: CBOR? = nil,
    using backend: Backend
  ) throws {
    let sets = cryptoSets ?? backend.supportedCryptoSets
    var keys: [PublicKeyEntry] = []
    var store: [[UInt8]: [UInt8]] = [:]
    for set in sets {
      let (sigPub, sigPriv) = try backend.generateSigningKeyPair(for: set)
      let sigID = backend.keyID(publicKey: sigPub)
      keys.append(PublicKeyEntry(id: sigID, keyType: .signing, cryptoSet: set, rawBytes: sigPub))
      store[sigID] = sigPriv

      let (kaPub, kaPriv) = try backend.generateEncryptionKeyPair(for: set)
      let kaID = backend.keyID(publicKey: kaPub)
      keys.append(
        PublicKeyEntry(id: kaID, keyType: .keyAgreement, cryptoSet: set, rawBytes: kaPub))
      store[kaID] = kaPriv
    }
    let profileID = backend.generateRandomBytes(count: 16)
    self.init(
      profile: Profile(
        id: profileID, keys: keys, name: name, createdAt: createdAt, expiresAt: expiresAt,
        extensions: extensions),
      backend: backend,
      privateKeyStore: store)
  }

  /// Restores an identity from an existing ``Profile`` and a map of private key bytes.
  ///
  /// - Parameters:
  ///   - profile: The public profile to associate with this identity.
  ///   - privateKeysByKeyID: Maps each public key ID to its raw private key bytes.
  ///   - backend: The crypto backend to use.
  public init(
    profile: Profile,
    privateKeysByKeyID: [[UInt8]: [UInt8]],
    using backend: Backend
  ) {
    self.init(profile: profile, backend: backend, privateKeyStore: privateKeysByKeyID)
  }
}

// MARK: - Private key export

extension Identity {
  /// The full private key store, suitable for secure serialisation and later restoration.
  ///
  /// Each entry maps a public key ID (32 bytes) to raw private key bytes (32 bytes seed).
  public var privateKeysByKeyID: [[UInt8]: [UInt8]] { privateKeyStore }
}

// MARK: - Signing

extension Identity {
  /// Signs a CBOR payload using the identity's signing key for the given crypto set.
  ///
  /// - Parameters:
  ///   - payload: The CBOR value to sign.
  ///   - cryptoSet: Which crypto set's signing key to use. Defaults to ``CryptoSet/classic``.
  /// - Returns: A ``SignedMessage`` containing the payload, sender key ID, and signature.
  /// - Throws: ``DiemError/unsupportedCryptoSet(_:)`` if the backend doesn't support the set,
  ///           ``DiemError/keyNotFound`` if no signing key for the set is present.
  public func sign(_ payload: CBOR, cryptoSet: CryptoSet = .classic) throws -> SignedMessage {
    guard backend.supportedCryptoSets.contains(cryptoSet) else {
      throw DiemError.unsupportedCryptoSet(cryptoSet)
    }
    guard
      let signingKey = profile.keys.first(where: {
        $0.keyType == .signing && $0.cryptoSet == cryptoSet
      })
    else {
      throw DiemError.keyNotFound
    }
    guard let privKeyBytes = privateKeyStore[signingKey.id] else {
      throw DiemError.keyNotFound
    }
    let payloadBytes = payload.encode()
    let signature = try backend.sign(
      message: payloadBytes, privateKey: privKeyBytes, cryptoSet: cryptoSet)
    return SignedMessage(
      senderKeyID: signingKey.id, cryptoSet: cryptoSet, payload: payload,
      payloadBytes: payloadBytes, signature: signature)
  }
}

// MARK: - Sign and encrypt

extension Identity {
  /// Signs `payload` and encrypts the resulting ``SignedMessage`` for `recipient` in one step,
  /// automatically negotiating the best shared crypto set.
  ///
  /// Picks the highest-priority crypto set for which this identity has both a signing key and
  /// a key-agreement key, and the recipient's profile has a key-agreement key, preferring
  /// ``CryptoSet/pqc`` over ``CryptoSet/classic``.
  ///
  /// - Throws: ``DiemError/keyNotFound`` if no common crypto set can be negotiated.
  public func signAndEncrypt(_ payload: CBOR, to recipient: Profile) throws -> EncryptedSignedMessage {
    let senderSets = Set(
      profile.keys.filter { $0.keyType == .signing }.map { $0.cryptoSet }
    ).intersection(
      profile.keys.filter { $0.keyType == .keyAgreement }.map { $0.cryptoSet }
    )
    let recipientSets = Set(recipient.keys.filter { $0.keyType == .keyAgreement }.map { $0.cryptoSet })
    let cryptoSet = try CryptoSet.negotiate(between: senderSets, and: recipientSets)
    return try signAndEncrypt(payload, to: recipient, cryptoSet: cryptoSet)
  }

  /// Signs `payload` and encrypts the resulting ``SignedMessage`` for `recipient` in one step,
  /// using an explicit `cryptoSet` for both signing and encryption.
  ///
  /// - Parameters:
  ///   - payload: The CBOR value to sign and encrypt.
  ///   - recipient: The recipient's ``Profile`` to encrypt the message for.
  ///   - cryptoSet: Which crypto set to use for both signing and encryption.
  /// - Returns: An ``EncryptedSignedMessage`` addressed to `recipient`.
  /// - Throws: ``DiemError/unsupportedCryptoSet(_:)`` if the backend doesn't support the set,
  ///           ``DiemError/keyNotFound`` if a required key is absent.
  public func signAndEncrypt(
    _ payload: CBOR,
    to recipient: Profile,
    cryptoSet: CryptoSet
  ) throws -> EncryptedSignedMessage {
    let signed = try sign(payload, cryptoSet: cryptoSet)
    return try EncryptedSignedMessage.encrypt(signed, to: recipient, cryptoSet: cryptoSet, using: backend)
  }
}

// MARK: - Decryption

extension Identity {
  /// Decrypts an ``EncryptedMessage`` addressed to this identity.
  ///
  /// This method only handles messages encrypted for a Profile (using HPKE).
  /// Messages encrypted for an ``EncryptedShare`` must be decrypted using
  /// ``EncryptedShare/decrypt(_:using:)``.
  ///
  /// Matches ``EncryptedMessage/recipientKeyID`` against the identity's key-agreement keys, then
  /// delegates HPKE decryption to the backend.
  ///
  /// - Parameter message: The encrypted message to decrypt.
  /// - Returns: The decrypted CBOR payload.
  /// - Throws: ``DiemError/unsupportedCryptoSet(_:)``, ``DiemError/keyNotFound``,
  ///           ``DiemError/decryptionFailed``, or ``DiemError/invalidCBOR``.
  public func decrypt(_ message: EncryptedMessage) throws -> CBOR {
    // Only handle Profile-type messages
    guard case .profile(let cryptoSet, let recipientKeyID, let encapsulatedKey) = message.recipientType else {
      throw DiemError.keyNotFound
    }

    guard backend.supportedCryptoSets.contains(cryptoSet) else {
      throw DiemError.unsupportedCryptoSet(cryptoSet)
    }
    guard
      let kaKey = profile.keys.first(where: {
        $0.id == recipientKeyID && $0.keyType == .keyAgreement
          && $0.cryptoSet == cryptoSet
      })
    else {
      throw DiemError.keyNotFound
    }
    guard let privKeyBytes = privateKeyStore[kaKey.id] else {
      throw DiemError.keyNotFound
    }
    let plaintext = try backend.hpkeDecrypt(
      ciphertext: message.ciphertext,
      encapsulatedKey: encapsulatedKey,
      recipientPrivateKey: privKeyBytes,
      cryptoSet: cryptoSet)
    do {
      return try CBOR.decode(plaintext)
    } catch {
      throw DiemError.invalidCBOR
    }
  }
}
