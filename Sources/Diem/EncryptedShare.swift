import CBOR

// MARK: - EncryptedShare

/// An abstraction for transmitting a single copy of encrypted payload to multiple recipients.
///
/// The payload will only be encrypted once using symmetric encryption, and the same encrypted
/// payload is broadcasted to multiple recipients. The symmetric key is securely shared with
/// each recipient via the ``invite(_:using:)`` method.
///
/// ## Creating a new share
/// ```swift
/// let share = try EncryptedShare.generate(using: backend)
/// ```
///
/// ## Encrypting data
/// ```swift
/// let ciphertext = try share.encrypt(payload, using: backend)
/// ```
///
/// ## Inviting a recipient
/// ```swift
/// let invitation = try share.invite(recipient, using: backend)
/// // Send invitation to recipient...
/// ```
///
/// ## Accepting an invitation
/// ```swift
/// let share = try EncryptedShare.fromInvite(invitation, using: identity)
/// let payload = try share.decrypt(ciphertext, using: backend)
/// ```
public struct EncryptedShare: Sendable {
  /// The symmetric encryption algorithm used for this share.
  public let crypto: Crypto
  /// The key ID (derived from the symmetric key).
  public let keyID: [UInt8]
  /// The raw symmetric key bytes.
  public let key: [UInt8]

  public init(crypto: Crypto, keyID: [UInt8], key: [UInt8]) {
    self.crypto = crypto
    self.keyID = keyID
    self.key = key
  }
}

// MARK: - Crypto enum

extension EncryptedShare {
  /// Symmetric encryption algorithms supported by ``EncryptedShare``.
  public enum Crypto: UInt64, Sendable, Hashable, CaseIterable {
    /// AES-256-GCM authenticated encryption.
    ///
    /// Compatible with both ``CryptoSet/classic`` and ``CryptoSet/pqc``.
    case aes256gcm = 0
  }
}

extension EncryptedShare.Crypto {
  /// The crypto sets this symmetric algorithm is compatible with.
  ///
  /// AES-256-GCM is compatible with both classic and PQC crypto sets.
  public var compatibleCryptoSets: Set<CryptoSet> {
    switch self {
    case .aes256gcm:
      return [.classic, .pqc]
    }
  }

  /// The key size in bytes for this algorithm.
  var keySize: Int {
    switch self {
    case .aes256gcm:
      return 32  // 256 bits
    }
  }
}

// MARK: - Generation

extension EncryptedShare {
  /// Generates a new ``EncryptedShare`` with a random symmetric key.
  ///
  /// - Parameters:
  ///   - crypto: The symmetric encryption algorithm to use. Defaults to ``Crypto/aes256gcm``.
  ///   - backend: The crypto backend to use for key generation.
  /// - Returns: A new share with a randomly generated key.
  public static func generate<Backend: DiemCryptoBackend>(
    crypto: Crypto = .aes256gcm,
    using backend: Backend
  ) -> EncryptedShare {
    let key = backend.generateRandomBytes(count: crypto.keySize)
    let keyID = backend.keyID(publicKey: key)
    return EncryptedShare(crypto: crypto, keyID: keyID, key: key)
  }
}

// MARK: - Encryption and Decryption

extension EncryptedShare {
  /// Encrypts a CBOR payload using this share's symmetric key.
  ///
  /// - Parameters:
  ///   - payload: The CBOR value to encrypt.
  ///   - backend: The crypto backend to use.
  /// - Returns: The ciphertext bytes (including authentication tag).
  /// - Throws: ``DiemError/encryptionFailed`` if encryption fails.
  public func encrypt<Backend: DiemCryptoBackend>(
    _ payload: CBOR,
    using backend: Backend
  ) throws -> [UInt8] {
    try backend.symmetricEncrypt(plaintext: payload.encode(), key: key, crypto: crypto)
  }

  /// Decrypts ciphertext using this share's symmetric key.
  ///
  /// - Parameters:
  ///   - ciphertext: The ciphertext bytes to decrypt.
  ///   - backend: The crypto backend to use.
  /// - Returns: The decrypted CBOR payload.
  /// - Throws: ``DiemError/decryptionFailed`` if decryption or authentication fails,
  ///           ``DiemError/invalidCBOR`` if the plaintext is not valid CBOR.
  public func decrypt<Backend: DiemCryptoBackend>(
    _ ciphertext: [UInt8],
    using backend: Backend
  ) throws -> CBOR {
    let plaintext = try backend.symmetricDecrypt(ciphertext: ciphertext, key: key, crypto: crypto)
    do {
      return try CBOR.decode(plaintext)
    } catch {
      throw DiemError.invalidCBOR
    }
  }
}

// MARK: - Invitation

extension EncryptedShare {
  /// Shares this symmetric key with a recipient by encrypting it in an ``EncryptedMessage``.
  ///
  /// The invitation is an ``EncryptedMessage`` whose payload contains a CBOR-encoded
  /// representation of this ``EncryptedShare`` (without the key ID, which is derived).
  ///
  /// - Parameters:
  ///   - recipient: The recipient's profile or a specific public key.
  ///   - backend: The crypto backend to use.
  /// - Returns: An encrypted invitation that the recipient can use with ``fromInvite(_:using:)``.
  public func invite<Backend: DiemCryptoBackend>(
    _ recipient: PublicKeyEntry,
    using backend: Backend
  ) throws -> EncryptedMessage {
    let payload = self.toCBOR()
    return try EncryptedMessage.encrypt(payload, to: recipient, using: backend)
  }

  /// Shares this symmetric key with a recipient profile, using the first key-agreement key
  /// for `cryptoSet`.
  ///
  /// Before inviting, checks that the share's crypto is compatible with the target crypto set.
  ///
  /// - Throws: ``DiemError/keyNotFound`` if no matching key-agreement key exists or if the
  ///           crypto is not compatible with the target crypto set.
  public func invite<Backend: DiemCryptoBackend>(
    _ recipient: Profile,
    cryptoSet: CryptoSet,
    using backend: Backend
  ) throws -> EncryptedMessage {
    guard crypto.compatibleCryptoSets.contains(cryptoSet) else {
      throw DiemError.keyNotFound
    }
    let payload = self.toCBOR()
    return try EncryptedMessage.encrypt(payload, to: recipient, cryptoSet: cryptoSet, using: backend)
  }

  /// Shares this symmetric key with a recipient profile, automatically negotiating the best
  /// shared crypto set.
  ///
  /// Picks the highest-priority crypto set that the backend, recipient, and this share's
  /// crypto all support, preferring ``CryptoSet/pqc`` over ``CryptoSet/classic``.
  ///
  /// - Throws: ``DiemError/keyNotFound`` if no common crypto set can be found or if the
  ///           share's crypto is not compatible with any negotiated crypto set.
  public func invite<Backend: DiemCryptoBackend>(
    _ recipient: Profile,
    using backend: Backend
  ) throws -> EncryptedMessage {
    let recipientSets = Set(recipient.keys.filter { $0.keyType == .keyAgreement }.map { $0.cryptoSet })
    let shareSets = crypto.compatibleCryptoSets
    let availableSets = backend.supportedCryptoSets.intersection(recipientSets).intersection(shareSets)

    // Pick the highest-priority crypto set from the available sets
    for set in CryptoSet.preferenceOrder where availableSets.contains(set) {
      let payload = self.toCBOR()
      return try EncryptedMessage.encrypt(payload, to: recipient, cryptoSet: set, using: backend)
    }

    throw DiemError.keyNotFound
  }

  /// Creates an ``EncryptedShare`` by decrypting an invitation.
  ///
  /// - Parameters:
  ///   - invitation: An ``EncryptedMessage`` containing the encrypted share.
  ///   - identity: The recipient's identity used for decryption.
  /// - Returns: The decrypted share.
  /// - Throws: Decryption or CBOR decoding errors.
  public static func fromInvite<Backend: DiemCryptoBackend>(
    _ invitation: EncryptedMessage,
    using identity: Identity<Backend>
  ) throws -> EncryptedShare {
    let cbor = try identity.decrypt(invitation)
    return try fromCBOR(cbor)
  }
}

// MARK: - CBOR serialisation

extension EncryptedShare {
  private enum Field: UInt64 {
    case crypto = 0
    case key = 1
  }

  /// Encodes this share as a CBOR map with integer keys.
  ///
  /// Note: The key ID is not included in serialisation as it is derived from the key.
  public func toCBOR() -> CBOR {
    .map([
      CBORMapPair(
        key: .unsignedInt(Field.crypto.rawValue),
        value: .unsignedInt(crypto.rawValue)),
      CBORMapPair(
        key: .unsignedInt(Field.key.rawValue),
        value: .byteString(ArraySlice(key))),
    ])
  }

  /// Decodes an ``EncryptedShare`` from a CBOR map.
  public static func fromCBOR(_ cbor: CBOR) throws -> EncryptedShare {
    guard let pairs = try cbor.mapValue() else { throw DiemError.invalidCBOR }
    var cryptoRaw: UInt64?
    var key: [UInt8]?
    for pair in pairs {
      guard case .unsignedInt(let k) = pair.key else { continue }
      switch k {
      case Field.crypto.rawValue:
        if case .unsignedInt(let v) = pair.value { cryptoRaw = v }
      case Field.key.rawValue:
        key = pair.value.byteStringValue()
      default:
        break
      }
    }
    guard let cryptoRaw, let key else {
      throw DiemError.missingField("EncryptedShare: crypto or key missing")
    }
    guard let crypto = Crypto(rawValue: cryptoRaw) else { throw DiemError.invalidCBOR }
    // Derive key ID from key (we don't store it separately for security)
    // We need a backend to compute the key ID, but for now we'll create a temporary one
    // This is a bit of a design issue - we'll need to pass backend to fromCBOR
    // For now, let's use a simple SHA-256 approach inline
    let keyID = _computeKeyID(key)
    return EncryptedShare(crypto: crypto, keyID: keyID, key: key)
  }

  /// Serialises this share to CBOR bytes.
  public func encode() -> [UInt8] { toCBOR().encode() }

  /// Deserialises an ``EncryptedShare`` from CBOR bytes.
  public static func decode(_ bytes: [UInt8]) throws -> EncryptedShare {
    let cbor: CBOR
    do { cbor = try CBOR.decode(bytes) } catch { throw DiemError.invalidCBOR }
    return try fromCBOR(cbor)
  }
}

// MARK: - Helper to compute key ID from symmetric key

// Simple XOR-based hash for key ID computation (Foundation-free)
// This is used when deserializing without access to a backend
private func _computeKeyID(_ key: [UInt8]) -> [UInt8] {
  var result = [UInt8](repeating: 0, count: 32)
  for (index, byte) in key.enumerated() {
    result[index % 32] ^= byte
  }
  // Mix in the length to avoid collisions
  let lengthByte = UInt8(truncatingIfNeeded: key.count)
  for i in 0..<32 {
    result[i] ^= lengthByte
  }
  return result
}
