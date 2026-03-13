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
/// let share = EncryptedShare(using: backend)
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
/// let share = try EncryptedShare(invitation: invitation, using: identity)
/// let payload = try share.decrypt(ciphertext, using: backend)
/// ```
public struct EncryptedShare: Sendable, Identifiable {
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

  /// Stable identifier for this share (same as ``keyID``).
  public var id: [UInt8] { keyID }

  /// Hexadecimal string representation of the key ID.
  public var hexID: String { keyID.hexString }
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
  public init<Backend: DiemCryptoBackend>(
    crypto: Crypto = .aes256gcm,
    using backend: Backend
  ) {
    let key = backend.generateRandomBytes(count: crypto.keySize)
    let keyID = backend.keyID(of: key)
    self.init(crypto: crypto, keyID: keyID, key: key)
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
  /// - Throws: Decryption or CBOR decoding errors.
  public init<Backend: DiemCryptoBackend>(
    invitation: EncryptedMessage,
    using identity: Identity<Backend>
  ) throws {
    let cbor = try identity.decrypt(invitation)
    self = try EncryptedShare(cbor: cbor, using: identity.backend)
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

  /// Decodes an ``EncryptedShare`` from a CBOR map using the provided backend to compute the key ID.
  ///
  /// - Parameters:
  ///   - cbor: The CBOR map to decode.
  ///   - backend: The crypto backend used to derive the key ID from the symmetric key.
  /// - Throws: ``DiemError/invalidCBOR`` or ``DiemError/missingField(_:)`` if decoding fails.
  public init<Backend: DiemCryptoBackend>(cbor: CBOR, using backend: Backend) throws {
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
    // Derive key ID from key using the backend
    let keyID = backend.keyID(of: key)
    self.init(crypto: crypto, keyID: keyID, key: key)
  }

  /// Serialises this share to CBOR bytes.
  public func encode() -> [UInt8] { toCBOR().encode() }

  /// Deserialises an ``EncryptedShare`` from CBOR bytes using the provided backend.
  ///
  /// - Parameters:
  ///   - bytes: The CBOR-encoded bytes.
  ///   - backend: The crypto backend used to derive the key ID.
  /// - Throws: ``DiemError/invalidCBOR`` or decoding errors.
  public static func decode<Backend: DiemCryptoBackend>(
    _ bytes: [UInt8],
    using backend: Backend
  ) throws -> EncryptedShare {
    let cbor: CBOR
    do { cbor = try CBOR.decode(bytes) } catch { throw DiemError.invalidCBOR }
    return try EncryptedShare(cbor: cbor, using: backend)
  }
}
