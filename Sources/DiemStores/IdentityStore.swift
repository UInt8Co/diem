import CBOR
import Diem

// MARK: - IdentityStore

/// A store for ``/Diem/Identity`` values, keyed by ``/Diem/Profile/id``.
///
/// The store is generic over a single ``/Diem/DiemCryptoBackend`` — all identities it manages
/// share the same backend. Default implementations are provided for ``storeOrUpdate(_:)``,
/// ``decrypt(_:)``, ``sign(_:identityID:cryptoSet:)``, and ``encrypt(_:to:cryptoSet:)``.
public protocol IdentityStore: Sendable {
  associatedtype Backend: DiemCryptoBackend

  /// The crypto backend shared by all identities in this store.
  var backend: Backend { get }

  // MARK: CRUD

  /// Stores a new identity.
  ///
  /// - Throws: ``/Diem/DiemError/alreadyExists`` if an identity with the same ``/Diem/Profile/id``
  ///   already exists.
  func store(_ identity: Identity<Backend>) throws

  /// Replaces an existing identity.
  ///
  /// If no identity with the same ID exists, acts like ``store(_:)``.
  func update(_ identity: Identity<Backend>) throws

  /// Stores the identity if new, or replaces it if it already exists.
  func storeOrUpdate(_ identity: Identity<Backend>) throws

  /// Returns the identity matching `id`, or `nil` if not found.
  func identity(for id: [UInt8]) throws -> Identity<Backend>?

  /// Returns all identities in the store.
  func allIdentities() throws -> [Identity<Backend>]

  /// Removes the identity with the given `id`.
  func remove(id: [UInt8]) throws
}

// MARK: - Default implementations

extension IdentityStore {
  public func storeOrUpdate(_ identity: Identity<Backend>) throws {
    if (try self.identity(for: identity.profile.id)) != nil {
      try update(identity)
    } else {
      try store(identity)
    }
  }

  // MARK: Convenience: decrypt

  /// Decrypts an ``/Diem/EncryptedMessage`` by scanning all stored identities for a matching
  /// key-agreement key.
  ///
  /// - Throws: ``/Diem/DiemError/keyNotFound`` if no identity owns the recipient key.
  public func decrypt(_ message: EncryptedMessage) throws -> CBOR {
    let identities = try allIdentities()
    for identity in identities {
      if identity.profile.keys.contains(where: {
        $0.id == message.recipientKeyID && $0.keyType == .keyAgreement
          && $0.cryptoSet == message.cryptoSet
      }) {
        return try identity.decrypt(message)
      }
    }
    throw DiemError.keyNotFound
  }

  // MARK: Convenience: sign

  /// Signs `payload` using the signing key of the identity identified by `identityID`.
  ///
  /// - Throws: ``/Diem/DiemError/keyNotFound`` if the identity is not in the store.
  public func sign(_ payload: CBOR, identityID: [UInt8], cryptoSet: CryptoSet = .classic)
    throws -> SignedMessage
  {
    guard let identity = try self.identity(for: identityID) else {
      throw DiemError.keyNotFound
    }
    return try identity.sign(payload, cryptoSet: cryptoSet)
  }

  // MARK: Convenience: encrypt to a profile

  /// Encrypts `payload` for the given `recipientProfile`, using the store's backend.
  public func encrypt(
    _ payload: CBOR, to recipientProfile: Profile, cryptoSet: CryptoSet = .classic
  )
    throws -> EncryptedMessage
  {
    try EncryptedMessage.encrypt(
      payload, to: recipientProfile, cryptoSet: cryptoSet, using: backend)
  }
}
