import CBOR
import Diem

// MARK: - ProfileStore

/// A store for ``/Diem/Profile`` values, keyed by ``/Diem/Profile/id``.
///
/// Implementors must provide persistent or in-memory storage. Default implementations
/// are provided for ``storeOrUpdate(_:)``, ``profile(forKeyID:)``,
/// ``encrypt(_:toProfileWithID:cryptoSet:using:)``, and ``verify(_:using:)``.
///
/// ``ProfileStore`` has no associated types and can be used as an existential.
public protocol ProfileStore: Sendable {

  // MARK: CRUD

  /// Stores a new profile.
  ///
  /// - Throws: ``/Diem/DiemError/alreadyExists`` if a profile with the same ``/Diem/Profile/id`` is
  ///   already present.
  func store(_ profile: Profile) throws

  /// Updates an existing profile and returns a diff summary.
  ///
  /// If no profile with the same ID exists, returns `nil` without modifying state.
  func update(_ profile: Profile) throws -> ProfileUpdateSummary?

  /// Stores or replaces a profile, returning a diff summary if the profile already existed.
  func storeOrUpdate(_ profile: Profile) throws -> ProfileUpdateSummary?

  /// Returns the profile matching `id`, or `nil` if not found.
  func profile(for id: [UInt8]) throws -> Profile?

  /// Returns the profile that owns the given public key ID, or `nil` if not found.
  ///
  /// Used to resolve a sender or recipient key to its profile without knowing the profile ID
  /// upfront — for example when verifying a ``/Diem/SignedMessage`` or routing an
  /// ``/Diem/EncryptedMessage``.
  ///
  /// A default implementation that scans ``allProfiles()`` is provided. Backends are
  /// encouraged to override this with an indexed lookup.
  func profile(forKeyID keyID: [UInt8]) throws -> Profile?

  /// Returns all profiles in the store.
  func allProfiles() throws -> [Profile]

  /// Removes the profile with the given `id`.
  ///
  /// It is not an error to remove a non-existent ID.
  func remove(id: [UInt8]) throws
}

// MARK: - Default implementations

extension ProfileStore {
  public func storeOrUpdate(_ profile: Profile) throws -> ProfileUpdateSummary? {
    if let existing = try self.profile(for: profile.id) {
      let summary = ProfileUpdateSummary.diff(old: existing, new: profile)
      _ = try update(profile)
      return summary
    } else {
      try store(profile)
      return nil
    }
  }

  /// Default implementation: scans all profiles for a matching key entry.
  /// Override in backends that maintain a key-ID index.
  public func profile(forKeyID keyID: [UInt8]) throws -> Profile? {
    try allProfiles().first { profile in
      profile.keys.contains { $0.id == keyID }
    }
  }

  // MARK: Convenience: encrypt for a stored profile

  /// Encrypts `payload` for the profile identified by `id`.
  public func encrypt<B: DiemCryptoBackend>(
    _ payload: CBOR,
    toProfileWithID id: [UInt8],
    cryptoSet: CryptoSet,
    using backend: B
  ) throws -> EncryptedMessage {
    guard let recipientProfile = try profile(for: id) else { throw DiemError.keyNotFound }
    return try EncryptedMessage.encrypt(
      payload, to: recipientProfile, cryptoSet: cryptoSet, using: backend)
  }

  // MARK: Convenience: verify signed message

  /// Verifies a ``/Diem/SignedMessage`` using ``profile(forKeyID:)`` to locate the sender's key.
  ///
  /// - Returns: `true` if the signature is valid.
  /// - Throws: ``/Diem/DiemError/keyNotFound`` if no stored profile owns ``/Diem/SignedMessage/senderKeyID``.
  public func verify<B: DiemCryptoBackend>(_ message: SignedMessage, using backend: B) throws
    -> Bool
  {
    guard let senderProfile = try profile(forKeyID: message.senderKeyID) else {
      throw DiemError.keyNotFound
    }
    guard
      let key = senderProfile.keys.first(where: {
        $0.id == message.senderKeyID && $0.keyType == .signing
          && $0.cryptoSet == message.cryptoSet
      })
    else {
      throw DiemError.keyNotFound
    }
    return try message.verify(against: key, using: backend)
  }
}
