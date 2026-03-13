import CBOR
import Diem

// MARK: - ShareStore

/// A store for ``/Diem/EncryptedShare`` values, keyed by ``/Diem/EncryptedShare/keyID``.
///
/// Implementors must provide persistent or in-memory storage. Default implementation
/// is provided for ``storeOrUpdate(_:)``.
///
/// ``ShareStore`` has no associated types and can be used as an existential.
public protocol ShareStore: Sendable {

  // MARK: CRUD

  /// Stores a new encrypted share.
  ///
  /// - Throws: ``/Diem/DiemError/alreadyExists`` if a share with the same ``/Diem/EncryptedShare/keyID`` is
  ///   already present.
  func store(_ share: EncryptedShare) throws

  /// Updates an existing encrypted share.
  ///
  /// If no share with the same key ID exists, returns `false` without modifying state.
  /// - Returns: `true` if the share was updated, `false` if it didn't exist.
  func update(_ share: EncryptedShare) throws -> Bool

  /// Stores or replaces an encrypted share.
  ///
  /// - Returns: `true` if an existing share was replaced, `false` if a new share was stored.
  func storeOrUpdate(_ share: EncryptedShare) throws -> Bool

  /// Returns the share matching `keyID`, or `nil` if not found.
  func share(for keyID: [UInt8]) throws -> EncryptedShare?

  /// Returns all encrypted shares in the store.
  func allShares() throws -> [EncryptedShare]

  /// Removes the share with the given `keyID`.
  ///
  /// It is not an error to remove a non-existent key ID.
  func remove(keyID: [UInt8]) throws
}

// MARK: - Default implementations

extension ShareStore {
  public func storeOrUpdate(_ share: EncryptedShare) throws -> Bool {
    if try self.share(for: share.keyID) != nil {
      _ = try update(share)
      return true
    } else {
      try store(share)
      return false
    }
  }
}
