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

  // MARK: Convenience: encrypt for a stored share

  /// Encrypts `payload` using the share identified by `keyID`.
  ///
  /// - Parameters:
  ///   - payload: The CBOR value to encrypt.
  ///   - keyID: The key ID of the share to use for encryption.
  ///   - backend: The crypto backend to use.
  /// - Returns: An ``/Diem/EncryptedMessage`` encrypted with the share's symmetric key.
  /// - Throws: ``/Diem/DiemError/keyNotFound`` if no share with the given key ID exists.
  public func encrypt<B: DiemCryptoBackend>(
    _ payload: CBOR,
    toShareWithKeyID keyID: [UInt8],
    using backend: B
  ) throws -> EncryptedMessage {
    guard let share = try self.share(for: keyID) else { throw DiemError.keyNotFound }
    return try EncryptedMessage.encrypt(payload, to: share, using: backend)
  }

  // MARK: Convenience: decrypt using a stored share

  /// Decrypts an ``/Diem/EncryptedMessage`` using a stored share.
  ///
  /// This method automatically looks up the share by the message's recipient key ID.
  ///
  /// - Parameters:
  ///   - message: The encrypted message to decrypt.
  ///   - backend: The crypto backend to use.
  /// - Returns: The decrypted CBOR payload.
  /// - Throws: ``/Diem/DiemError/keyNotFound`` if no matching share exists,
  ///           ``/Diem/DiemError/unexpectedMessageRecipientType`` if the message is not for a share,
  ///           or decryption errors.
  public func decrypt<B: DiemCryptoBackend>(
    _ message: EncryptedMessage,
    using backend: B
  ) throws -> CBOR {
    // Only handle share-type messages
    guard case .share(let keyID) = message.recipient else {
      throw DiemError.unexpectedMessageRecipientType
    }

    guard let share = try self.share(for: keyID) else {
      throw DiemError.keyNotFound
    }
    return try share.decrypt(message.ciphertext, using: backend)
  }
}
