import Diem
import DiemStores

/// An in-memory ``/DiemStores/IdentityStore`` with a secondary key-ID index for efficient decryption.
///
/// Suitable for tests, short-lived processes, and Swift Embedded targets.
public final class InMemoryIdentityStore<B: DiemCryptoBackend>: IdentityStore,
  @unchecked Sendable
{
  public typealias Backend = B

  public let backend: B
  /// Identities keyed by ``/Diem/Profile/id``.
  private var identities: [[UInt8]: Identity<B>] = [:]
  /// Maps each ``/Diem/PublicKeyEntry/id`` to its owning ``/Diem/Profile/id``.
  private var keyIndex: [[UInt8]: [UInt8]] = [:]

  public init(backend: B) {
    self.backend = backend
  }

  public func store(_ identity: Identity<B>) throws {
    let id = identity.profile.id
    guard identities[id] == nil else { throw DiemError.alreadyExists }
    identities[id] = identity
    indexKeys(of: identity)
  }

  public func update(_ identity: Identity<B>) throws {
    if let existing = identities[identity.profile.id] { deindexKeys(of: existing) }
    identities[identity.profile.id] = identity
    indexKeys(of: identity)
  }

  public func identity(for id: [UInt8]) throws -> Identity<B>? {
    identities[id]
  }

  public func allIdentities() throws -> [Identity<B>] {
    Array(identities.values)
  }

  public func remove(id: [UInt8]) throws {
    if let existing = identities[id] { deindexKeys(of: existing) }
    identities.removeValue(forKey: id)
  }

  // MARK: - Efficient decrypt using key index

  /// Decrypts an ``/Diem/EncryptedMessage`` using the key-ID index for O(1) identity lookup.
  public func decrypt(_ message: EncryptedMessage) throws -> CBOR {
    guard let profileID = keyIndex[message.recipientKeyID] else {
      throw DiemError.keyNotFound
    }
    guard let identity = identities[profileID] else {
      throw DiemError.keyNotFound
    }
    return try identity.decrypt(message)
  }

  // MARK: - Index helpers

  private func indexKeys(of identity: Identity<B>) {
    for key in identity.profile.keys {
      keyIndex[key.id] = identity.profile.id
    }
  }

  private func deindexKeys(of identity: Identity<B>) {
    for key in identity.profile.keys {
      keyIndex.removeValue(forKey: key.id)
    }
  }
}
