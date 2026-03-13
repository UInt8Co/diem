import DiemStores

/// An in-memory ``/DiemStores/ShareStore`` for storing encrypted shares.
///
/// Suitable for tests, short-lived processes, and Swift Embedded targets.
/// Thread-safety is provided via `@unchecked Sendable` with manual dictionary management
/// (single-threaded or caller-synchronised use assumed; wrap in an actor if needed).
public final class InMemoryShareStore: ShareStore, @unchecked Sendable {
  /// Encrypted shares keyed by ``EncryptedShare/keyID``.
  private var shares: [[UInt8]: EncryptedShare] = [:]

  public init() {}

  public func store(_ share: EncryptedShare) throws {
    guard shares[share.keyID] == nil else { throw DiemError.alreadyExists }
    shares[share.keyID] = share
  }

  public func update(_ share: EncryptedShare) throws -> Bool {
    guard shares[share.keyID] != nil else { return false }
    shares[share.keyID] = share
    return true
  }

  public func share(for keyID: [UInt8]) throws -> EncryptedShare? {
    shares[keyID]
  }

  public func allShares() throws -> [EncryptedShare] {
    Array(shares.values)
  }

  public func remove(keyID: [UInt8]) throws {
    shares.removeValue(forKey: keyID)
  }
}
