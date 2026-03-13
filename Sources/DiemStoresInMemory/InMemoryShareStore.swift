import DiemStores
import Synchronization

/// An in-memory ``/DiemStores/ShareStore`` for storing encrypted shares.
///
/// Suitable for tests, short-lived processes, and Swift Embedded targets.
/// Thread-safety is provided via Swift `Mutex` from the `Synchronization` module.
public final class InMemoryShareStore: ShareStore {
  /// Encrypted shares keyed by ``EncryptedShare/keyID``.
  private let shares: Mutex<[[UInt8]: EncryptedShare]> = Mutex([:])

  public init() {}

  public func store(_ share: EncryptedShare) throws {
    try shares.withLock { shares in
      guard shares[share.keyID] == nil else { throw DiemError.alreadyExists }
      shares[share.keyID] = share
    }
  }

  public func update(_ share: EncryptedShare) throws -> Bool {
    shares.withLock { shares in
      guard shares[share.keyID] != nil else { return false }
      shares[share.keyID] = share
      return true
    }
  }

  public func share(for keyID: [UInt8]) throws -> EncryptedShare? {
    shares.withLock { shares in
      shares[keyID]
    }
  }

  public func allShares() throws -> [EncryptedShare] {
    shares.withLock { shares in
      Array(shares.values)
    }
  }

  public func remove(keyID: [UInt8]) throws {
    shares.withLock { shares in
      shares.removeValue(forKey: keyID)
    }
  }
}
