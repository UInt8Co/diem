import Diem
import DiemStores
import Synchronization

/// An in-memory ``/DiemStores/IdentityStore`` with a secondary key-ID index for efficient decryption.
///
/// Suitable for tests, short-lived processes, and Swift Embedded targets.
/// Thread-safety is provided via Swift `Mutex` from the `Synchronization` module.
public final class InMemoryIdentityStore<B: DiemCryptoBackend>: IdentityStore {
  public typealias Backend = B

  public let backend: B

  private struct State {
    /// Identities keyed by ``/Diem/Profile/id``.
    var identities: [[UInt8]: Identity<B>] = [:]
    /// Maps each ``/Diem/PublicKeyEntry/id`` to its owning ``/Diem/Profile/id``.
    var keyIndex: [[UInt8]: [UInt8]] = [:]
  }

  private let state: Mutex<State> = Mutex(State())

  public init(backend: B) {
    self.backend = backend
  }

  public func store(_ identity: Identity<B>) throws {
    try state.withLock { state in
      let id = identity.profile.id
      guard state.identities[id] == nil else { throw DiemError.alreadyExists }
      state.identities[id] = identity
      indexKeys(of: identity, in: &state)
    }
  }

  public func update(_ identity: Identity<B>) throws {
    state.withLock { state in
      if let existing = state.identities[identity.profile.id] {
        deindexKeys(of: existing, in: &state)
      }
      state.identities[identity.profile.id] = identity
      indexKeys(of: identity, in: &state)
    }
  }

  public func identity(for id: [UInt8]) throws -> Identity<B>? {
    state.withLock { state in
      state.identities[id]
    }
  }

  public func allIdentities() throws -> [Identity<B>] {
    state.withLock { state in
      Array(state.identities.values)
    }
  }

  public func remove(id: [UInt8]) throws {
    state.withLock { state in
      if let existing = state.identities[id] { deindexKeys(of: existing, in: &state) }
      state.identities.removeValue(forKey: id)
    }
  }

  // MARK: - Efficient decrypt using key index

  /// Decrypts an ``/Diem/EncryptedMessage`` using the key-ID index for O(1) identity lookup.
  ///
  /// This method only handles messages encrypted for a Profile (using HPKE).
  /// Messages encrypted for an ``EncryptedShare`` must be decrypted using
  /// ``EncryptedShare/decrypt(_:using:)``.
  public func decrypt(_ message: EncryptedMessage) throws -> CBOR {
    // Only handle key-type messages
    guard case .profileKey(_, let keyID, _) = message.recipient else {
      throw DiemError.unexpectedMessageRecipientType
    }

    return try state.withLock { state in
      guard let profileID = state.keyIndex[keyID] else {
        throw DiemError.keyNotFound
      }
      guard let identity = state.identities[profileID] else {
        throw DiemError.keyNotFound
      }
      return try identity.decrypt(message)
    }
  }

  // MARK: - Index helpers

  private func indexKeys(of identity: Identity<B>, in state: inout State) {
    for key in identity.profile.keys {
      state.keyIndex[key.id] = identity.profile.id
    }
  }

  private func deindexKeys(of identity: Identity<B>, in state: inout State) {
    for key in identity.profile.keys {
      state.keyIndex.removeValue(forKey: key.id)
    }
  }
}
