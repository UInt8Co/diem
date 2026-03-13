import DiemStores
import Synchronization

/// An in-memory ``/DiemStores/ProfileStore`` with a secondary key-ID index for O(1) lookup.
///
/// Suitable for tests, short-lived processes, and Swift Embedded targets.
/// Thread-safety is provided via Swift `Mutex` from the `Synchronization` module.
public final class InMemoryProfileStore: ProfileStore {
  private struct State {
    /// Profiles keyed by ``Profile/id``.
    var profiles: [[UInt8]: Profile] = [:]
    /// Maps each ``PublicKeyEntry/id`` to its owning ``Profile/id``.
    var keyIndex: [[UInt8]: [UInt8]] = [:]
  }

  private let state: Mutex<State> = Mutex(State())

  public init() {}

  public func store(_ profile: Profile) throws {
    try state.withLock { state in
      guard state.profiles[profile.id] == nil else { throw DiemError.alreadyExists }
      state.profiles[profile.id] = profile
      indexKeys(of: profile, in: &state)
    }
  }

  public func update(_ profile: Profile) throws -> ProfileUpdateSummary? {
    state.withLock { state in
      guard let existing = state.profiles[profile.id] else { return nil }
      deindexKeys(of: existing, in: &state)
      state.profiles[profile.id] = profile
      indexKeys(of: profile, in: &state)
      return ProfileUpdateSummary.diff(old: existing, new: profile)
    }
  }

  public func profile(for id: [UInt8]) throws -> Profile? {
    state.withLock { state in
      state.profiles[id]
    }
  }

  public func profile(forKeyID keyID: [UInt8]) throws -> Profile? {
    state.withLock { state in
      guard let profileID = state.keyIndex[keyID] else { return nil }
      return state.profiles[profileID]
    }
  }

  public func allProfiles() throws -> [Profile] {
    state.withLock { state in
      Array(state.profiles.values)
    }
  }

  public func remove(id: [UInt8]) throws {
    state.withLock { state in
      if let existing = state.profiles[id] { deindexKeys(of: existing, in: &state) }
      state.profiles.removeValue(forKey: id)
    }
  }

  // MARK: - Index helpers

  private func indexKeys(of profile: Profile, in state: inout State) {
    for key in profile.keys {
      state.keyIndex[key.id] = profile.id
    }
  }

  private func deindexKeys(of profile: Profile, in state: inout State) {
    for key in profile.keys {
      state.keyIndex.removeValue(forKey: key.id)
    }
  }
}
