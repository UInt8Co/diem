import DiemStores

/// An in-memory ``ProfileStore`` with a secondary key-ID index for O(1) lookup.
///
/// Suitable for tests, short-lived processes, and Swift Embedded targets.
/// Thread-safety is provided via `@unchecked Sendable` with manual dictionary management
/// (single-threaded or caller-synchronised use assumed; wrap in an actor if needed).
public final class InMemoryProfileStore: ProfileStore, @unchecked Sendable {
  /// Profiles keyed by ``Profile/id``.
  private var profiles: [[UInt8]: Profile] = [:]
  /// Maps each ``PublicKeyEntry/id`` to its owning ``Profile/id``.
  private var keyIndex: [[UInt8]: [UInt8]] = [:]

  public init() {}

  public func store(_ profile: Profile) throws {
    guard profiles[profile.id] == nil else { throw DiemError.alreadyExists }
    profiles[profile.id] = profile
    indexKeys(of: profile)
  }

  public func update(_ profile: Profile) throws -> ProfileUpdateSummary? {
    guard let existing = profiles[profile.id] else { return nil }
    deindexKeys(of: existing)
    profiles[profile.id] = profile
    indexKeys(of: profile)
    return ProfileUpdateSummary.diff(old: existing, new: profile)
  }

  public func profile(for id: [UInt8]) throws -> Profile? {
    profiles[id]
  }

  public func profile(forKeyID keyID: [UInt8]) throws -> Profile? {
    guard let profileID = keyIndex[keyID] else { return nil }
    return profiles[profileID]
  }

  public func allProfiles() throws -> [Profile] {
    Array(profiles.values)
  }

  public func remove(id: [UInt8]) throws {
    if let existing = profiles[id] { deindexKeys(of: existing) }
    profiles.removeValue(forKey: id)
  }

  // MARK: - Index helpers

  private func indexKeys(of profile: Profile) {
    for key in profile.keys {
      keyIndex[key.id] = profile.id
    }
  }

  private func deindexKeys(of profile: Profile) {
    for key in profile.keys {
      keyIndex.removeValue(forKey: key.id)
    }
  }
}
