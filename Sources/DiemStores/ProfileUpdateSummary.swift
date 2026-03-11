import CBOR

/// Describes the differences observed when updating a ``Profile`` in a ``ProfileStore``.
public struct ProfileUpdateSummary: Sendable {
  /// The new version of the profile that was stored.
  public let updated: Profile
  /// Keys present in the new profile that were absent from the old one.
  public let addedKeys: [PublicKeyEntry]
  /// Keys present in the old profile that are absent from the new one.
  public let removedKeys: [PublicKeyEntry]
  /// Whether ``Profile/createdAt`` changed.
  public let createdAtChanged: Bool
  /// Whether ``Profile/expiresAt`` changed.
  public let expiresAtChanged: Bool
  /// The old and new ``Profile/extensions`` CBOR values, or `nil` if they didn't change.
  public let extensionsChange: (old: CBOR?, new: CBOR?)?

  public init(
    updated: Profile,
    addedKeys: [PublicKeyEntry],
    removedKeys: [PublicKeyEntry],
    createdAtChanged: Bool,
    expiresAtChanged: Bool,
    extensionsChange: (old: CBOR?, new: CBOR?)?
  ) {
    self.updated = updated
    self.addedKeys = addedKeys
    self.removedKeys = removedKeys
    self.createdAtChanged = createdAtChanged
    self.expiresAtChanged = expiresAtChanged
    self.extensionsChange = extensionsChange
  }
}

extension ProfileUpdateSummary {
  /// Returns `true` if any difference was recorded.
  public var hasChanges: Bool {
    !addedKeys.isEmpty || !removedKeys.isEmpty || createdAtChanged || expiresAtChanged
      || extensionsChange != nil
  }

  /// Builds a ``ProfileUpdateSummary`` by diffing `old` against `new`.
  public static func diff(old: Profile, new: Profile) -> ProfileUpdateSummary {
    let oldKeyIDs = Set(old.keys.map { $0.id })
    let newKeyIDs = Set(new.keys.map { $0.id })
    let added = new.keys.filter { !oldKeyIDs.contains($0.id) }
    let removed = old.keys.filter { !newKeyIDs.contains($0.id) }
    let extensionsChange: (old: CBOR?, new: CBOR?)?
    if cborsEqual(old.extensions, new.extensions) {
      extensionsChange = nil
    } else {
      extensionsChange = (old: old.extensions, new: new.extensions)
    }
    return ProfileUpdateSummary(
      updated: new,
      addedKeys: added,
      removedKeys: removed,
      createdAtChanged: old.createdAt != new.createdAt,
      expiresAtChanged: old.expiresAt != new.expiresAt,
      extensionsChange: extensionsChange
    )
  }
}

// A lightweight structural equality check for CBOR values. Used only for change detection.
private func cborsEqual(_ lhs: CBOR?, _ rhs: CBOR?) -> Bool {
  switch (lhs, rhs) {
  case (.none, .none): return true
  case (.some(let l), .some(let r)): return l.encode() == r.encode()
  default: return false
  }
}
