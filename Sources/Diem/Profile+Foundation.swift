#if canImport(FoundationEssentials)
  import FoundationEssentials

  extension Profile {
    /// The creation date as a ``Date``, if ``createdAt`` is set.
    public var createdAtDate: Date? {
      createdAt.map { Date(timeIntervalSince1970: TimeInterval($0)) }
    }

    /// The expiry date as a ``Date``, if ``expiresAt`` is set.
    public var expiresAtDate: Date? {
      expiresAt.map { Date(timeIntervalSince1970: TimeInterval($0)) }
    }
  }
#elseif canImport(Foundation)
  import Foundation

  extension Profile {
    /// The creation date as a ``Date``, if ``createdAt`` is set.
    public var createdAtDate: Date? {
      createdAt.map { Date(timeIntervalSince1970: TimeInterval($0)) }
    }

    /// The expiry date as a ``Date``, if ``expiresAt`` is set.
    public var expiresAtDate: Date? {
      expiresAt.map { Date(timeIntervalSince1970: TimeInterval($0)) }
    }
  }
#endif
