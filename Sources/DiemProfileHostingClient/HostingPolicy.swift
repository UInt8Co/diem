import Diem

public struct HostingPolicy: Sendable, Equatable {
  /// Policy for child names (`label.<domain>`). Absent on apex-only hosts.
  public struct Names: Sendable, Equatable {
    /// Informational only; the server evaluates its pattern.
    public let labelPattern: String
    public let maxClaimsPerIdentity: Int64
    public let maxUpdatesPerIdentityPerHour: Int64
    public let claimGraceAfterExpiry: Int64
    public let algorithm: String
    public let baseBits: Int64
    public let bitsPerShorterCharacter: Int64
    public let referenceLength: Int64

    fileprivate init(fields: [String: JSON]) throws(ProfileHostingError) {
      labelPattern = try fields.field("labelPattern").string()
      maxClaimsPerIdentity = try fields.field("maxClaimsPerIdentity").integer()
      maxUpdatesPerIdentityPerHour = try fields.field("maxUpdatesPerIdentityPerHour").integer()
      claimGraceAfterExpiry = try fields.field("claimGraceAfterExpiry").integer()
      let pow = try fields.field("proofOfWork").object()
      algorithm = try pow.field("algorithm").string()
      guard algorithm == "sha256-leading-zero-bits-v1" else { throw .unsupportedAlgorithm(algorithm) }
      baseBits = try pow.field("baseBits").integer()
      bitsPerShorterCharacter = try pow.field("bitsPerShorterCharacter").integer()
      referenceLength = try pow.field("referenceLength").integer()
    }
  }

  public let domain: DomainName
  /// Whether this host serves its own domain's profile. Defaults to false on the wire.
  public let apex: Bool
  public let names: Names?
  public var servesChildNames: Bool { names != nil }

  public init(json: [UInt8], domain: DomainName) throws(ProfileHostingError) {
    let fields = try JSON(json).object()
    guard try fields.field("domain").string() == domain.name else { throw .domainMismatch }
    self.domain = domain
    if let value = fields["apex"] {
      guard case .bool(let enabled) = value else { throw .invalidResponse }
      apex = enabled
    } else { apex = false }
    let keys = ["labelPattern", "maxClaimsPerIdentity", "maxUpdatesPerIdentityPerHour",
      "claimGraceAfterExpiry", "proofOfWork"]
    let count = keys.filter { fields[$0] != nil }.count
    guard count == 0 || count == keys.count else { throw .invalidResponse }
    names = count == 0 ? nil : try Names(fields: fields)
    guard apex || servesChildNames else { throw .invalidResponse }
  }

  /// Nil for the apex (`@`), no child-name policy, overflow or a requirement outside 0...64.
  public func requiredBits(for label: String) -> Int? {
    guard label != "@", let names else { return nil }
    return ProofOfWorkPuzzle.requiredBits(for: label, baseBits: names.baseBits,
      bitsPerShorterCharacter: names.bitsPerShorterCharacter, referenceLength: names.referenceLength)
  }
}

public struct HostedName: Sendable, Equatable {
  public enum Status: String, Sendable { case available, claimed, invalid }
  public let label: String
  public let status: Status
  public let requiredBits: Int64?
}

public struct HostingPlan: Sendable, Equatable {
  public enum Status: Sendable, Equatable {
    case invalid, taken, held
    case needsProof(requiredBits: Int64)
  }

  public struct Name: Sendable, Equatable {
    public let label: String
    public let status: Status
  }

  public let domain: DomainName
  public let identityID: Digest
  public let names: [Name]
}
