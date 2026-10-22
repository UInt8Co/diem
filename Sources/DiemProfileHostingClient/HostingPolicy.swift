import Diem

public struct HostingPolicy: Sendable, Equatable {
  public let domain: DomainName
  /// Informational only; the server evaluates its pattern.
  public let labelPattern: String
  public let maxClaimsPerIdentity: Int64
  public let maxUpdatesPerIdentityPerHour: Int64
  public let claimGraceAfterExpiry: Int64
  public let algorithm: String
  public let baseBits: Int64
  public let bitsPerShorterCharacter: Int64
  public let referenceLength: Int64

  public init(json: [UInt8], domain: DomainName) throws(ProfileHostingError) {
    let fields = try JSON(json).object()
    guard try fields.field("domain").string() == domain.name else { throw .domainMismatch }
    self.domain = domain
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

  /// Nil means overflow or a requirement outside 0...64.
  public func requiredBits(for label: String) -> Int? {
    ProofOfWorkPuzzle.requiredBits(for: label, baseBits: baseBits,
      bitsPerShorterCharacter: bitsPerShorterCharacter, referenceLength: referenceLength)
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
