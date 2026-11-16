#if ProfileHostingServer
import Diem
import DiemProfileHostingClient

#if canImport(FoundationEssentials)
  import FoundationEssentials
#else
  import Foundation
#endif

/// The host's own JSON configuration: only `domain` is required, and unknown keys are refused.
public struct DiemProfileHostingConfiguration: Codable, Sendable {
  /// The work a new name needs, published by the policy endpoint.
  public struct ProofOfWork: Codable, Sendable {
    public let baseBits: Int
    public let bitsPerShorterCharacter: Int
    public let referenceLength: Int

    public init(baseBits: Int = 20, bitsPerShorterCharacter: Int = 2, referenceLength: Int = 8) {
      self.baseBits = baseBits
      self.bitsPerShorterCharacter = bitsPerShorterCharacter
      self.referenceLength = referenceLength
    }

    public init(from decoder: any Decoder) throws {
      try rejectUnknownKeys(decoder, allowed: ["baseBits", "bitsPerShorterCharacter", "referenceLength"])
      let c = try decoder.container(keyedBy: CodingKeys.self)
      self.init(baseBits: try c.decodeIfPresent(Int.self, forKey: .baseBits) ?? 20,
        bitsPerShorterCharacter: try c.decodeIfPresent(Int.self, forKey: .bitsPerShorterCharacter) ?? 2,
        referenceLength: try c.decodeIfPresent(Int.self, forKey: .referenceLength) ?? 8)
    }

    /// The client's curve; nil on overflow or a requirement outside 0...64.
    public func requiredBits(label: String) -> Int? {
      ProofOfWorkPuzzle.requiredBits(for: label, baseBits: Int64(baseBits),
        bitsPerShorterCharacter: Int64(bitsPerShorterCharacter),
        referenceLength: Int64(referenceLength))
    }

    func isValid(nonce: [UInt8], domain: String, label: String, identityID: Digest) -> Bool {
      guard let bits = requiredBits(label: label), let domain = try? DomainName(domain),
        let puzzle = try? ProofOfWorkPuzzle(domain: domain, label: label,
          identityID: identityID, requiredBits: bits)
      else { return false }
      return puzzle.isSolved(by: nonce)
    }
  }

  public let domain: String
  public let database: String
  public let labelPattern: String
  public let maxClaimsPerIdentity: Int
  public let maxUpdatesPerIdentityPerHour: Int
  public let claimGraceAfterExpiry: Int
  public let proofOfWork: ProofOfWork

  public init(
    domain: String, database: String = "diem-profile-hosting.sqlite",
    labelPattern: String = "^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$",
    maxClaimsPerIdentity: Int = 3, maxUpdatesPerIdentityPerHour: Int = 12,
    claimGraceAfterExpiry: Int = 2_592_000, proofOfWork: ProofOfWork = .init()
  ) throws {
    guard let normalized = DomainName(normalizing: domain), normalized.name == domain,
      domain.contains(".")
    else { throw ConfigurationError.invalidValue("domain", "a lowercase domain of at least two labels") }
    guard maxClaimsPerIdentity >= 1 else { throw ConfigurationError.invalidValue("maxClaimsPerIdentity", "at least 1") }
    guard maxUpdatesPerIdentityPerHour >= 1 else {
      throw ConfigurationError.invalidValue("maxUpdatesPerIdentityPerHour", "at least 1")
    }
    guard claimGraceAfterExpiry >= 0 else { throw ConfigurationError.invalidValue("claimGraceAfterExpiry", "not negative") }
    guard !database.isEmpty else { throw ConfigurationError.invalidValue("database", "a path") }
    // The shortest label needs the most work, so it bounds every name.
    guard proofOfWork.baseBits >= 0, proofOfWork.bitsPerShorterCharacter >= 0,
      proofOfWork.referenceLength >= 0, proofOfWork.requiredBits(label: "a") != nil
    else {
      throw ConfigurationError.invalidValue("proofOfWork", "non-negative, requiring at most 64 bits for any name")
    }
    do { _ = try Regex(labelPattern) }
    catch { throw ConfigurationError.invalidValue("labelPattern", "a regular expression") }
    self.domain = domain
    self.database = database
    self.labelPattern = labelPattern
    self.maxClaimsPerIdentity = maxClaimsPerIdentity
    self.maxUpdatesPerIdentityPerHour = maxUpdatesPerIdentityPerHour
    self.claimGraceAfterExpiry = claimGraceAfterExpiry
    self.proofOfWork = proofOfWork
  }

  public init(from decoder: any Decoder) throws {
    try rejectUnknownKeys(decoder, allowed: ["domain", "database", "labelPattern", "maxClaimsPerIdentity",
      "maxUpdatesPerIdentityPerHour", "claimGraceAfterExpiry", "proofOfWork"])
    let c = try decoder.container(keyedBy: CodingKeys.self)
    try self.init(domain: c.decode(String.self, forKey: .domain),
      database: c.decodeIfPresent(String.self, forKey: .database) ?? "diem-profile-hosting.sqlite",
      labelPattern: c.decodeIfPresent(String.self, forKey: .labelPattern) ?? "^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$",
      maxClaimsPerIdentity: c.decodeIfPresent(Int.self, forKey: .maxClaimsPerIdentity) ?? 3,
      maxUpdatesPerIdentityPerHour: c.decodeIfPresent(Int.self, forKey: .maxUpdatesPerIdentityPerHour) ?? 12,
      claimGraceAfterExpiry: c.decodeIfPresent(Int.self, forKey: .claimGraceAfterExpiry) ?? 2_592_000,
      proofOfWork: c.decodeIfPresent(ProofOfWork.self, forKey: .proofOfWork) ?? .init())
  }

  /// `database` resolved against `directory` unless it is absolute.
  public func databasePath(relativeTo directory: String) -> String {
    URL(fileURLWithPath: database, relativeTo: URL(fileURLWithPath: directory, isDirectory: true)).path
  }

  func normalizedLabel(_ label: String) -> String? {
    guard !label.contains("."), let domain = DomainName(normalizing: label + ".example") else { return nil }
    return String(domain.name.dropLast(".example".count))
  }

  func validLabel(_ label: String) -> Bool {
    guard let label = normalizedLabel(label) else { return false }
    return (try? label.wholeMatch(of: Regex(labelPattern))) != nil
  }

  /// Whether `other` equals, contains or lies below the hosting domain.
  public func overlaps(domain other: String) -> Bool {
    guard let other = DomainName(normalizing: other)?.name else { return false }
    return domain == other || domain.hasSuffix("." + other) || other.hasSuffix("." + domain)
  }
}

public enum ConfigurationError: Error, CustomStringConvertible {
  case invalidValue(String, String), unknownKey(String)

  public var description: String {
    switch self {
    case .invalidValue(let key, let requirement): "profile hosting `\(key)` must be \(requirement)"
    case .unknownKey(let key): "profile hosting configuration has unknown key `\(key)`"
    }
  }
}

private struct AnyKey: CodingKey {
  let stringValue: String
  var intValue: Int? { nil }
  init?(stringValue: String) { self.stringValue = stringValue }
  init?(intValue: Int) { return nil }
}

private func rejectUnknownKeys(_ decoder: any Decoder, allowed: Set<String>) throws {
  let c = try decoder.container(keyedBy: AnyKey.self)
  for key in c.allKeys where !allowed.contains(key.stringValue) {
    throw ConfigurationError.unknownKey(key.stringValue)
  }
}
#endif
