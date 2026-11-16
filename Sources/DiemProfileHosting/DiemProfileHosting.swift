#if ProfileHostingServer
import Diem
import DiemProfileHostingClient
import DiemSwiftCrypto
import Hummingbird

#if canImport(FoundationEssentials)
  import FoundationEssentials
#else
  import Foundation
#endif

/// First-come name claims and signed profile publication under one hosting domain.
public actor DiemProfileHosting {
  /// Where every hosted name serves and accepts its profile.
  public static let profilePath = "/.well-known/diem/profile.cbor"

  public nonisolated let configuration: DiemProfileHostingConfiguration
  /// ``profilePath`` followed by the aliases given at initialization.
  public nonisolated let profilePaths: [String]
  private let database: HostingDatabase
  private let now: @Sendable () -> UInt64
  private var verifications = 0

  /// `profileAliases` are further absolute paths for the same profile resource, such as an
  /// application's own well-known path. `":memory:"` opens a database that the host removes
  /// when it shuts down.
  public init(configuration: DiemProfileHostingConfiguration, databasePath: String,
    profileAliases: [String] = [],
    now: @escaping @Sendable () -> UInt64 = { UInt64(Date().timeIntervalSince1970) }
  ) async throws {
    for alias in profileAliases where !alias.hasPrefix("/") || alias.hasPrefix("/.well-known/diem/hosting") {
      throw ConfigurationError.invalidValue("profile alias \(alias)", "an absolute path outside the hosting API")
    }
    self.configuration = configuration
    profilePaths = [Self.profilePath] + profileAliases.filter { $0 != Self.profilePath }
    self.now = now
    database = try await HostingDatabase(path: databasePath)
  }

  public nonisolated func middleware<Context: RequestContext>() -> ProfileHostingMiddleware<Context> {
    ProfileHostingMiddleware(hosting: self)
  }

  /// Closes the database; later requests are refused as `busy`. Calling it again does nothing.
  public func shutdown() async { await database.shutdown() }

  nonisolated var policy: HostingJSON.Policy { .init(configuration) }

  func profile(label: String) async throws -> Data? {
    try await database.profile(label: label, now: now(), grace: configuration.claimGraceAfterExpiry)
  }

  func hasProfile(label: String) async throws -> Bool {
    try await database.hasProfile(label: label, now: now(), grace: configuration.claimGraceAfterExpiry)
  }

  func publish(_ bytes: [UInt8], label: String, proof: String?) async throws -> HostingReceipt {
    guard verifications < 8 else {
      throw HostingProblem(.busy, status: 503, detail: "Signature verification is busy")
    }
    verifications += 1
    defer { verifications -= 1 }
    let profile: ProfileRecord
    let time = now()
    do {
      profile = try ProfileRecord(encoding: bytes)
      try await profile.verify(using: SwiftCryptoBackend(), at: time)
    } catch {
      throw HostingProblem(.invalidProfile, status: 422,
        detail: "The profile is malformed, invalid or not currently valid")
    }
    return try await database.publish(profile, label: label, proof: proof, configuration: configuration, now: time)
  }

  func name(_ label: String) async throws -> HostingJSON.Name {
    let label = configuration.normalizedLabel(label) ?? label
    guard configuration.validLabel(label) else { return .init(label: label, status: "invalid") }
    let claimed = try await database.hasProfile(label: label, now: now(), grace: configuration.claimGraceAfterExpiry)
    return .init(label: label, status: claimed ? "claimed" : "available",
      requiredBits: configuration.proofOfWork.requiredBits(label: label))
  }
}

/// What an accepted publication answers: the identity, its revision and its hosted names.
struct HostingReceipt: Sendable {
  let identity: Data
  let revision: UInt64
  let domains: [String]
}
#endif
