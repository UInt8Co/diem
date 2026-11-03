import Diem

/// A signed revision with the proofs and name host its publication needs.
///
/// Store ``profile`` before publishing it: once a host holds a revision, it accepts only
/// later ones, so a revision lost after an unanswered PUT would block the identity.
public struct HostingPublication<Profile: DomainNamedProfile>: Sendable {
  public let profile: Profile
  public let proofs: [String: [UInt8]]
  /// The publication target; nil selects the first child name, then a listed apex.
  public let via: HostingTarget?

  public init(profile: Profile, proofs: [String: [UInt8]] = [:], via: String? = nil) {
    self.profile = profile
    self.proofs = proofs
    self.via = via.map(HostingTarget.name)
  }

  public init(profile: Profile, proofs: [String: [UInt8]] = [:], via: HostingTarget) {
    self.profile = profile
    self.proofs = proofs
    self.via = via
  }
}

extension ProfileHostingClient {
  /// Publishes a prepared revision with its proofs, retrying once on proof-required.
  public func publish<Profile>(_ publication: HostingPublication<Profile>,
    solver: some ProofOfWorkSolver
  ) async throws {
    if let target = publication.via {
      try await publish(publication.profile, via: target, proofs: publication.proofs, solver: solver)
    } else {
      try await publish(publication.profile, proofs: publication.proofs, solver: solver)
    }
  }
}

extension Identity where Profile: DomainNamedProfile {
  /// Plans and proves added names and signs the next revision listing them. Existing
  /// domains retain their order. Like Diem's other operations, nothing is adopted: the
  /// caller stores the revision, then publishes it.
  public func claiming<HTTP: HostingHTTPClient>(
    labels: [String], at host: ProfileHostingClient<HTTP>, solver: some ProofOfWorkSolver,
    transform: (Profile.Content, [DomainName]) throws -> Profile.Content
  ) async throws -> HostingPublication<Profile> {
    let plan = try await host.plan(labels: labels, identity: id)
    let proofs = try await host.prove(plan, identity: id, solver: solver)
    var domains = profile.domains
    for label in labels {
      let name = try DomainName(label + "." + host.domain.name)
      if !domains.contains(name) { domains.append(name) }
    }
    return HostingPublication(
      profile: try await hostedRevision(domains: domains, transform: transform), proofs: proofs)
  }

  /// Signs the next revision without the named hosted domains. When none remain, it is
  /// published via a listed apex or the first removed name. Store the revision before publishing.
  public func releasing<HTTP: HostingHTTPClient>(
    labels: [String], at host: ProfileHostingClient<HTTP>,
    transform: (Profile.Content, [DomainName]) throws -> Profile.Content
  ) async throws -> HostingPublication<Profile> {
    let held = host.labels(in: profile)
    for label in labels {
      guard validLabel(label, domain: host.domain) else {
        throw ProfileHostingError.invalidLabel(label)
      }
      guard held.contains(label) else { throw ProfileHostingError.hostNotListed }
    }
    guard let via = labels.first else { throw ProfileHostingError.noHostedName }
    let removed = labels.map { $0 + "." + host.domain.name }
    let domains = profile.domains.filter { !removed.contains($0.name) }
    let next = try await hostedRevision(domains: domains, transform: transform)
    let target: HostingTarget
    if let retained = host.labels(in: next).first { target = .name(retained) }
    else if next.domains.contains(host.domain) { target = .apex }
    else { target = .name(via) }
    return HostingPublication(profile: next, via: target)
  }

  private func hostedRevision(domains: [DomainName],
    transform: (Profile.Content, [DomainName]) throws -> Profile.Content
  ) async throws -> Profile {
    let content = try transform(profile.content, domains)
    guard try Profile.fields(for: content).domains == domains else {
      throw ProfileHostingError.domainsMismatch
    }
    let next = try await updating(content)
    guard next.domains == domains else { throw ProfileHostingError.domainsMismatch }
    return next
  }
}
