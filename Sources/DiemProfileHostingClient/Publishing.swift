import Diem

/// A child label under the hosting domain, or the hosting domain itself.
public enum HostingTarget: Sendable, Equatable {
  case name(String)
  case apex
}

extension ProfileHostingClient {
  /// One PUT replaces all claims for this identity under the hosting domain. Defaults
  /// to the first child name, then the apex if listed. A release may use a held name.
  public func publish(_ profile: some DomainNamedProfile, via label: String? = nil,
    proofs: [String: [UInt8]] = [:]
  ) async throws {
    try await publish(profile, via: publicationTarget(profile, label: label), proofs: proofs)
  }

  /// Publishes through an explicit child name or apex. Apex requests never send proofs.
  public func publish(_ profile: some DomainNamedProfile, via target: HostingTarget,
    proofs: [String: [UInt8]] = [:]
  ) async throws {
    let response = try await send(publication(profile, via: target, proofs: proofs))
    try accept(response, for: profile)
  }

  /// Sends `proofs`, then retries once on proof-required, solving exactly the labels listed
  /// by the server.
  public func publish(_ profile: some DomainNamedProfile, via label: String? = nil,
    proofs initial: [String: [UInt8]] = [:], solver: some ProofOfWorkSolver
  ) async throws {
    try await publish(profile, via: publicationTarget(profile, label: label), proofs: initial,
      solver: solver)
  }

  /// Retries child-name publication once on proof-required. Apex refusals never run a solver.
  public func publish(_ profile: some DomainNamedProfile, via target: HostingTarget,
    proofs initial: [String: [UInt8]] = [:], solver: some ProofOfWorkSolver
  ) async throws {
    let response = try await send(publication(profile, via: target, proofs: initial))
    if response.status == 403 {
      let problem = try HostingProblem(response: response)
      if problem.code == .proofRequired, case .name = target {
        let hosted = labels(in: profile)
        var seen: Set<String> = []
        // Validate the entire refusal before spending work on any label.
        for item in problem.labels {
          guard hosted.contains(item.label), seen.insert(item.label).inserted,
            item.reason == "proof-required"
          else { throw ProfileHostingError.invalidResponse }
          if let bits = item.requiredBits, !(0...64).contains(bits) {
            throw ProfileHostingError.unsolvable(item.label)
          }
        }
        var fallback: HostingPolicy?
        if problem.labels.contains(where: { $0.requiredBits == nil }) {
          fallback = try await policy()
        }
        var requirements: [(String, Int64)] = []
        for item in problem.labels {
          guard let bits = item.requiredBits ?? fallback?.requiredBits(for: item.label).map(Int64.init)
          else { throw ProfileHostingError.unsolvable(item.label) }
          requirements.append((item.label, bits))
        }
        var proofs = initial
        for (name, bits) in requirements {
          proofs[name] = try await solve(label: name, identity: profile.id, bits: bits, solver: solver)
        }
        try await publish(profile, via: target, proofs: proofs)
        return
      }
      throw ProfileHostingError.problem(problem)
    }
    try accept(response, for: profile)
  }

  private func publicationTarget(_ profile: some DomainNamedProfile, label: String?)
    throws(ProfileHostingError) -> HostingTarget
  {
    if let label { return .name(label) }
    if let first = labels(in: profile).first { return .name(first) }
    if profile.domains.contains(domain) { return .apex }
    throw .noHostedName
  }

  private func publication(_ profile: some DomainNamedProfile, via target: HostingTarget,
    proofs: [String: [UInt8]]
  ) throws(ProfileHostingError) -> HostingHTTPRequest {
    let hosted = labels(in: profile)
    for name in profile.domains where name != domain && name.name.hasSuffix("." + domain.name) {
      guard hostedLabel(name) != nil else { throw .invalidLabel(name.name) }
    }
    switch target {
    case .apex:
      guard profile.domains.contains(domain) else { throw .hostNotListed }
    case .name(let label):
      guard hosted.isEmpty || hosted.contains(label) else { throw .hostNotListed }
    }
    let bytes = profile.encoding
    guard bytes.count <= CBOR.maximumBytes else { throw .tooLarge }
    var headers = ["Content-Type": "application/cbor"]
    if case .name = target, !proofs.isEmpty {
      headers["Diem-Hosting-Proof"] = try hostingProofHeader(proofs)
    }
    return try HostingHTTPRequest(method: .put, url: profileURL(target), headers: headers, body: bytes)
  }

  private func accept(_ response: HostingHTTPResponse, for profile: some DomainNamedProfile)
    throws(ProfileHostingError)
  {
    try requireSuccess(response)
    let fields = try JSON(response.body).object()
    guard try fields.field("identity").string() == base64URL(profile.id.bytes),
      try fields.field("revision").unsigned() == profile.revision
    else { throw .publishedMismatch }
    // Require the Published schema, but leave claim ordering to the host.
    for name in try fields.field("domains").array() { _ = try name.string() }
  }
}
