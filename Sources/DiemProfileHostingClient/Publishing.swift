import Diem

extension ProfileHostingClient {
  /// One PUT replaces all claims for this identity under the hosting domain. A release
  /// of every name must use a currently held name as `via`.
  public func publish(_ profile: some DomainNamedProfile, via label: String? = nil,
    proofs: [String: [UInt8]] = [:]
  ) async throws {
    let response = try await send(publication(profile, via: label, proofs: proofs))
    try accept(response, for: profile)
  }

  /// Sends `proofs`, then retries once on proof-required, solving exactly the labels listed
  /// by the server.
  public func publish(_ profile: some DomainNamedProfile, via label: String? = nil,
    proofs initial: [String: [UInt8]] = [:], solver: some ProofOfWorkSolver
  ) async throws {
    let response = try await send(publication(profile, via: label, proofs: initial))
    if response.status == 403 {
      let problem = try HostingProblem(response: response)
      if problem.code == .proofRequired {
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
        try await publish(profile, via: label, proofs: proofs)
        return
      }
      throw ProfileHostingError.problem(problem)
    }
    try accept(response, for: profile)
  }

  private func publication(_ profile: some DomainNamedProfile, via label: String?,
    proofs: [String: [UInt8]]
  ) throws(ProfileHostingError) -> HostingHTTPRequest {
    let hosted = labels(in: profile)
    for name in profile.domains where name.name.hasSuffix("." + domain.name) {
      guard hostedLabel(name) != nil else { throw .invalidLabel(name.name) }
    }
    guard let target = label ?? hosted.first else { throw .noHostedName }
    guard hosted.isEmpty || hosted.contains(target) else { throw .hostNotListed }
    let bytes = profile.encoding
    guard bytes.count <= CBOR.maximumBytes else { throw .tooLarge }
    var headers = ["Content-Type": "application/cbor"]
    if !proofs.isEmpty { headers["Diem-Hosting-Proof"] = try hostingProofHeader(proofs) }
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
