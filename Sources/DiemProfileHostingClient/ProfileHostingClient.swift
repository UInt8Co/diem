import Diem

public struct ProfileHostingClient<HTTP: HostingHTTPClient>: Sendable {
  public let domain: DomainName
  public let http: HTTP

  public init(domain: DomainName, http: HTTP) {
    self.domain = domain
    self.http = http
  }

  public func policy() async throws -> HostingPolicy {
    let response = try await send(.init(method: .get,
      url: "https://" + domain.name + "/.well-known/diem/hosting"))
    try requireSuccess(response)
    return try HostingPolicy(json: response.body, domain: domain)
  }

  /// Labels are lowercase DNS labels; pattern validity is decided by the host.
  public func name(_ label: String) async throws -> HostedName {
    guard validLabel(label, domain: domain) else {
      return HostedName(label: label, status: .invalid, requiredBits: nil)
    }
    let response = try await send(.init(method: .get,
      url: "https://" + domain.name + "/.well-known/diem/hosting/names/" + label))
    try requireSuccess(response)
    let fields = try JSON(response.body).object()
    guard try fields.field("label").string() == label,
      let status = try HostedName.Status(rawValue: fields.field("status").string())
    else { throw ProfileHostingError.invalidResponse }
    return try HostedName(label: label, status: status,
      requiredBits: fields["requiredBits"]?.integer())
  }

  /// Raw profile bytes, or nil on 404. The caller verifies signatures and validity.
  public func profile(at label: String) async throws -> [UInt8]? {
    let response = try await send(.init(method: .get, url: profileURL(label)))
    if response.status == 404 { return nil }
    try requireSuccess(response)
    return response.body
  }

  /// Direct children of this domain, in signed profile order.
  public func labels(in profile: some DomainNamedProfile) -> [String] {
    profile.domains.compactMap { hostedLabel($0) }
  }

  /// Ownership is an unverified discovery hint. The server decides the subsequent PUT.
  public func plan(labels: [String], identity: Digest) async throws -> HostingPlan {
    var names: [HostingPlan.Name] = []
    var fallback: HostingPolicy?
    for label in labels {
      let name = try await name(label)
      let status: HostingPlan.Status
      switch name.status {
      case .invalid: status = .invalid
      case .claimed:
        if let bytes = try await profile(at: label) {
          status = try ProfileRecord(encoding: bytes).id == identity ? .held : .taken
          break
        }
        fallthrough
      case .available:
        let bits: Int64
        if let required = name.requiredBits { bits = required }
        else {
          if fallback == nil { fallback = try await policy() }
          guard let required = fallback!.requiredBits(for: label) else {
            throw ProfileHostingError.unsolvable(label)
          }
          bits = Int64(required)
        }
        status = .needsProof(requiredBits: bits)
      }
      names.append(.init(label: label, status: status))
    }
    return HostingPlan(domain: domain, identityID: identity, names: names)
  }

  public func prove(_ plan: HostingPlan, identity: Digest, solver: some ProofOfWorkSolver)
    async throws -> [String: [UInt8]]
  {
    guard plan.domain == domain, plan.identityID == identity else {
      throw ProfileHostingError.domainsMismatch
    }
    // Refuse doomed plans before doing any work.
    for name in plan.names {
      switch name.status {
      case .invalid: throw ProfileHostingError.invalidLabel(name.label)
      case .taken: throw ProfileHostingError.nameTaken(name.label)
      case .needsProof(let bits):
        guard (0...64).contains(bits) else { throw ProfileHostingError.unsolvable(name.label) }
      case .held: break
      }
    }
    var proofs: [String: [UInt8]] = [:]
    for name in plan.names {
      if case .needsProof(let bits) = name.status, bits > 0, proofs[name.label] == nil {
        proofs[name.label] = try await solve(label: name.label, identity: identity,
          bits: bits, solver: solver)
      }
    }
    return proofs
  }

  public func prove(_ labels: [String], identity: Digest, solver: some ProofOfWorkSolver)
    async throws -> [String: [UInt8]]
  {
    try await prove(plan(labels: labels, identity: identity), identity: identity, solver: solver)
  }

  func solve(label: String, identity: Digest, bits: Int64, solver: some ProofOfWorkSolver)
    async throws -> [UInt8]
  {
    guard (0...64).contains(bits) else { throw ProfileHostingError.unsolvable(label) }
    let puzzle = try ProofOfWorkPuzzle(domain: domain, label: label,
      identityID: identity, requiredBits: Int(bits))
    try checkHostingCancellation()
    let nonce = try await solver.solve(puzzle)
    try checkHostingCancellation()
    guard puzzle.isSolved(by: nonce) else { throw ProfileHostingError.invalidProof(label) }
    return nonce
  }

  func hostedLabel(_ name: DomainName) -> String? {
    let suffix = "." + domain.name
    guard name.name.hasSuffix(suffix) else { return nil }
    let label = String(name.name.dropLast(suffix.count))
    return validLabel(label, domain: domain) ? label : nil
  }

  func profileURL(_ label: String) throws(ProfileHostingError) -> String {
    guard validLabel(label, domain: domain) else { throw .invalidLabel(label) }
    return "https://" + label + "." + domain.name + "/.well-known/diem/profile.cbor"
  }

  func send(_ request: HostingHTTPRequest) async throws -> HostingHTTPResponse {
    try checkHostingCancellation()
    let response = try await http.send(request)
    guard response.body.count <= JSON.maximumBytes else { throw ProfileHostingError.tooLarge }
    return response
  }

  func requireSuccess(_ response: HostingHTTPResponse) throws(ProfileHostingError) {
    guard response.status != 200 else { return }
    if (400...599).contains(response.status), !response.body.isEmpty {
      throw .problem(try HostingProblem(response: response))
    }
    throw .unexpectedStatus(response.status)
  }
}
