import Diem
import Testing
@testable import DiemProfileHostingClient

@Suite struct ClientTests {
  let domain = try! DomainName("id.example")
  let backend = TestBackend()

  func identity(_ labels: [String] = []) async throws -> TestIdentity {
    let domains = try labels.map { try DomainName($0.contains(".") ? $0 : $0 + ".id.example") }
    return try await TestIdentity(ProfileFields(domains: domains),
      identityKey: .generate(.ed25519, using: backend),
      deviceKey: .generate(.ed25519, using: backend), using: backend)
  }

  @Test func claimSeveralUpdateAndRelease() async throws {
    let server = FakeHost()
    let client = ProfileHostingClient(domain: domain, http: server)
    let identity = try await identity(["external.example"])
    let solver = RecordingSolver()
    let claim = try await identity.claiming(labels: ["bob", "alice"], at: client,
      solver: solver) { content, domains in
        ProfileFields(domains: domains, application: content.application)
      }
    #expect(await server.requests.filter { $0.method == .put }.isEmpty)
    try await client.publish(claim, solver: solver)
    let claimed = claim.profile
    #expect(claimed.revision == 2)
    #expect(identity.profile.revision == 1)
    #expect(claimed.domains.map(\.name) == ["external.example", "bob.id.example", "alice.id.example"])
    #expect(client.labels(in: claimed) == ["bob", "alice"])
    #expect(await server.requests.filter { $0.method == .put }.count == 1)
    #expect(await solver.puzzles.map(\.label) == ["bob", "alice"])
    #expect(try await client.profile(at: "alice") == claimed.encoding)
    #expect(try await client.profile(at: "bob") == claimed.encoding)
    let plan = try await client.plan(labels: ["bob", "alice", "reserved", "a.b"],
      identity: identity.id)
    #expect(plan.names.map(\.status) == [.held, .held, .invalid, .invalid])
    #expect(try await client.prove(["bob", "alice"], identity: identity.id, solver: solver).isEmpty)

    let adopted = try await TestIdentity(profile: claimed, deviceKey: identity.deviceKey,
      identityKey: identity.identityKey, using: backend)
    let updated = try await adopted.updating(claimed.fields)
    try await client.publish(updated)
    #expect(await server.requests.last?.headers["Diem-Hosting-Proof"] == nil)
    let current = try await TestIdentity(profile: updated, deviceKey: identity.deviceKey,
      identityKey: identity.identityKey, using: backend)
    let release = try await current.releasing(labels: ["bob", "alice"], at: client) { content, domains in
      ProfileFields(domains: domains, application: content.application)
    }
    #expect(release.via == "bob" && release.proofs.isEmpty)
    try await client.publish(release, solver: solver)
    let released = release.profile
    #expect(released.revision == 4)
    #expect(released.domains.map(\.name) == ["external.example"])
    #expect(await server.requests.last?.url == "https://bob.id.example/.well-known/diem/profile.cbor")
    #expect(try await client.profile(at: "bob") == nil)
    #expect(try await client.profile(at: "alice") == nil)
    #expect(current.profile.revision == 3)
  }

  @Test func partialReleaseUsesRetainedHost() async throws {
    let server = FakeHost()
    let client = ProfileHostingClient(domain: domain, http: server)
    let identity = try await identity(["alice", "bob"])
    try await client.publish(identity.profile, solver: PortableProofOfWorkSolver())
    let release = try await identity.releasing(labels: ["alice"], at: client) { _, domains in
      ProfileFields(domains: domains)
    }
    #expect(release.via == "bob")
    try await client.publish(release, solver: PortableProofOfWorkSolver())
    let next = release.profile
    #expect(client.labels(in: next) == ["bob"])
    #expect(await server.requests.last?.url == "https://bob.id.example/.well-known/diem/profile.cbor")
    #expect(try await client.profile(at: "alice") == nil)
    #expect(try await client.profile(at: "bob") == next.encoding)
    await #expect(throws: ProfileHostingError.hostNotListed) {
      try await client.publish(next, via: "alice")
    }
  }

  @Test func retrySolvesOnlyListedLabelsAndUsesPolicyFallback() async throws {
    for omitBits in [false, true] {
      let server = FakeHost()
      await server.configure(omitBits: omitBits, onlyMissing: true)
      let client = ProfileHostingClient(domain: domain, http: server)
      let identity = try await identity(["alice", "bob"])
      let solver = RecordingSolver()
      try await client.publish(identity.profile, solver: solver)
      #expect(await solver.puzzles.map(\.label) == ["bob"])
      #expect(await solver.puzzles.map(\.requiredBits) == [4])
      let requests = await server.requests
      #expect(requests.filter { $0.method == .put }.count == 2)
      #expect(requests.filter { $0.url == "https://id.example/.well-known/diem/hosting" }.count
        == (omitBits ? 1 : 0))
      #expect(requests.last?.headers["Diem-Hosting-Proof"]?.hasPrefix("bob=") == true)
    }
  }

  @Test func retryOccursOnlyOnce() async throws {
    let server = FakeHost()
    await server.configure(alwaysNeedsProof: true)
    let client = ProfileHostingClient(domain: domain, http: server)
    let identity = try await identity(["alice"])
    do {
      try await client.publish(identity.profile, solver: PortableProofOfWorkSolver())
      Issue.record("Expected proof refusal")
    } catch ProfileHostingError.problem(let problem) {
      #expect(problem.code == .proofRequired)
    }
    #expect(await server.requests.filter { $0.method == .put }.count == 2)
  }

  @Test func takenAndRateLimited() async throws {
    let server = FakeHost()
    let client = ProfileHostingClient(domain: domain, http: server)
    let first = try await identity(["alice"])
    let second = try await identity(["alice", "bob"])
    try await client.publish(first.profile, solver: PortableProofOfWorkSolver())
    #expect(try await client.plan(labels: ["alice"], identity: second.id).names.first?.status == .taken)
    let solver = RecordingSolver()
    await #expect(throws: ProfileHostingError.nameTaken("alice")) {
      try await client.prove(["bob", "alice"], identity: second.id, solver: solver)
    }
    #expect(await solver.puzzles.isEmpty)
    do {
      try await client.publish(second.profile, solver: solver)
      Issue.record("Expected conflict")
    } catch ProfileHostingError.problem(let problem) {
      #expect(problem.code == .nameTaken)
      #expect(problem.labels.map(\.label) == ["alice"])
    }
    #expect(try await client.profile(at: "bob") == nil)
    await server.configure(limited: true)
    do {
      try await client.publish(first.updating(first.profile.fields), solver: solver)
      Issue.record("Expected rate limit")
    } catch ProfileHostingError.problem(let problem) {
      #expect(problem.code == .rateLimited && problem.retryAfter == 37)
    }
    #expect(await solver.puzzles.isEmpty)
  }

  @Test func badSolverAndTransformAreRejected() async throws {
    let server = FakeHost()
    let client = ProfileHostingClient(domain: domain, http: server)
    let identity = try await identity(["alice"])
    let bad = RecordingSolver(bad: true)
    await #expect(throws: ProfileHostingError.invalidProof("alice")) {
      try await client.publish(identity.profile, solver: bad)
    }
    #expect(await server.requests.filter { $0.method == .put }.count == 1)
    await #expect(throws: ProfileHostingError.domainsMismatch) {
      try await identity.claiming(labels: ["bob"], at: client,
        solver: PortableProofOfWorkSolver()) { content, _ in content }
    }
    #expect(await server.requests.filter { $0.method == .put }.count == 1)
  }

  @Test func endpointAndResponseValidation() async throws {
    let stub = StubHTTP(.init(status: 302, headers: ["Location": "https://else.example"]))
    let client = ProfileHostingClient(domain: domain, http: stub)
    await #expect(throws: ProfileHostingError.unexpectedStatus(302)) { try await client.policy() }
    #expect(await stub.requests.count == 1)
    #expect(try await client.name("../alice").status == .invalid)
    await #expect(throws: ProfileHostingError.invalidLabel("a.b")) {
      try await client.profile(at: "a.b")
    }
    #expect(await stub.requests.count == 1)
    let mismatch = ProfileHostingClient(domain: domain,
      http: StubHTTP(FakeHost.json(FakeHost.policy(domain: "other.example"))))
    await #expect(throws: ProfileHostingError.domainMismatch) { try await mismatch.policy() }
    let identity = try await identity(["alice"])
    let wrong = ProfileHostingClient(domain: domain,
      http: StubHTTP(FakeHost.json(["identity": FakeHost.base64(identity.id.bytes),
        "revision": 2, "domains": ["alice.id.example"]])))
    await #expect(throws: ProfileHostingError.publishedMismatch) { try await wrong.publish(identity.profile) }
    let nested = try await self.identity(["alice", "nested.name.id.example"])
    #expect(client.labels(in: nested.profile) == ["alice"])
    await #expect(throws: ProfileHostingError.invalidLabel("nested.name.id.example")) {
      try await client.publish(nested.profile)
    }
  }
}
