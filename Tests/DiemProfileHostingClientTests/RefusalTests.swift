import Diem
import Testing
@testable import DiemProfileHostingClient

@Suite struct RefusalTests {
  let domain = try! DomainName("id.example")

  func identity() async throws -> TestIdentity {
    let backend = TestBackend()
    return try await TestIdentity(ProfileFields(domains: [DomainName("alice.id.example")]),
      identityKey: .generate(.ed25519, using: backend),
      deviceKey: .generate(.ed25519, using: backend), using: backend)
  }

  @Test func invalidRefusalsDoNoWork() async throws {
    let identity = try await identity()
    for labels in [
      [["label": "elsewhere", "reason": "proof-required", "requiredBits": 4]],
      [["label": "alice", "reason": "other", "requiredBits": 4]],
      [["label": "alice", "reason": "proof-required", "requiredBits": 4],
        ["label": "alice", "reason": "proof-required", "requiredBits": 4]],
    ] {
      let response = FakeHost.json(["type": "urn:diem:profile-hosting:proof-required",
        "title": "proof-required", "status": 403, "detail": "Proof", "labels": labels], status: 403)
      let http = StubHTTP(response)
      let host = ProfileHostingClient(domain: domain, http: http)
      let solver = RecordingSolver()
      await #expect(throws: ProfileHostingError.invalidResponse) {
        try await host.publish(identity.profile, solver: solver)
      }
      #expect(await solver.puzzles.isEmpty)
      #expect(await http.requests.count == 1)
    }
    for bits in [-1, 65, Int64.max] {
      let response = FakeHost.json(["type": "urn:diem:profile-hosting:proof-required",
        "title": "proof-required", "status": 403, "detail": "Proof",
        "labels": [["label": "alice", "reason": "proof-required", "requiredBits": bits]]],
        status: 403)
      let host = ProfileHostingClient(domain: domain, http: StubHTTP(response))
      let solver = RecordingSolver()
      await #expect(throws: ProfileHostingError.unsolvable("alice")) {
        try await host.publish(identity.profile, solver: solver)
      }
      #expect(await solver.puzzles.isEmpty)
    }
  }

  @Test func plansAreBoundToDomainAndIdentity() async throws {
    let host = ProfileHostingClient(domain: domain, http: FakeHost())
    let identity = try await identity()
    let plan = try await host.plan(labels: ["alice"], identity: identity.id)
    let solver = RecordingSolver()
    await #expect(throws: ProfileHostingError.domainsMismatch) {
      try await host.prove(plan, identity: Digest(hashing: []), solver: solver)
    }
    let other = ProfileHostingClient(domain: try DomainName("other.example"), http: FakeHost())
    await #expect(throws: ProfileHostingError.domainsMismatch) {
      try await other.prove(plan, identity: identity.id, solver: solver)
    }
    await #expect(throws: ProfileHostingError.invalidLabel("bad.name")) {
      try await host.prove(["alice", "bad.name"], identity: identity.id, solver: solver)
    }
    #expect(await solver.puzzles.isEmpty)
  }

  @Test func zeroBitsNeedNoSolver() async throws {
    let http = StubHTTP(FakeHost.json(["label": "alice", "status": "available", "requiredBits": 0]))
    let host = ProfileHostingClient(domain: domain, http: http)
    let solver = RecordingSolver(bad: true)
    let identity = Digest(hashing: [])
    #expect(try await host.prove(["alice"], identity: identity, solver: solver).isEmpty)
    #expect(await solver.puzzles.isEmpty)
  }

  @Test func schemaIntegersAndResponseBounds() async throws {
    let malformed = Array(#"{"label":"alice","status":"available","requiredBits":18446744073709551616}"#.utf8)
    let host = ProfileHostingClient(domain: domain, http: StubHTTP(.init(status: 200, body: malformed)))
    await #expect(throws: ProfileHostingError.invalidResponse) { try await host.name("alice") }
    let large = ProfileHostingClient(domain: domain, http: StubHTTP(.init(status: 200,
      body: Array(repeating: 0, count: JSON.maximumBytes + 1))))
    await #expect(throws: ProfileHostingError.tooLarge) { try await large.profile(at: "alice") }
    let wrongName = ProfileHostingClient(domain: domain, http: StubHTTP(FakeHost.json([
      "label": "bob", "status": "available", "requiredBits": 4])))
    await #expect(throws: ProfileHostingError.invalidResponse) { try await wrongName.name("alice") }
  }

  @Test func wrongPublishedIdentityAndEmptyHost() async throws {
    let identity = try await identity()
    let host = ProfileHostingClient(domain: domain, http: StubHTTP(FakeHost.json([
      "identity": "wrong", "revision": 1, "domains": ["alice.id.example"]])))
    await #expect(throws: ProfileHostingError.publishedMismatch) {
      try await host.publish(identity.profile)
    }
    let released = try await identity.updating(ProfileFields())
    await #expect(throws: ProfileHostingError.noHostedName) { try await host.publish(released) }
  }
}
