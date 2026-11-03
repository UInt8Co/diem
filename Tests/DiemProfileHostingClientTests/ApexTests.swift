import Diem
import Testing
@testable import DiemProfileHostingClient

@Suite struct ApexTests {
  let domain = try! DomainName("id.example")

  @Test func policyCapabilitiesAndGroups() throws {
    let apex = try HostingPolicy(json: FakeHost.json([
      "domain": domain.name, "apex": true]).body, domain: domain)
    #expect(apex.apex && !apex.servesChildNames && apex.names == nil)
    #expect(apex.requiredBits(for: "alice") == nil)
    let children = try HostingPolicy(json: FakeHost.json(FakeHost.policy()).body, domain: domain)
    #expect(!children.apex && children.servesChildNames)
    #expect(children.names?.labelPattern == "[a-z0-9-]+")
    #expect(children.requiredBits(for: "alice") == 4)
    var both = FakeHost.policy()
    both["apex"] = true
    #expect(try HostingPolicy(json: FakeHost.json(both).body, domain: domain).servesChildNames)
    let invalid: [[String: Any]] = [
      ["domain": domain.name],
      ["domain": domain.name, "apex": false],
      ["domain": domain.name, "apex": "true"],
      ["domain": domain.name, "apex": true, "labelPattern": ".*"],
      FakeHost.policy().filter { $0.key != "proofOfWork" },
    ]
    for fields in invalid {
      #expect(throws: ProfileHostingError.invalidResponse) {
        try HostingPolicy(json: FakeHost.json(fields).body, domain: domain)
      }
    }
  }

  @Test func defaultAndExplicitTargets() async throws {
    let fixtures = ClientTests()
    let apexOnly = try await fixtures.identity(["id.example", "external.example"])
    let both = try await fixtures.identity(["id.example", "bob", "alice"])
    for (identity, explicit, expected) in [
      (apexOnly, false, "id.example"), (both, false, "bob.id.example"),
      (both, true, "id.example"),
    ] {
      let http = StubHTTP(FakeHost.json([
        "identity": FakeHost.base64(identity.id.bytes), "revision": identity.profile.revision,
        "domains": identity.profile.domains.map(\.name)]))
      let client = ProfileHostingClient(domain: domain, http: http)
      if explicit {
        try await client.publish(identity.profile, via: .apex, proofs: ["bob": [1]])
      } else {
        try await client.publish(identity.profile)
      }
      let request = try #require(await http.requests.first)
      #expect(request.method == .put)
      #expect(request.url == "https://" + expected + "/.well-known/diem/profile.cbor")
      #expect(request.body == identity.profile.encoding)
      #expect(request.headers == ["Content-Type": "application/cbor"])
    }
    let http = StubHTTP(.init(status: 200))
    let client = ProfileHostingClient(domain: domain, http: http)
    let childOnly = try await fixtures.identity(["alice"])
    await #expect(throws: ProfileHostingError.hostNotListed) {
      try await client.publish(childOnly.profile, via: .apex)
    }
    #expect(await http.requests.isEmpty)
  }

  @Test func apexFetch() async throws {
    for status in [200, 404] {
      let http = StubHTTP(.init(status: status, body: [1, 2, 3]))
      let client = ProfileHostingClient(domain: domain, http: http)
      #expect(try await client.profile(at: .apex) == (status == 404 ? nil : [1, 2, 3]))
      #expect(await http.requests.first?.url == "https://id.example/.well-known/diem/profile.cbor")
    }
  }

  @Test func apexProofRefusalNeverSolvesOrRetries() async throws {
    // Even a refusal naming a listed child must not trigger work on an apex request.
    let identity = try await ClientTests().identity(["id.example", "alice"])
    let http = StubHTTP(FakeHost.json([
      "type": "urn:diem:profile-hosting:proof-required", "title": "Proof", "detail": "Proof",
      "status": 403, "labels": [["label": "alice", "reason": "proof-required", "requiredBits": 4]]],
      status: 403))
    let client = ProfileHostingClient(domain: domain, http: http)
    let solver = RecordingSolver()
    do {
      try await client.publish(identity.profile, via: .apex, solver: solver)
      Issue.record("Expected refusal")
    } catch ProfileHostingError.problem(let problem) {
      #expect(problem.code == .proofRequired)
    }
    #expect(await solver.puzzles.isEmpty)
    #expect(await http.requests.count == 1)
  }

  @Test func releasingChildrenRetainsApex() async throws {
    let identity = try await ClientTests().identity(["alice", "id.example"])
    let http = StubHTTP(FakeHost.json([
      "identity": FakeHost.base64(identity.id.bytes), "revision": identity.profile.revision + 1,
      "domains": [domain.name]]))
    let client = ProfileHostingClient(domain: domain, http: http)
    let release = try await identity.releasing(labels: ["alice"], at: client) { _, domains in
      ProfileFields(domains: domains)
    }
    #expect(release.via == .apex)
    #expect(release.profile.domains == [domain])
    let solver = RecordingSolver()
    try await client.publish(release, solver: solver)
    #expect(await solver.puzzles.isEmpty)
    #expect(await http.requests.first?.url == "https://id.example/.well-known/diem/profile.cbor")
  }
}
