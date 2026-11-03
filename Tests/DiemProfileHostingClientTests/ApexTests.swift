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
    #expect(children.requiredBits(for: "@") == nil)
    var both = FakeHost.policy()
    both["apex"] = true
    let combined = try HostingPolicy(json: FakeHost.json(both).body, domain: domain)
    #expect(combined.servesChildNames && combined.requiredBits(for: "@") == nil)
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
        try await client.publish(identity.profile, via: .apex, proofs: ["@": [2], "bob": [1]])
      } else {
        try await client.publish(identity.profile)
      }
      let request = try #require(await http.requests.first)
      #expect(request.method == .put)
      #expect(request.url == "https://" + expected + "/.well-known/diem/profile.cbor")
      #expect(request.body == identity.profile.encoding)
      #expect(request.headers["Content-Type"] == "application/cbor")
      #expect(request.headers["Diem-Hosting-Proof"] == (explicit ? "@=Ag, bob=AQ" : nil))
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

  @Test func apexStatusPlanningAndProof() async throws {
    let identity = try await ClientTests().identity(["id.example"])
    let http = FakeHost()
    let client = ProfileHostingClient(domain: domain, http: http)
    let name = try await client.name("@")
    #expect(name.label == "@" && name.status == .available && name.requiredBits == 4)
    #expect(await http.requests.first?.url == "https://id.example/.well-known/diem/hosting/names/@")
    let plan = try await client.plan(labels: ["@"], identity: identity.id)
    #expect(plan.names.map(\.status) == [.needsProof(requiredBits: 4)])
    let solver = RecordingSolver()
    let proofs = try await client.prove(plan, identity: identity.id, solver: solver)
    #expect(await solver.puzzles.map(\.label) == ["@"])
    try await client.publish(identity.profile, via: "@", proofs: proofs)
    #expect(try await client.plan(labels: ["@"], identity: identity.id).names.map(\.status) == [.held])
    #expect(try await client.profile(at: "@") == identity.profile.encoding)
  }

  @Test func apexProofRequiredSolvesAndRetries() async throws {
    let identity = try await ClientTests().identity(["id.example", "alice"])
    let http = FakeHost()
    let client = ProfileHostingClient(domain: domain, http: http)
    let solver = RecordingSolver()
    try await client.publish(identity.profile, via: .apex, solver: solver)
    let requests = await http.requests
    #expect(requests.count == 2)
    #expect(requests.allSatisfy { $0.method == .put
      && $0.url == "https://id.example/.well-known/diem/profile.cbor"
      && $0.body == identity.profile.encoding })
    #expect(requests.first?.headers["Diem-Hosting-Proof"] == nil)
    let puzzles = await solver.puzzles
    #expect(puzzles.map(\.label) == ["@", "alice"])
    #expect(puzzles.allSatisfy { $0.requiredBits == 4 && $0.identityID == identity.id })
    let header = try #require(requests.last?.headers["Diem-Hosting-Proof"])
    #expect(header.hasPrefix("@=") && header.contains(", alice="))
    #expect(try await client.profile(at: .apex) == identity.profile.encoding)
  }

  @Test func missingApexDifficultyIsUnsolvable() async throws {
    let identity = try await ClientTests().identity(["id.example", "alice"])
    let statusHTTP = StubHTTP(FakeHost.json(["label": "@", "status": "available"]))
    let statusClient = ProfileHostingClient(domain: domain, http: statusHTTP)
    let solver = RecordingSolver()
    await #expect(throws: ProfileHostingError.unsolvable("@")) {
      try await statusClient.prove(["@"], identity: identity.id, solver: solver)
    }
    #expect(await statusHTTP.requests.count == 1)
    let http = StubHTTP(FakeHost.json([
      "type": "urn:diem:profile-hosting:proof-required", "title": "Proof", "detail": "Proof",
      "status": 403, "labels": [
        ["label": "alice", "reason": "proof-required", "requiredBits": 4],
        ["label": "@", "reason": "proof-required"]]],
      status: 403))
    let client = ProfileHostingClient(domain: domain, http: http)
    await #expect(throws: ProfileHostingError.unsolvable("@")) {
      try await client.publish(identity.profile, via: .apex, solver: solver)
    }
    #expect(await solver.puzzles.isEmpty)
    #expect(await http.requests.count == 1)
  }

  @Test func apexPuzzleAndMixedHeaderGrammar() throws {
    let identity = try Digest(bytes: Array(1...32))
    let puzzle = try ProofOfWorkPuzzle(domain: domain, label: "@",
      identityID: identity, requiredBits: 4)
    #expect(puzzle.input == Array("diem-profile-hosting-pow-v1\0id.example\0@\0".utf8) + identity.bytes)
    #expect(ProofOfWorkPuzzle.requiredBits(for: "@", baseBits: 4,
      bitsPerShorterCharacter: 0, referenceLength: 8) == nil)
    #expect(try hostingProofHeader(["bob": [251, 255], "@": [1], "alice": [2]])
      == "@=AQ, alice=Ag, bob=-_8")
    #expect(throws: ProfileHostingError.invalidLabel("@@")) {
      try hostingProofHeader(["@@": [1]])
    }
    #expect(throws: ProfileHostingError.invalidLabel("@alice")) {
      try ProofOfWorkPuzzle(domain: domain, label: "@alice", identityID: identity, requiredBits: 4)
    }
    #expect(throws: ProfileHostingError.invalidProof("@")) {
      try hostingProofHeader(["@": []])
    }
    #expect(throws: ProfileHostingError.invalidResponse) {
      try HostingProblem(response: FakeHost.json([
        "type": "urn:diem:profile-hosting:proof-required", "title": "Proof", "detail": "Proof",
        "status": 403, "labels": [["label": "@@", "reason": "proof-required"]]], status: 403))
    }
  }

  @Test func claimingAndReleasingApex() async throws {
    let identity = try await ClientTests().identity(["external.example"])
    let http = FakeHost()
    let client = ProfileHostingClient(domain: domain, http: http)
    let solver = RecordingSolver()
    let claim = try await identity.claiming(labels: ["@", "alice"], at: client,
      solver: solver) { _, domains in ProfileFields(domains: domains) }
    #expect(claim.profile.domains.map(\.name) == ["external.example", domain.name, "alice.id.example"])
    #expect(client.labels(in: claim.profile) == ["@", "alice"])
    #expect(Set(claim.proofs.keys) == Set(["@", "alice"]))
    try await client.publish(claim, solver: solver)
    #expect(await http.requests.last?.url == "https://alice.id.example/.well-known/diem/profile.cbor")
    let current = try await TestIdentity(profile: claim.profile, deviceKey: identity.deviceKey,
      identityKey: identity.identityKey, using: identity.backend)
    let partial = try await current.releasing(labels: ["@"], at: client) { _, domains in
      ProfileFields(domains: domains)
    }
    #expect(partial.profile.domains.map(\.name) == ["external.example", "alice.id.example"])
    #expect(partial.via == .name("alice"))
    let release = try await current.releasing(labels: ["@", "alice"], at: client) { _, domains in
      ProfileFields(domains: domains)
    }
    #expect(release.profile.domains.map(\.name) == ["external.example"])
    #expect(release.via == .apex)
    try await client.publish(release, solver: solver)
    #expect(await http.requests.last?.url == "https://id.example/.well-known/diem/profile.cbor")
    #expect(try await client.profile(at: .apex) == nil)
    #expect(try await client.profile(at: "alice") == nil)
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
