#if ProfileHostingServer
import Diem
import DiemProfileHostingClient
import DiemSwiftCrypto
import HTTPTypes
import Hummingbird
import HummingbirdTesting
import Testing

@testable import DiemProfileHosting

#if canImport(FoundationEssentials)
  import FoundationEssentials
#else
  import Foundation
#endif

@Suite struct ProfileHostingTests {
  static let path = "/.well-known/diem/profile.cbor"
  static let legacy = "/.well-known/example/profile.cbor"
  static let policy = "/.well-known/diem/hosting"

  func config(claims: Int = 3, updates: Int = 12, grace: Int = 100, bits: Int = 0,
    pattern: String = "^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$"
  ) throws -> DiemProfileHostingConfiguration {
    try .init(domain: "id.example", labelPattern: pattern, maxClaimsPerIdentity: claims,
      maxUpdatesPerIdentityPerHour: updates, claimGraceAfterExpiry: grace,
      proofOfWork: .init(baseBits: bits, bitsPerShorterCharacter: 0))
  }

  func identity(_ names: [String], clock: TestBackend, lifetime: UInt64 = 1000) async throws -> TestIdentity {
    try await TestIdentity(fields(names), identityKey: .generate(.ed25519, using: clock),
      deviceKey: .generate(.ed25519, using: clock), profileLifetime: lifetime, using: clock)
  }

  func fields(_ labels: [String]) throws -> ProfileFields {
    .init(domains: try labels.map { try DomainName($0.contains(".") ? $0 : $0 + ".id.example") })
  }

  func withHost(_ configuration: DiemProfileHostingConfiguration? = nil, clock: TestBackend = .init(),
    path: String = ":memory:",
    _ body: @Sendable (any TestClientProtocol) async throws -> Void
  ) async throws {
    let host = try await DiemProfileHosting(configuration: configuration ?? config(), databasePath: path,
      profileAliases: [Self.legacy], now: { clock.now })
    defer { await host.shutdown() }
    let router = Router()
    router.middlewares.add(TestAuthorityMiddleware())
    router.middlewares.add(host.middleware())
    router.get("/oauth") { _, _ in Response(status: .accepted) }
    try await Application(router: router).test(.router, body)
  }

  func put(_ client: any TestClientProtocol, _ profile: ProfileRecord, host: String = "alice.id.example",
    path: String = Self.path, proof: String? = nil, contentType: String? = nil
  ) async throws -> TestResponse {
    var headers: HTTPFields = [HTTPField.Name("x-test-authority")!: host]
    headers[HTTPField.Name("Diem-Hosting-Proof")!] = proof
    headers[.contentType] = contentType
    return try await client.execute(uri: path, method: .put, headers: headers, body: .init(bytes: profile.encoding))
  }

  /// Parsed as clients parse it.
  func problem(_ response: TestResponse) throws -> HostingProblem {
    var headers: [String: String] = [:]
    for field in response.headers { headers[field.name.canonicalName] = field.value }
    return try HostingProblem(response: HostingHTTPResponse(status: Int(response.status.code),
      headers: headers, body: Array(response.body.readableBytesView)))
  }

  func code(_ response: TestResponse) throws -> String { try problem(response).code.rawValue }

  func solve(_ c: DiemProfileHostingConfiguration, _ label: String, _ id: Diem.Digest) async throws -> [UInt8] {
    let bits = try #require(c.proofOfWork.requiredBits(label: label))
    return try await PortableProofOfWorkSolver().solve(
      ProofOfWorkPuzzle(domain: DomainName(c.domain), label: label, identityID: id, requiredBits: bits))
  }

  @Test func configuration() throws {
    let defaults = try JSONDecoder().decode(DiemProfileHostingConfiguration.self, from: Data(#"{"domain":"id.example"}"#.utf8))
    #expect(defaults.maxClaimsPerIdentity == 3)
    #expect(defaults.maxUpdatesPerIdentityPerHour == 12)
    #expect(defaults.claimGraceAfterExpiry == 2_592_000)
    #expect(defaults.proofOfWork.requiredBits(label: "a") == 34)
    #expect(defaults.proofOfWork.requiredBits(label: "@") == nil)
    #expect(defaults.databasePath(relativeTo: "/data") == "/data/diem-profile-hosting.sqlite")
    #expect(try DiemProfileHostingConfiguration(domain: "id.example", database: "/elsewhere/db").databasePath(relativeTo: "/data") == "/elsewhere/db")
    let roundTrip = try JSONDecoder().decode(DiemProfileHostingConfiguration.self, from: JSONEncoder().encode(defaults))
    #expect(roundTrip.domain == defaults.domain)
    for json in [#"{"domain":"localhost"}"#, #"{"domain":"ID.example"}"#,
      #"{"domain":"id.example","extra":1}"#, #"{"domain":"id.example","labelPattern":"["}"#,
      #"{"domain":"id.example","maxClaimsPerIdentity":0}"#, #"{"domain":"id.example","maxUpdatesPerIdentityPerHour":0}"#,
      #"{"domain":"id.example","claimGraceAfterExpiry":-1}"#,
      #"{"domain":"id.example","proofOfWork":{"extra":1}}"#,
      #"{"domain":"id.example","proofOfWork":{"baseBits":65}}"#,
      #"{"domain":"id.example","proofOfWork":{"bitsPerShorterCharacter":-1}}"#] {
      #expect(throws: (any Error).self) {
        try JSONDecoder().decode(DiemProfileHostingConfiguration.self, from: Data(json.utf8))
      }
    }
    #expect(defaults.overlaps(domain: "example" ) == false)
    for domain in ["id.example", "a.id.example", "example.id.example"] { #expect(defaults.overlaps(domain: domain)) }
    #expect(try DiemProfileHostingConfiguration(domain: "a.id.example").overlaps(domain: "id.example"))
    #expect(!defaults.overlaps(domain: "dc.example"))
    #expect(defaults.validLabel("ALICE"))
    #expect(!defaults.validLabel("a.b"))
    #expect(!defaults.validLabel("-alice"))
    #expect(!defaults.validLabel(String(repeating: "a", count: 64)))
  }

  @Test func proofOfWork() async throws {
    let pow = DiemProfileHostingConfiguration.ProofOfWork(baseBits: 8, bitsPerShorterCharacter: 2, referenceLength: 4)
    #expect(pow.requiredBits(label: "a") == 14)
    #expect(pow.requiredBits(label: "alice") == 8)
    let id = Diem.Digest(hashing: [1])
    let nonce = try await solve(.init(domain: "id.example", proofOfWork: pow), "alice", id)
    #expect(pow.isValid(nonce: nonce, domain: "id.example", label: "alice", identityID: id))
    #expect(!pow.isValid(nonce: nonce, domain: "id.example", label: "alice", identityID: .init(hashing: [2])))
    #expect(!pow.isValid(nonce: nonce, domain: "else.example", label: "alice", identityID: id))
    #expect(!pow.isValid(nonce: nonce, domain: "id.example", label: "bob", identityID: id))
    #expect(!pow.isValid(nonce: [], domain: "id.example", label: "alice", identityID: id))
    #expect(!pow.isValid(nonce: Array(repeating: 0, count: 65), domain: "id.example", label: "alice", identityID: id))
    // The grammar itself is the client's; hosts add the absent header and the apex rule.
    #expect(parseProof(nil, limit: 3) == [:])
    #expect(parseProof("alice=AA=", limit: 3) == nil)
    #expect(parseProof(" alice = AA , bob = AQ ", limit: 3) == ["alice": [0], "bob": [1]])
    #expect(parseProof("@=AA, alice=AA", limit: 3) == nil)
    #expect(parseProof("@=AA, alice=AA", limit: 3, allowApex: true) == ["@": [0], "alice": [0]])
    #expect(throws: Never.self) { try HostingProofHeader.validateForApex("@=AA") }
    #expect(throws: HostingProblem.self) { try HostingProofHeader.validateForApex("@=") }
  }

  @Test func severalClaimsAndAliases() async throws {
    let clock = TestBackend()
    let alice = try await identity(["alice", "bob", "external.example"], clock: clock)
    try await withHost(clock: clock) { (client: any TestClientProtocol) async throws in
      let response = try await put(client, alice.profile, contentType: "text/plain")
      #expect(response.status == .ok)
      let result = try JSONDecoder().decode(Published.self, from: Data(response.body.readableBytesView))
      #expect(result.domains == ["alice.id.example", "bob.id.example"])
      #expect(result.identity == Base64URL.encode(alice.id.bytes))
      for host in ["alice.id.example", "BOB.ID.EXAMPLE:443"] {
        for path in [Self.path, Self.legacy] {
          let get = try await client.execute(uri: path, method: .get, headers: [HTTPField.Name("x-test-authority")!: host])
          #expect(get.status == .ok)
          #expect(Array(get.body.readableBytesView) == alice.profile.encoding)
          #expect(get.headers[.contentType] == "application/cbor")
          #expect(get.headers[.cacheControl] == "no-store")
          #expect(get.headers[.accessControlAllowOrigin] == "*")
          let head = try await client.execute(uri: path, method: .head, headers: [HTTPField.Name("x-test-authority")!: host])
          #expect(head.status == .ok)
          #expect(head.body.readableBytes == 0)
        }
      }
      #expect(try await put(client, alice.profile, path: Self.legacy).status == .ok)
    }
  }

  @Test func conflictsAndConcurrentRace() async throws {
    let clock = TestBackend()
    let alice = try await identity(["alice"], clock: clock)
    let bob = try await identity(["alice"], clock: clock)
    try await withHost(clock: clock) { (client: any TestClientProtocol) async throws in
      async let first = put(client, alice.profile)
      async let second = put(client, bob.profile)
      let responses = try await [first, second]
      #expect(responses.filter { $0.status == .ok }.count == 1)
      #expect(responses.filter { $0.status == .conflict }.count == 1)
      let loser = responses[0].status == .ok ? bob : alice
      let retry = try await put(client, loser.profile)
      #expect(try code(retry) == "name-taken")
    }
  }

  @Test func limitsAndNoOp() async throws {
    let clock = TestBackend()
    let alice = try await identity(["alice"], clock: clock)
    let revision2 = try await alice.updating(fields(["alice", "bob"]))
    let tooMany = try await alice.updating(fields(["alice", "bob", "charlie"]))
    try await withHost(config(claims: 2, updates: 1), clock: clock) { (client: any TestClientProtocol) async throws in
      #expect(try code(await put(client, tooMany)) == "too-many-claims")
      #expect(try await put(client, alice.profile).status == .ok)
      #expect(try await put(client, alice.profile).status == .ok)
      let limited = try await put(client, revision2)
      #expect(limited.status == .tooManyRequests)
      #expect(limited.headers[.retryAfter] == "3600")
      #expect(try problem(limited).retryAfter == 3600)
      #expect(limited.headers[.accessControlExposeHeaders] == "Retry-After")
      #expect(try await client.execute(uri: Self.path, method: .get, headers: [HTTPField.Name("x-test-authority")!: "bob.id.example"]).status == .notFound)
    }
  }

  @Test func revisionsAndReleaseAllFloor() async throws {
    let clock = TestBackend()
    var alice = try await identity(["alice", "bob"], clock: clock)
    let first = alice.profile
    let release = try await alice.update(fields([]))
    let reacquire = try await alice.update(fields(["alice"]))
    let bob = try await identity(["bob"], clock: clock)
    try await withHost(clock: clock) { (client: any TestClientProtocol) async throws in
      #expect(try await put(client, first).status == .ok)
      #expect(try await put(client, release).status == .ok)
      #expect(try code(await put(client, first)) == "stale-revision")
      #expect(try await client.execute(uri: Self.path, method: .get, headers: [HTTPField.Name("x-test-authority")!: "alice.id.example"]).status == .notFound)
      #expect(try await put(client, bob.profile, host: "bob.id.example").status == .ok)
      #expect(try await put(client, reacquire).status == .ok)
    }
  }

  @Test func generationCannotRollBack() async throws {
    let clock = TestBackend()
    var alice = try await identity(["alice"], clock: clock)
    let extra = try await DevicePrivateKey.generate(.ed25519, using: clock)
    try await alice.add(extra.publicKey)
    var oldGeneration = alice
    let current = try await alice.remove(extra.publicKey.id)
    try await oldGeneration.renew()
    let rollback = try await oldGeneration.renew()
    try await withHost(clock: clock) { (client: any TestClientProtocol) async throws in
      #expect(try await put(client, current).status == .ok)
      #expect(try code(await put(client, rollback)) == "stale-revision")
    }
  }

  @Test func labelAndHostValidation() async throws {
    let clock = TestBackend()
    let alice = try await identity(["alice"], clock: clock)
    let deeper = try await identity(["alice", "a.b.id.example"], clock: clock)
    let invalid = try await identity(["alice", "bad-name"], clock: clock)
    try await withHost(config(pattern: "[a-z]+"), clock: clock) { (client: any TestClientProtocol) async throws in
      #expect(try code(await put(client, alice.profile, host: "bob.id.example")) == "host-not-listed")
      let deeperProblem = try problem(await put(client, deeper.profile))
      #expect(deeperProblem.code == .invalidLabel)
      #expect(deeperProblem.labels.isEmpty)
      let invalidProblem = try problem(await put(client, invalid.profile))
      #expect(invalidProblem.code == .invalidLabel)
      #expect(invalidProblem.labels.map(\.label) == ["bad-name"])
      let malformed = try await client.execute(uri: Self.path, method: .put, headers: [HTTPField.Name("x-test-authority")!: "alice.id.example"], body: .init(string: "bad"))
      #expect(try code(malformed) == "invalid-profile")
      var tampered = alice.profile.encoding
      tampered[tampered.count - 1] ^= 1
      let badSignature = try await client.execute(uri: Self.path, method: .put, headers: [HTTPField.Name("x-test-authority")!: "alice.id.example"], body: .init(bytes: tampered))
      #expect(try code(badSignature) == "invalid-profile")
      let large = try await client.execute(uri: Self.path, method: .put, headers: [HTTPField.Name("x-test-authority")!: "alice.id.example"], body: .init(bytes: Array(repeating: UInt8(0), count: CBOR.maximumBytes + 1)))
      #expect(large.status == .contentTooLarge)
    }
  }

  @Test func proofRequiredHeldNamesAndDroppedNames() async throws {
    let clock = TestBackend()
    var alice = try await identity(["alice", "bob"], clock: clock)
    let first = alice.profile
    let dropped = try await alice.update(fields(["alice"]))
    let bob = try await identity(["bob"], clock: clock)
    let c = try config(bits: 4)
    var nonces: [String: [UInt8]] = [:]
    for label in ["alice", "bob"] { nonces[label] = try await solve(c, label, alice.id) }
    let proof = try hostingProofHeader(nonces)
    let insufficientNonce = try #require((0...255).map { [UInt8($0)] }.first {
      !c.proofOfWork.isValid(nonce: $0, domain: c.domain, label: "alice", identityID: alice.id)
    })
    let insufficientProof = "alice=" + Base64URL.encode(insufficientNonce) + ", " + proof.split(separator: ",")[1]
    let bobProof = try hostingProofHeader(["bob": await solve(c, "bob", bob.id)])
    try await withHost(c, clock: clock) { (client: any TestClientProtocol) async throws in
      let missing = try await put(client, first)
      #expect(try code(missing) == "proof-required")
      #expect(try problem(missing).labels.map(\.requiredBits) == [4, 4])
      #expect(try code(await put(client, first, proof: "@=AA")) == "proof-required")
      #expect(try code(await put(client, first, proof: "alice=!, bob=AA")) == "proof-required")
      #expect(try code(await put(client, first, proof: String(proof.split(separator: ",")[0]))) == "proof-required")
      #expect(try code(await put(client, first, proof: insufficientProof)) == "proof-required")
      #expect(try await put(client, first, proof: proof).status == .ok)
      #expect(try await put(client, dropped).status == .ok)
      #expect(try await put(client, bob.profile, host: "bob.id.example", proof: bobProof).status == .ok)
    }
  }

  @Test func expiryGraceAndPersistence() async throws {
    let clock = TestBackend()
    let alice = try await identity(["alice"], clock: clock, lifetime: 10)
    let db = FileManager.default.temporaryDirectory.appendingPathComponent("hosting-test-\(UUID()).sqlite").path
    defer { for suffix in ["", "-wal", "-shm"] { try? FileManager.default.removeItem(atPath: db + suffix) } }
    try await withHost(clock: clock, path: db) { (client: any TestClientProtocol) async throws in
      #expect(try await put(client, alice.profile).status == .ok)
    }
    clock.advance(by: 110)
    let bob = try await identity(["alice"], clock: clock)
    try await withHost(clock: clock, path: db) { (client: any TestClientProtocol) async throws in
      #expect(try await client.execute(uri: Self.path, method: .get, headers: [HTTPField.Name("x-test-authority")!: "alice.id.example"]).status == .ok)
      for path in [Self.path, Self.legacy] {
        let head = try await client.execute(uri: path, method: .head,
          headers: [HTTPField.Name("x-test-authority")!: "alice.id.example"])
        #expect(head.status == .ok)
        #expect(head.body.readableBytes == 0)
      }
      #expect(try code(await put(client, bob.profile)) == "name-taken")
      #expect(try code(await put(client, alice.profile)) == "invalid-profile")
      clock.advance(by: 1)
      #expect(try await client.execute(uri: Self.path, method: .get, headers: [HTTPField.Name("x-test-authority")!: "alice.id.example"]).status == .notFound)
      for path in [Self.path, Self.legacy] {
        #expect(try await client.execute(uri: path, method: .head,
          headers: [HTTPField.Name("x-test-authority")!: "alice.id.example"]).status == .notFound)
      }
      #expect(try await put(client, bob.profile).status == .ok)
    }
  }

  @Test func routingPolicyNamesAndCORS() async throws {
    let clock = TestBackend()
    let alice = try await identity(["alice"], clock: clock)
    try await withHost(clock: clock) { (client: any TestClientProtocol) async throws in
      #expect(try await client.execute(uri: "/oauth", method: .get, headers: [HTTPField.Name("x-test-authority")!: "dc.example"]).status == .accepted)
      for host in ["alice.id.example", "a.b.id.example", "id.example"] {
        #expect(try await client.execute(uri: "/oauth", method: .get, headers: [HTTPField.Name("x-test-authority")!: host]).status == .notFound)
      }
      #expect(try await client.execute(uri: Self.path, method: .get, headers: [HTTPField.Name("x-test-authority")!: "id.example"]).status == .notFound)
      #expect(try await client.execute(uri: Self.policy, method: .get, headers: [HTTPField.Name("x-test-authority")!: "a.b.id.example"]).status == .notFound)
      let policy = try await client.execute(uri: Self.policy, method: .get, headers: [HTTPField.Name("x-test-authority")!: "id.example"])
      #expect(policy.status == .ok)
      let parsed = try HostingPolicy(json: Array(policy.body.readableBytesView), domain: DomainName("id.example"))
      #expect(!parsed.apex)
      #expect(parsed.requiredBits(for: "alice") == 0)
      #expect(parsed.names?.maxClaimsPerIdentity == 3)
      for (label, expected) in [("alice", "available"), ("ALICE", "available"), ("bad.name", "invalid")] {
        let name = try await client.execute(uri: Self.policy + "/names/" + label, method: .get, headers: [HTTPField.Name("x-test-authority")!: "id.example"])
        #expect(String(buffer: name.body).contains(expected))
      }
      #expect(try await put(client, alice.profile).status == .ok)
      let claimed = try await client.execute(uri: Self.policy + "/names/ALICE", method: .get, headers: [HTTPField.Name("x-test-authority")!: "id.example"])
      #expect(String(buffer: claimed.body).contains("claimed"))
      for path in [Self.path, Self.legacy] {
        let options = try await client.execute(uri: path, method: .options, headers: [HTTPField.Name("x-test-authority")!: "alice.id.example"])
        #expect(options.status == .noContent)
        #expect(options.headers[.accessControlAllowMethods] == "GET, HEAD, PUT")
        #expect(options.headers[.accessControlAllowHeaders] == "Content-Type, Diem-Hosting-Proof")
        #expect(options.headers[.accessControlMaxAge] == "600")
        #expect(options.headers[.accessControlAllowOrigin] == "*")
      }
    }
  }
  @Test func rollingRateWindowAndAtomicConflicts() async throws {
    let clock = TestBackend()
    let alice = try await identity(["alice"], clock: clock, lifetime: 7200)
    let bob = try await identity(["bob", "carol"], clock: clock, lifetime: 7200)
    let expanded = try await alice.updating(fields(["alice", "bob", "carol"]))
    let renewal = try await alice.renewing()
    try await withHost(config(updates: 1), clock: clock) { (client: any TestClientProtocol) async throws in
      #expect(try await put(client, alice.profile).status == .ok)
      #expect(try await put(client, bob.profile, host: "bob.id.example").status == .ok)
      let conflict = try await put(client, expanded)
      #expect(try problem(conflict).labels.map(\.label) == ["bob", "carol"])
      clock.advance(by: 3599)
      #expect(try await put(client, alice.profile).status == .ok)
      let rate = try await put(client, renewal)
      #expect(rate.headers[.retryAfter] == "1")
      clock.advance(by: 1)
      #expect(try await put(client, renewal).status == .ok)
      let fetched = try await client.execute(uri: Self.path, method: .get,
        headers: [HTTPField.Name("x-test-authority")!: "alice.id.example"])
      #expect(Array(fetched.body.readableBytesView) == renewal.encoding)
    }
  }

  @Test func sameRevisionDifferentContentAndUnauthorizedRelease() async throws {
    let clock = TestBackend()
    let alice = try await identity(["alice"], clock: clock)
    let first = try await alice.updating(fields(["alice", "bob"]))
    let sameRevision = try await alice.updating(fields(["alice"]))
    let outsider = try await identity([], clock: clock)
    let release = try await outsider.renewing()
    try await withHost(clock: clock) { (client: any TestClientProtocol) async throws in
      #expect(try await put(client, first).status == .ok)
      #expect(try code(await put(client, sameRevision)) == "stale-revision")
      #expect(try code(await put(client, release)) == "host-not-listed")
      #expect(try await client.execute(uri: Self.path, method: .get,
        headers: [HTTPField.Name("x-test-authority")!: "bob.id.example"]).status == .ok)
    }
  }

  @Test func reclaimsSpecificNameBeyondSweepBatch() async throws {
    let clock = TestBackend()
    try await withHost(config(grace: 0), clock: clock) { (client: any TestClientProtocol) async throws in
      for number in 0..<20 {
        let label = "name\(number)"
        let holder = try await identity([label], clock: clock, lifetime: UInt64(number + 1))
        #expect(try await put(client, holder.profile, host: label + ".id.example").status == .ok)
      }
      clock.advance(by: 21)
      let replacement = try await identity(["name19"], clock: clock)
      #expect(try await put(client, replacement.profile, host: "name19.id.example").status == .ok)
    }
  }

  @Test func unavailableDatabaseIsBusy() async throws {
    let clock = TestBackend()
    let holder = try await identity(["alice"], clock: clock)
    let hosting = try await DiemProfileHosting(configuration: config(), databasePath: ":memory:", now: { clock.now })
    await hosting.shutdown()
    await hosting.shutdown()
    let router = Router()
    router.middlewares.add(TestAuthorityMiddleware())
    router.middlewares.add(hosting.middleware())
    try await Application(router: router).test(.router) { client in
      let response = try await put(client, holder.profile)
      #expect(response.status == .serviceUnavailable)
      #expect(try code(response) == "busy")
      #expect(response.headers[.cacheControl] == "no-store")
    }
  }
}

private struct Published: Decodable {
  let identity: String
  let revision: UInt64
  let domains: [String]
}

// Hummingbird's in-process client fixes authority to localhost.
private struct TestAuthorityMiddleware: RouterMiddleware {
  func handle(_ request: Request, context: BasicRequestContext,
    next: (Request, BasicRequestContext) async throws -> Response
  ) async throws -> Response {
    var head = request.head
    head.authority = request.headers[HTTPField.Name("x-test-authority")!]
    return try await next(Request(head: head, body: request.body), context)
  }
}

@Suite(.enabled(if: ProcessInfo.processInfo.environment["DIEM_PERF"] != nil))
struct HostingReadPerfTests {
  @Test func repeatedReads() async throws {
    let fixture = ProfileHostingTests()
    let clock = TestBackend()
    let identity = try await fixture.identity(["alice"], clock: clock)
    try await fixture.withHost(clock: clock) { (client: any TestClientProtocol) async throws in
      #expect(try await fixture.put(client, identity.profile).status == .ok)
      for (path, method, host) in [
        (ProfileHostingTests.path, HTTPRequest.Method.get, "alice.id.example"),
        (ProfileHostingTests.path, .head, "alice.id.example"),
        (ProfileHostingTests.policy + "/names/alice", .get, "id.example")
      ] {
        let start = ContinuousClock.now
        for _ in 0..<500 {
          #expect(try await client.execute(uri: path, method: method,
            headers: [HTTPField.Name("x-test-authority")!: host]).status == .ok)
        }
        print("PERF hosting \(method) \(path) iterations=500 profileBytes=\(identity.profile.encoding.count) elapsed=\(ContinuousClock.now - start)")
      }
    }
  }
}

extension ProfileHostingTests {
  @Test func existenceAndBytesShareExpiryBoundaries() async throws {
    let clock = TestBackend()
    let alice = try await identity(["alice"], clock: clock, lifetime: 10)
    let db = try await HostingDatabase(path: ":memory:")
    defer { await db.shutdown() }
    _ = try await db.publish(alice.profile, label: "alice", proof: nil,
      configuration: config(), now: clock.now)
    for time in [UInt64(0), clock.now, clock.now + 110, clock.now + 111, UInt64.max] {
      for label in ["alice", "missing"] {
        let bytes = try await db.profile(label: label, now: time, grace: 100)
        #expect(try await db.hasProfile(label: label, now: time, grace: 100) == (bytes != nil))
        if let bytes { #expect(Array(bytes) == alice.profile.encoding) }
      }
    }
    await db.shutdown()
    await #expect(throws: (any Error).self) {
      _ = try await db.hasProfile(label: "alice", now: clock.now, grace: 100)
    }
  }
}

extension HostingReadPerfTests {
  @Test func largeProfileProjection() async throws {
    let clock = TestBackend()
    let identity = try await TestIdentity(
      ProfileFields(domains: [try DomainName("alice.id.example")],
        application: [16: .bytes([UInt8](repeating: 42, count: 100_000))]),
      identityKey: .generate(.ed25519, using: clock),
      deviceKey: .generate(.ed25519, using: clock), using: clock)
    let db = try await HostingDatabase(path: ":memory:")
    defer { await db.shutdown() }
    _ = try await db.publish(identity.profile, label: "alice", proof: nil,
      configuration: ProfileHostingTests().config(), now: clock.now)
    for existence in [false, true] {
      let start = ContinuousClock.now
      for _ in 0..<1000 {
        if existence {
          #expect(try await db.hasProfile(label: "alice", now: clock.now, grace: 100))
        } else {
          #expect(try await db.profile(label: "alice", now: clock.now, grace: 100) != nil)
        }
      }
      print("PERF hosting projection existence=\(existence) iterations=1000 profileBytes=\(identity.profile.encoding.count) elapsed=\(ContinuousClock.now - start)")
    }
  }
}
#endif
