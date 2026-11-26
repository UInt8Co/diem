import Diem
import DiemTesting
import Testing

/// A challenge the test application signs: a nonce that expires.
private struct Challenge: Statement {
  static let application = ApplicationID.test
  let nonce: [UInt8]
  let expiresAt: UInt64

  init(nonce: [UInt8], expiresAt: UInt64) {
    self.nonce = nonce
    self.expiresAt = expiresAt
  }

  init(value: CBOR) throws {
    let a = try value.recordValue(requiredKeys: 0..<2)
    try self.init(nonce: a[0]!.bytesValue(count: 4), expiresAt: a[1]!.unsignedValue())
  }

  var value: CBOR { CBOR.record([0: .bytes(nonce), 1: .unsigned(expiresAt)]) }
}

@Suite struct StatementProofTests {
  let backend = TestBackend()

  @Test func statementsProveUnderTheirApplication() async throws {
    let identity = try await TestIdentity(.data([1]), using: backend)
    let challenge = Challenge(nonce: [1, 2, 3, 4], expiresAt: backend.now + 60)
    let proof = try await identity.prove(challenge)
    #expect(proof.application == .test && proof.value == challenge.value)
    let decoded = try StatementProof<Challenge>(encoding: proof.encoding)
    #expect(decoded.statement == challenge)
    try await decoded.verify(against: identity.profile, using: backend)
  }

  @Test func proofsBindTheirApplication() async throws {
    let identity = try await TestIdentity(.data([1]), using: backend)
    let challenge = Challenge(nonce: [1, 2, 3, 4], expiresAt: backend.now + 60)
    // The same value signed for another application is not this application's statement.
    let foreign = try await identity.prove(challenge.value, for: ApplicationID("org.example.other"))
    #expect(throws: DiemError.invalidEncoding) {
      try StatementProof<Challenge>(encoding: foreign.encoding)
    }
  }

  @Test func proofRecordsCarryExactlyOneApplication() async throws {
    let identity = try await TestIdentity(.data([1]), using: backend)
    let device = identity.deviceKey.publicKey.id
    func signed(_ applications: [ApplicationID: CBOR], extra: [UInt64: CBOR] = [:]) async throws
      -> [UInt8]
    {
      var fields: [UInt64: CBOR] = [0: .text("Diem/proof"), 1: .unsigned(4),
        2: .bytes(identity.id.bytes), 3: .bytes(device.bytes)]
      fields.merge(extra) { $1 }
      let message = CBOR.record(fields, applications: applications).encoded
      return try await SignedMessage(signing: message, with: backend.makePrivateKey(for: .device))
        .encoding
    }
    let other = try ApplicationID("org.example.other")
    for applications in [[:], [.test: .null, other: .null]] as [[ApplicationID: CBOR]] {
      let encoding = try await signed(applications)
      #expect(throws: DiemError.invalidEncoding) { try ProofRecord(encoding: encoding) }
    }
    // Later Diem fields are accepted.
    let future = try ProofRecord(encoding: await signed([.test: .null], extra: [4: .text("future")]))
    #expect(future.application == .test)
  }

  @Test func liveChallengesExpireWithinTheirWindow() async throws {
    let identity = try await TestIdentity(.data([1]), using: backend)
    let now = backend.now
    try identity.requireLive(until: now + 120, window: 120)
    for expiresAt in [now, now - 1, now + 121] {
      #expect(throws: DiemError.expired) { try identity.requireLive(until: expiresAt, window: 120) }
    }
  }
}
