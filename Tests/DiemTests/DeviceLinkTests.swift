import Diem
import DiemTesting
import Foundation
import Testing

/// Contract tests use public records and independently assembled hostile plaintexts.
@Suite struct DeviceLinkTests {
  let backend = TestBackend()
  let domain = try! DomainName("link.example")
  let secret = [UInt8](0..<16)
  let seed = try! IdentitySeed(entropy: Array(repeating: 8, count: 32))
  let accept: (ProfileRecord, DeviceLinkGrant) throws -> Void = { _, _ in }

  func identity(seed: IdentitySeed? = nil, lifetime: UInt64 = ProfileRecord.defaultLifetime)
    async throws -> TestIdentity
  {
    try await TestIdentity(ProfileFields(domains: [domain], applications: [.test: .bytes([1])]),
      identityKey: (seed ?? self.seed).identityKey(.ed25519, using: backend),
      deviceKey: .generate(.ed25519, using: backend), profileLifetime: lifetime, using: backend)
  }

  func request(label: String = "Desktop", verifies: [PublicKey.Algorithm] = [.ed25519])
    async throws -> (DeviceLinkRequest, EncryptionPrivateKey)
  {
    let recipient = try await backend.makeEncryptionKey(.p256)
    return (try await DeviceLinkRequest(device: DevicePrivateKey.generate(.ed25519, using: backend).publicKey,
      recipient: recipient.publicKey, label: label, verifies: verifies), recipient)
  }

  func code(_ request: DeviceLinkRequest) throws -> DeviceLinkCode {
    try DeviceLinkCode(requestDigest: request.digest, secret: secret)
  }

  func replacing(_ bytes: [UInt8], _ key: UInt64, _ value: CBOR?) throws -> [UInt8] {
    var record = try CBOR(decoding: bytes).recordValue(requiredKeys: 0..<0)
    record[key] = value
    return record.value.encoded
  }

  func context(_ code: DeviceLinkCode) -> [UInt8] {
    CBOR.record([0: .text("Diem/device-link-context"), 1: .unsigned(1),
      2: .bytes(code.requestDigest.bytes), 3: .bytes(code.secret)]).encoded
  }

  func plaintext(_ profile: ProfileRecord, domain: DomainName? = nil, seed: SealedIdentitySeed? = nil,
    applications: [ApplicationID: CBOR] = [:]
  ) -> [UInt8] {
    var fields: [UInt64: CBOR] = [0: .text("Diem/device-link-grant"), 1: .unsigned(1),
      2: .bytes(profile.encoding), 3: .text((domain ?? self.domain).name)]
    if let seed { fields[4] = .bytes(seed.encoding) }
    return CBOR.record(fields, applications: applications).encoded
  }

  // Bypasses the grant and seal constructors: open must defend itself.
  func rawResponse(_ plaintext: [UInt8], request: DeviceLinkRequest, code: DeviceLinkCode,
    recipient: EncryptionPublicKey? = nil) async throws -> [UInt8]
  {
    let box = try await backend.seal(plaintext, to: recipient ?? request.recipient, context: context(code))
    return CBOR.record([0: .bytes(box.encapsulatedKey), 1: .bytes(box.ciphertext)]).encoded
  }

  func open(_ response: [UInt8], _ recipient: EncryptionPrivateKey, _ request: DeviceLinkRequest,
    code: DeviceLinkCode, at time: UInt64? = nil,
    accept: (ProfileRecord, DeviceLinkGrant) throws -> Void = { _, _ in }
  ) async throws -> DeviceLinkResponse.Opened<ProfileRecord> {
    try await DeviceLinkResponse.open(response, as: ProfileRecord.self, recipientKey: recipient,
      request: request, code: code, at: time, using: backend, accept: accept)
  }

  @Test func fixedCanonicalEncodingVectors() async throws {
    func hex(_ text: String) -> [UInt8] {
      let characters = Array(text)
      return stride(from: 0, to: characters.count, by: 2).map {
        UInt8(String(characters[$0...($0 + 1)]), radix: 16)!
      }
    }
    // Ed25519 seed 07 x 32 and P-256 scalar 1; assembled independently from the key vectors.
    let expectedRequest = hex("a60078184469656d2f6465766963652d6c696e6b2d726571756573740101025834a500684469656d2f6b6579010302020301045820ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c035855a500684469656d2f6b6579010302030304045841046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5046f496e7465726f70206465736b746f70058101")
    let expectedCode = hex("a400754469656d2f6465766963652d6c696e6b2d636f64650101025820796dc6099c904f1e12bb72e781bf2d4431310550c957512096fad7c98f65fc910350000102030405060708090a0b0c0d0e0f")
    let expectedContext = hex("a40078184469656d2f6465766963652d6c696e6b2d636f6e746578740101025820796dc6099c904f1e12bb72e781bf2d4431310550c957512096fad7c98f65fc910350000102030405060708090a0b0c0d0e0f")
    let device = try DevicePrivateKey(await backend.makePrivateKey(.ed25519, for: .device,
      restoring: Array(repeating: 7, count: 32)))
    let recipient = try await backend.makeEncryptionKey(.p256, restoring: Array(repeating: 0, count: 31) + [1])
    let request = try DeviceLinkRequest(device: device.publicKey, recipient: recipient.publicKey,
      label: "Interop desktop", verifies: [.ed25519])
    let code = try code(request)
    #expect(request.encoding == expectedRequest)
    #expect(request.digest.description == "796dc6099c904f1e12bb72e781bf2d4431310550c957512096fad7c98f65fc91")
    #expect(code.encoding == expectedCode)
    #expect(code.parameter == "pAB1RGllbS9kZXZpY2UtbGluay1jb2RlAQECWCB5bcYJnJBPHhK7cueBvy1EMTEFUMlXUSCW-tfJj2X8kQNQAAECAwQFBgcICQoLDA0ODw")
    #expect(DeviceLinkContext(code: code).encoding == expectedContext)
    #expect(try DeviceLinkRequest(encoding: expectedRequest).encoding == expectedRequest)
    #expect(try DeviceLinkCode(encoding: expectedCode).encoding == expectedCode)
    #expect(try DeviceLinkContext(encoding: expectedContext).encoding == expectedContext)

    // A grant of the committed Ed25519 profile vector, with one application field.
    struct Fixture: Decodable { struct Vector: Decodable { let algorithm: UInt64; let profile: String }; let vectors: [Vector] }
    let url = URL(filePath: #filePath).deletingLastPathComponent().appending(path: "../Vectors/diem-v5.json")
    let fixture = try JSONDecoder().decode(Fixture.self, from: Data(contentsOf: url))
    let profile = hex(try #require(fixture.vectors.first { $0.algorithm == 1 }).profile)
    let grant = try DeviceLinkGrant(profile: profile, domain: DomainName("vectors.example"),
      applications: [.test: .bytes([1])])
    let expectedGrant = hex("a50076") + Array("Diem/device-link-grant".utf8) + hex("01010259")
      + [UInt8(profile.count >> 8), UInt8(profile.count & 0xff)] + profile
      + hex("036f") + Array("vectors.example".utf8) + hex("70") + Array("org.example.test".utf8) + hex("4101")
    #expect(grant.encoding == expectedGrant)
    #expect(try DeviceLinkGrant(encoding: expectedGrant) == grant)
  }

  @Test func recordsBoundTheirFieldsAndRetainUnknownOnes() async throws {
    let (request, _) = try await request()
    let code = try code(request)
    let alice = try await identity()
    let encodings = [request.encoding, code.encoding, context(code), plaintext(alice.profile)]
    let decoders: [([UInt8]) throws -> [UInt8]] = [
      { try DeviceLinkRequest(encoding: $0).encoding }, { try DeviceLinkCode(encoding: $0).encoding },
      { try DeviceLinkContext(encoding: $0).encoding }, { try DeviceLinkGrant(encoding: $0).encoding },
    ]
    for (bytes, decode) in zip(encodings, decoders) {
      let extended = try replacing(bytes, 99, .text("future"))
      #expect(try decode(extended) == extended)
      for (key, value): (UInt64, CBOR?) in [(0, .unsigned(17)), (1, .unsigned(2)), (0, nil), (2, nil), (3, nil)] {
        #expect(throws: DiemError.invalidDeviceLink) { try decode(replacing(bytes, key, value)) }
      }
    }
    for label in ["", String(repeating: "é", count: 33)] {
      await #expect(throws: DiemError.invalidDeviceLink) { try await self.request(label: label) }
    }
    for algorithms: [PublicKey.Algorithm] in [[], [.ed25519, .ed25519]] {
      await #expect(throws: DiemError.invalidDeviceLink) { try await self.request(verifies: algorithms) }
    }
    let x25519 = try await backend.makeEncryptionKey(.x25519)
    #expect(throws: DiemError.unsupportedAlgorithm) {
      try DeviceLinkRequest(device: request.device, recipient: x25519.publicKey, label: "x", verifies: [.ed25519])
    }
    // Unknown fields count towards the request bound and its digest.
    let overhead = try replacing(request.encoding, 99, .bytes(Array(repeating: 0, count: 4000))).count - 4000
    _ = try DeviceLinkRequest(encoding: replacing(request.encoding, 99, .bytes(Array(repeating: 0, count: 4096 - overhead))))
    #expect(throws: DiemError.invalidDeviceLink) {
      try DeviceLinkRequest(encoding: replacing(request.encoding, 99, .bytes(Array(repeating: 0, count: 4097 - overhead))))
    }
    #expect(!code.matches(try replacing(request.encoding, 99, .unsigned(1))))
  }

  @Test func codeParameterIsStrictBase64URL() async throws {
    let (request, _) = try await request()
    let code = try code(request)
    #expect(try DeviceLinkCode(parameter: code.parameter) == code)
    #expect(code.matches(request.encoding))
    let alphabet = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")
    let last = alphabet.firstIndex(of: code.parameter.last!)!
    let nonzeroPadBits = String(code.parameter.dropLast()) + String(alphabet[last ^ 1])
    for malformed in ["", code.parameter + "=", " " + code.parameter, "+" + code.parameter, nonzeroPadBits,
      String(repeating: "A", count: 5463)] {
      #expect(throws: DiemError.invalidDeviceLink) { try DeviceLinkCode(parameter: malformed) }
    }
    for count in [15, 17] {
      #expect(throws: DiemError.invalidDeviceLink) {
        try DeviceLinkCode(requestDigest: request.digest, secret: Array(repeating: 0, count: count))
      }
    }
  }

  @Test func grantsRoundTripWithAndWithoutCustody() async throws {
    let (request, recipient) = try await request()
    let code = try code(request)
    var alice = try await identity()
    try await alice.add(request.device)
    let other = try ApplicationID("org.example.other")
    for transfer in [false, true] {
      let sealed = try await transfer ? seed.sealed(to: request.recipient, identity: alice.profile.identityKey, using: backend) : nil
      let applications: [ApplicationID: CBOR] = transfer ? [other: .bytes([0, 255])] : [:]
      let grant = try DeviceLinkGrant(profile: alice.profile, domain: domain, seed: sealed, applications: applications)
      #expect(grant.encoding == plaintext(alice.profile, seed: sealed, applications: applications))
      let response = try await DeviceLinkResponse.seal(grant, as: ProfileRecord.self, for: request,
        code: code, using: backend, accept: accept)
      var accepted: (ProfileRecord, DeviceLinkGrant)?
      let opened = try await open(response, recipient, request, code: code) { accepted = ($0, $1) }
      #expect(opened.profile == alice.profile && accepted?.0 == alice.profile && accepted?.1 == grant)
      #expect(opened.grant.profile == alice.profile.encoding)
      #expect(opened.grant.applications == applications)
      #expect(opened.seed?.entropy == (transfer ? seed.entropy : nil))
      // An independently built context also opens.
      _ = try await open(rawResponse(grant.encoding, request: request, code: code), recipient, request, code: code)
    }
  }

  @Test func openingRejectsWrongBindingsAndTampering() async throws {
    let (request, recipient) = try await request()
    let code = try code(request)
    var alice = try await identity()
    try await alice.add(request.device)
    let grant = plaintext(alice.profile)
    let response = try await rawResponse(grant, request: request, code: code)
    var tampered = response
    tampered[tampered.count - 1] ^= 1
    let other = try await backend.makeEncryptionKey(.p256)
    let wrongSecret = try DeviceLinkCode(requestDigest: request.digest, secret: Array(repeating: 99, count: 16))
    let wrongDigest = try DeviceLinkCode(requestDigest: Digest(hashing: [1]), secret: secret)
    await #expect(throws: (any Error).self) { try await open(response, recipient, request, code: wrongSecret) }
    await #expect(throws: DiemError.invalidDeviceLink) { try await open(response, recipient, request, code: wrongDigest) }
    await #expect(throws: (any Error).self) { try await open(tampered, recipient, request, code: code) }
    await #expect(throws: DiemError.identityMismatch) { try await open(response, other, request, code: code) }
    let toOther = try await rawResponse(grant, request: request, code: code, recipient: other.publicKey)
    await #expect(throws: (any Error).self) { try await open(toOther, recipient, request, code: code) }
    // The application's check runs on the verified profile and grant and can refuse it.
    await #expect(throws: DiemError.deviceNotListed) {
      try await open(response, recipient, request, code: code) { _, _ in throw DiemError.deviceNotListed }
    }
    await #expect(throws: DiemError.invalidDeviceLink) {
      try await DeviceLinkResponse.seal(DeviceLinkGrant(encoding: grant), as: ProfileRecord.self,
        for: request, code: wrongDigest, using: backend, accept: accept)
    }
  }

  @Test func acceptanceSeesTheGrantBeforeTheSeedOpens() async throws {
    final class Opens: @unchecked Sendable { var count = 0 }
    let (request, recipient) = try await request()
    let opens = Opens()
    let counting = EncryptionPrivateKey(publicKey: recipient.publicKey, protection: recipient.protection,
      rawRepresentation: nil) { box, context in
        opens.count += 1
        return try await recipient.open(box, context: context)
      }
    let code = try code(request)
    var alice = try await identity()
    try await alice.add(request.device)
    let sealed = try await seed.sealed(to: request.recipient, identity: alice.profile.identityKey, using: backend)
    let grant = try DeviceLinkGrant(profile: alice.profile, domain: domain, seed: sealed,
      applications: [.test: .bytes([7])])
    let response = try await DeviceLinkResponse.seal(grant, as: ProfileRecord.self, for: request,
      code: code, using: backend) { _, sealing in
        #expect(sealing == grant)
      }
    // A refusal based on the grant's fields leaves the sealed seed unopened.
    await #expect(throws: DiemError.invalidDeviceLink) {
      try await open(response, counting, request, code: code) { _, grant in
        #expect(grant.seed == sealed && grant.applications[.test] == .bytes([7]))
        throw DiemError.invalidDeviceLink
      }
    }
    #expect(opens.count == 1)
    _ = try await open(response, counting, request, code: code)
    #expect(opens.count == 3)
  }

  @Test func openingRejectsGrantsThatDoNotAuthorizeTheDevice() async throws {
    let (request, recipient) = try await request()
    let code = try code(request)
    var alice = try await identity()
    let beforeAdding = alice.profile
    try await alice.add(request.device)
    let certified = alice.profile
    let removed = try await alice.remove(request.device.id)
    // A relay cannot resurrect an old certificate by appending it to the new generation.
    var envelope = try CBOR(decoding: removed.encoding).recordValue(requiredKeys: 0..<5)
    let stale = try #require(certified.devices.first { $0.device == request.device })
    envelope[3] = .array(removed.devices.map { .bytes($0.encoding) } + [.bytes(stale.encoding)])
    let staleCertificate = try replacing(plaintext(removed), 2, .bytes(envelope.value.encoded))
    var shortLived = try await identity(lifetime: 60)
    try await shortLived.add(request.device)
    let foreignSeed = try IdentitySeed.generate(using: backend)
    let stranger = try await identity(seed: foreignSeed)
    let foreignKey = try await foreignSeed.sealed(to: request.recipient, identity: stranger.profile.identityKey, using: backend)
    let otherRecipient = try await backend.makeEncryptionKey(.p256)
    let misaddressed = try await seed.sealed(to: otherRecipient.publicKey, identity: certified.identityKey, using: backend)
    let cases: [(String, [UInt8], UInt64)] = [
      ("before adding", plaintext(beforeAdding), backend.now),
      ("removed device", plaintext(removed), backend.now),
      ("old certificate in new generation", staleCertificate, backend.now),
      ("unlisted domain", plaintext(certified, domain: try DomainName("evil.example")), backend.now),
      ("expired profile", plaintext(shortLived.profile), shortLived.profile.validity.expiresAt),
      ("not yet valid", plaintext(certified), certified.validity.notBefore - 1),
      ("seed of another identity", plaintext(certified, seed: foreignKey), backend.now),
      ("seed sealed to another recipient", plaintext(certified, seed: misaddressed), backend.now),
    ]
    for (name, plain, time) in cases {
      let response = try await rawResponse(plain, request: request, code: code)
      await #expect(throws: (any Error).self, Comment(rawValue: name)) {
        try await open(response, recipient, request, code: code, at: time)
      }
    }
  }

  @Test func responseSizeBoundAndAlgorithmCompatibility() async throws {
    let (request, recipient) = try await request()
    let code = try code(request)
    var alice = try await identity()
    try await alice.add(request.device)
    let plain = plaintext(alice.profile)
    let overhead = try await rawResponse(replacing(plain, 99, .bytes(Array(repeating: 0, count: 60000))),
      request: request, code: code).count - 60000
    for size in [65536, 65537] {
      let padded = try replacing(plain, 99, .bytes(Array(repeating: 0, count: size - overhead)))
      let response = try await rawResponse(padded, request: request, code: code)
      #expect(response.count == size)
      if size == 65536 {
        _ = try await open(response, recipient, request, code: code)
      } else {
        await #expect(throws: DiemError.invalidDeviceLink) { try await open(response, recipient, request, code: code) }
      }
    }
    let edIdentity = try await IdentityPrivateKey.generate(.ed25519, using: backend)
    let p256Device = try await DevicePrivateKey.generate(.p256, using: backend)
    let edDevice = try await DevicePrivateKey.generate(.ed25519, using: backend)
    try request.requireCompatible(identityKey: edIdentity.publicKey, device: edDevice.publicKey)
    #expect(throws: DiemError.unsupportedAlgorithm) {
      try request.requireCompatible(identityKey: edIdentity.publicKey, device: p256Device.publicKey)
    }
  }
}
