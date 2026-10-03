import Diem
import Foundation
import Testing

@Suite struct IdentityTests {
  let backend = TestBackend()

  @Test func newIdentityPublishesAVerifiableProfileAndProofs() async throws {
    let identity = try await Identity(data: [1, 2, 3], using: backend)
    let profile = try Profile(encoding: identity.profile.encoding)
    #expect(profile == identity.profile)
    #expect(profile.data == [1, 2, 3] && profile.revision == 1 && profile.generation == 1)
    #expect(profile.previousDigest == nil && profile.id == identity.identityKey?.publicKey.id)
    try await profile.verify(using: backend)

    let proof = try Proof(encoding: try await identity.prove([7]).encoding)
    #expect(proof.data == [7] && proof.deviceID == identity.deviceKey.publicKey.id)
    try await proof.verify(against: profile, using: backend)

    let stranger = try await Identity(data: [], using: backend)
    await #expect(throws: DiemError.identityMismatch) {
      try await proof.verify(against: stranger.profile, using: backend)
    }
  }

  @Test func updatesChainRevisions() async throws {
    var identity = try await Identity(data: [1], using: backend)
    let first = identity.profile
    let second = try await identity.update(data: [2])
    #expect(second.revision == 2 && second.previousDigest == first.digest && second.data == [2])
    try await second.verify(using: backend)
  }

  @Test func chosenLifetimesSurvivePublicationRenewalAndReopening() async throws {
    let day: UInt64 = 86400
    var owner = try await Identity(data: [1], profileLifetime: 90 * day,
      deviceLifetime: 90 * day, using: backend)
    #expect(owner.profile.validity.lifetime == 90 * day)
    #expect(owner.profile.devices[0].validity.lifetime == 90 * day)
    backend.advance(by: 60 * day)
    try await owner.profile.verify(using: backend)
    // A device cannot publish beyond its certificate without the identity key.
    var device = try await Identity(profile: owner.profile, deviceKey: owner.deviceKey,
      profileLifetime: 90 * day, using: backend)
    #expect(try await device.update(data: [2]).validity.lifetime == 30 * day)
    try await owner.renew()
    #expect(owner.profile.validity.lifetime == 90 * day)
    backend.advance(by: 91 * day)
    await #expect(throws: DiemError.expired) { try await owner.profile.verify(using: backend) }
    var reopened = try await Identity(profile: owner.profile, deviceKey: owner.deviceKey,
      identityKey: owner.identityKey, profileLifetime: 120 * day, deviceLifetime: 180 * day,
      using: backend)
    try await reopened.renew().verify(using: backend)
    #expect(reopened.profile.validity.lifetime == 120 * day)
    #expect(reopened.profile.devices[0].validity.lifetime == 180 * day)
  }

  @Test func invalidLifetimesFailWithoutArithmeticOverflow() async throws {
    for lifetime: UInt64 in [0, UInt64(Int64.max), UInt64.max] {
      await #expect(throws: DiemError.invalidValidity) {
        try await Identity(data: [], profileLifetime: lifetime, using: backend)
      }
      await #expect(throws: DiemError.invalidValidity) {
        try await Identity(data: [], deviceLifetime: lifetime, using: backend)
      }
    }
  }

  @Test func addedDeviceSignsProfilesAndProofsWithoutTheIdentityKey() async throws {
    var owner = try await Identity(data: [1], using: backend)
    let laptopKey = try await DevicePrivateKey.generate(.p256, using: backend)
    let added = try await owner.add(laptopKey.publicKey)
    #expect(added.devices.count == 2 && added.generation == 1)

    var laptop = try await Identity(profile: added, deviceKey: laptopKey, using: backend)
    #expect(laptop.identityKey == nil)
    let updated = try await laptop.update(data: [9])
    #expect(updated.signer == laptopKey.publicKey)
    try await updated.verify(using: backend)
    try await laptop.prove([4]).verify(against: updated, using: backend)
    await #expect(throws: DiemError.identityKeyRequired) {
      try await laptop.add(try await DevicePrivateKey.generate(using: backend).publicKey)
    }
  }

  @Test func removingADeviceStartsANewGeneration() async throws {
    var owner = try await Identity(data: [1], using: backend)
    let lostKey = try await DevicePrivateKey.generate(using: backend)
    let withLost = try await owner.add(lostKey.publicKey)
    let lost = try await Identity(profile: withLost, deviceKey: lostKey, using: backend)
    let staleProof = try await lost.prove([1])

    let without = try await owner.remove(lostKey.publicKey.id)
    #expect(without.generation == 2 && without.devices.count == 1)
    await #expect(throws: DiemError.deviceNotListed) {
      try await staleProof.verify(against: without, using: backend)
    }
    await #expect(throws: DiemError.deviceNotListed) {
      try await Identity(profile: without, deviceKey: lostKey, using: backend)
    }
    await #expect(throws: DiemError.identityMismatch) {
      try await owner.remove(owner.deviceKey.publicKey.id)
    }
  }

  @Test func profilesAndCertificatesExpire() async throws {
    var owner = try await Identity(data: [1], using: backend)
    let otherKey = try await DevicePrivateKey.generate(using: backend)
    var other = try await Identity(
      profile: try await owner.add(otherKey.publicKey), deviceKey: otherKey, using: backend)

    backend.advance(by: Profile.defaultLifetime)
    await #expect(throws: DiemError.expired) { try await owner.profile.verify(using: backend) }
    try await other.renew().verify(using: backend)

    backend.advance(by: DeviceCertificate.defaultLifetime)
    await #expect(throws: DiemError.expired) { try await other.update(data: [2]) }
    // The identity key reissues expired certificates on update.
    let renewed = try await owner.update(data: [3])
    try await renewed.verify(using: backend)
    #expect(renewed.devices.count == 2)
  }

  @Test func decodingRejectsMixedIdentitiesAndGenerations() async throws {
    let alice = try await Identity(data: [], using: backend)
    let bob = try await Identity(data: [], using: backend)
    func mixed(key: Profile, devices: Profile, content: Profile) -> [UInt8] {
      CBOR.map([
        .unsigned(0): .text("Diem/profile"), .unsigned(1): .unsigned(3), .unsigned(2): .bytes(key.identityKey.key.encoding),
        .unsigned(3): .array(devices.devices.map { .bytes($0.encoding) }), .unsigned(4): .bytes(content.content.encoding),
      ]).encoded
    }
    #expect(throws: DiemError.identityMismatch) {
      try Profile(encoding: mixed(key: alice.profile, devices: bob.profile, content: alice.profile))
    }
    #expect(throws: DiemError.identityMismatch) {
      try Profile(encoding: mixed(key: alice.profile, devices: alice.profile, content: bob.profile))
    }
    var owner = alice
    let removedKey = try await DevicePrivateKey.generate(using: backend)
    let first = try await owner.add(removedKey.publicKey)
    let second = try await owner.remove(removedKey.publicKey.id)
    #expect(throws: DiemError.identityMismatch) {
      try Profile(encoding: mixed(key: first, devices: first, content: second))
    }
  }

  @Test(arguments: PublicKey.Algorithm.allCases)
  func softwareIdentityRestoresFromItsRecoverySecret(algorithm: PublicKey.Algorithm) async throws {
    let key = try await IdentityPrivateKey.generate(algorithm, using: backend)
    let secret = try #require(key.rawRepresentation)
    let restored = try await IdentityPrivateKey(
      backend.makePrivateKey(algorithm, for: .identity, restoring: secret))
    #expect(restored.publicKey == key.publicKey)
    #expect(restored.protection == .software)

    let identity = try await Identity(data: [1], identityKey: restored,
      deviceKey: .generate(using: backend), using: backend)
    try await identity.profile.verify(using: backend)
    #expect(identity.profile.id == key.publicKey.id)
  }

  @Test func hardwareIdentityCannotExportOrSealARecoverySecret() async throws {
    let software = try await backend.makePrivateKey(.p256, for: .identity)
    // Even if a backend supplies bytes, hardware protection must prevent export.
    let hardware = try IdentityPrivateKey(PrivateKey(publicKey: software.publicKey,
      protection: .hardware, rawRepresentation: software.rawRepresentation,
      sign: { _ in throw DiemError.invalidKey }))
    #expect(hardware.rawRepresentation == nil)
    let recipient = try await backend.makeEncryptionKey()
    await #expect(throws: DiemError.invalidKey) {
      try await hardware.sealed(to: recipient.publicKey, using: backend)
    }
  }

  @Test func sealedIdentityKeyOpensOnlyForItsRecipient() async throws {
    let identity = try await Identity(data: [], using: backend)
    let recipient = try await backend.makeEncryptionKey()
    let sealed = try await identity.identityKey!.sealed(to: recipient.publicKey, using: backend)
    let decoded = try SealedIdentityKey(encoding: sealed.encoding)
    let opened = try await decoded.open(with: recipient, using: backend)
    #expect(opened.publicKey == identity.profile.identityKey)
    #expect(opened.rawRepresentation == identity.identityKey!.rawRepresentation)

    var restored = try await Identity(
      profile: identity.profile, deviceKey: identity.deviceKey, identityKey: opened, using: backend)
    try await restored.renew().verify(using: backend)

    let other = try await backend.makeEncryptionKey()
    await #expect(throws: DiemError.identityMismatch) {
      try await decoded.open(with: other, using: backend)
    }
  }

  @Test func identityKeyMaterialNeverActsAsADevice() async throws {
    let identityKey = try await backend.makePrivateKey(for: .identity)
    let sameMaterial = try DevicePrivateKey(
      await backend.makePrivateKey(.mlDSA65, for: .device, restoring: identityKey.rawRepresentation))
    await #expect(throws: DiemError.identityMismatch) {
      try await Identity(
        data: [], identityKey: IdentityPrivateKey(identityKey), deviceKey: sameMaterial,
        using: backend)
    }
    var owner = try await Identity(
      data: [], identityKey: IdentityPrivateKey(identityKey),
      deviceKey: .generate(using: backend), using: backend)
    await #expect(throws: DiemError.identityMismatch) { try await owner.add(sameMaterial.publicKey) }
  }

  @Test func committedVectorsDecodeAndVerify() async throws {
    struct Fixture: Decodable {
      struct Vector: Decodable { let profile, proof, sealedIdentityKey, identityID: String }
      let now: UInt64
      let vectors: [Vector]
    }
    func bytes(_ hex: String) -> [UInt8] {
      var result: [UInt8] = []
      var index = hex.startIndex
      while index < hex.endIndex {
        let next = hex.index(index, offsetBy: 2)
        result.append(UInt8(hex[index..<next], radix: 16)!)
        index = next
      }
      return result
    }
    let url = URL(filePath: #filePath).deletingLastPathComponent()
      .appending(path: "../Vectors/diem-v3.json")
    let fixture = try JSONDecoder().decode(Fixture.self, from: Data(contentsOf: url))
    for vector in fixture.vectors {
      let profile = try Profile(encoding: bytes(vector.profile))
      #expect(profile.id.bytes == bytes(vector.identityID))
      try await profile.verify(using: backend, at: fixture.now)
      try await Proof(encoding: bytes(vector.proof)).verify(
        against: profile, using: backend, at: fixture.now)
      #expect(try SealedIdentityKey(encoding: bytes(vector.sealedIdentityKey)).identityKey
        == profile.identityKey)
    }
  }
}
