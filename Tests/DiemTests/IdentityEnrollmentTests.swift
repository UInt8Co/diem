@testable import Diem
import DiemSwiftCrypto
import Testing

@Suite struct IdentityEnrollmentTests {
  let backend = TestBackend()

  @Test func recoveryCertifiesANewDeviceAndPreservesTheProfileChain() async throws {
    let backend = SwiftCryptoBackend()
    let root = try await IdentityPrivateKey(backend.makePrivateKey(.ed25519, for: .identity))
    let original = try await DevicePrivateKey(backend.makePrivateKey(.ed25519, for: .device))
    let identity = try await TestIdentity(.data([1, 2, 3]), identityKey: root, deviceKey: original, using: backend)
    let restoredDevice = try await DevicePrivateKey(backend.makePrivateKey(.p256, for: .device))
    let recovered = try await TestIdentity.enrolling(restoredDevice, in: identity.profile,
      identityKey: root, using: backend)
    try await recovered.profile.verify(using: backend)
    #expect(recovered.id == identity.id)
    #expect(recovered.profile.generation == identity.profile.generation)
    #expect(recovered.profile.revision == identity.profile.revision + 1)
    #expect(recovered.profile.previousDigest == identity.profile.digest)
    #expect(recovered.profile.content == identity.profile.content)
    #expect(recovered.profile.devices.map(\.device) == [original.publicKey, restoredDevice.publicKey])
  }

  @Test func anUnrelatedRootCannotEnroll() async throws {
    let backend = SwiftCryptoBackend()
    let identity = try await TestIdentity(.data([4]), using: backend)
    let root = try await IdentityPrivateKey(backend.makePrivateKey(.ed25519, for: .identity))
    let device = try await DevicePrivateKey(backend.makePrivateKey(.p256, for: .device))
    await #expect(throws: DiemError.identityMismatch) {
      try await TestIdentity.enrolling(device, in: identity.profile, identityKey: root, using: backend)
    }
  }

  @Test func enrollmentRevokesDevicesAndPublishesContentInOneRevision() async throws {
    let (old, root, _) = try await fixture(count: 3)
    let fresh = try await DevicePrivateKey.generate(.p256, using: backend)
    let removals = Set([old.devices[0].device.id, old.devices[1].device.id])
    backend.advance(by: DeviceCertificate.defaultLifetime + 1)
    let recovered = try await TestIdentity.enrolling(fresh, in: old, identityKey: root,
      removing: removals, publishing: .data([9]), profileLifetime: 60, deviceLifetime: 120,
      using: backend)
    let next = recovered.profile
    try await next.verify(using: backend)
    #expect(next.id == old.id && next.signer == fresh.publicKey)
    #expect(next.generation == old.generation + 1 && next.revision == old.revision + 1)
    #expect(next.previousDigest == old.digest && next.content == .data([9]))
    #expect(next.devices.map(\.device) == [old.devices[2].device, fresh.publicKey])
    #expect(try next.validity == Validity(starting: backend.now, lifetime: 60))
    #expect(try next.devices[0].validity == Validity(starting: backend.now, lifetime: 120))
    #expect(next.devices[0].generation == next.generation)
    #expect(next.devices[1].generation == next.generation)
  }

  @Test func enrollmentPrunesBeforeAddingAtTheDeviceLimit() async throws {
    let (old, root, original) = try await fixture(count: ProfileRecord.maximumDevices)
    let fresh = try await DevicePrivateKey.generate(.p256, using: backend)
    let next = try await old.enrolling(fresh, identityKey: root,
      removing: [original.publicKey.id], using: backend)
    try await next.verify(using: backend)
    #expect(next.devices.count == ProfileRecord.maximumDevices)
    #expect(next.device(original.publicKey.id) == nil && next.signer == fresh.publicKey)
    #expect(next.device(old.devices[64].device.id) == old.devices[64].device)
    #expect(next.generation == old.generation + 1 && next.revision == old.revision + 1)
    #expect(next.previousDigest == old.digest && next.content == old.content)
    await #expect(throws: DiemError.invalidEncoding) {
      try await old.enrolling(fresh, identityKey: root, using: backend)
    }
    let reissued = try await old.enrolling(original, identityKey: root, using: backend)
    #expect(reissued.devices.count == ProfileRecord.maximumDevices)
    #expect(reissued.generation == old.generation && reissued.previousDigest == old.digest)
  }

  @Test func enrollmentRejectsInvalidRemovalsAndLifetimes() async throws {
    let (old, root, original) = try await fixture()
    let fresh = try await DevicePrivateKey.generate(.p256, using: backend)
    await #expect(throws: DiemError.deviceNotListed) {
      try await old.enrolling(original, identityKey: root,
        removing: [fresh.publicKey.id], using: backend)
    }
    await #expect(throws: DiemError.identityMismatch) {
      try await old.enrolling(fresh, identityKey: root,
        removing: [fresh.publicKey.id], using: backend)
    }
    await #expect(throws: DiemError.identityMismatch) {
      try await old.enrolling(original, identityKey: root,
        removing: [original.publicKey.id], using: backend)
    }
    await #expect(throws: DiemError.invalidValidity) {
      try await old.enrolling(fresh, identityKey: root,
        profileLifetime: 121, deviceLifetime: 120, using: backend)
    }
  }

  @Test func enrollmentVerifiesThePreviousProfile() async throws {
    let (old, root, _) = try await fixture()
    let fresh = try await DevicePrivateKey.generate(.p256, using: backend)
    var signature = old.record.signedContent.signature
    signature[0] ^= 1
    var fields = try CBOR(decoding: old.encoding).recordValue(requiredKeys: 0..<5)
    fields[ProfileRecord.cborKeyContent] = .bytes(SignedMessage(
      message: old.record.signedContent.message, signature: signature).encoding)
    let unverified = try ProfileRecord(encoding: CBOR.record(fields).encoded)
    await #expect(throws: DiemError.invalidSignature) {
      try await unverified.enrolling(fresh, identityKey: root, using: backend)
    }
  }

  @Test func enrollmentRejectsVersionOverflow() async throws {
    let (lastRevision, root, _) = try await fixture(revision: UInt64(Int64.max))
    let fresh = try await DevicePrivateKey.generate(.p256, using: backend)
    await #expect(throws: DiemError.invalidEncoding) {
      try await lastRevision.enrolling(fresh, identityKey: root, using: backend)
    }
    let (lastGeneration, otherRoot, original) = try await fixture(generation: UInt64(Int64.max))
    await #expect(throws: DiemError.invalidEncoding) {
      try await lastGeneration.enrolling(fresh, identityKey: otherRoot,
        removing: [original.publicKey.id], using: backend)
    }
    let next = try await lastGeneration.enrolling(fresh, identityKey: otherRoot, using: backend)
    #expect(next.generation == lastGeneration.generation && next.revision == 2)
  }

  private func fixture(count: Int = 1, generation: UInt64 = 1, revision: UInt64 = 1) async throws
    -> (ProfileRecord, IdentityPrivateKey, DevicePrivateKey)
  {
    let root = try await IdentityPrivateKey.generate(.ed25519, using: backend)
    let original = try await DevicePrivateKey.generate(.p256, using: backend)
    let validity = try Validity(starting: backend.now, lifetime: DeviceCertificate.defaultLifetime)
    var certificates = [try await DeviceCertificate.issue(
      by: root, for: original.publicKey, generation: generation, validity: validity)]
    // Build one capacity fixture without publishing every intermediate device count.
    for _ in 1..<count {
      let device = try await DevicePrivateKey.generate(.ed25519, using: backend)
      certificates.append(try await DeviceCertificate.issue(
        by: root, for: device.publicKey, generation: generation, validity: validity))
    }
    let profile = try await ProfileRecord.sign(
      identityKey: root.publicKey, devices: certificates, by: original,
      revision: revision, previousDigest: revision == 1 ? nil : Digest(hashing: [1]),
      validity: Validity(starting: backend.now, lifetime: ProfileRecord.defaultLifetime),
      fields: .data([1, 2, 3]))
    return (profile, root, original)
  }
}
