import Diem
import DiemSwiftCrypto
import Testing

@Suite struct IdentityEnrollmentTests {
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
}
