import DiemSwiftCrypto
import Testing

@Suite("Identity") struct IdentityTests {
  let backend = SwiftCryptoBackend()

  @Test func newIdentityHasFourKeys() throws {
    let identity = try Identity(name: "Alice", using: backend)
    #expect(identity.profile.name == "Alice")
    #expect(identity.profile.id.count == 16)
    #expect(identity.profile.keys.count == 4)
    let classicKeys = identity.profile.keys.filter { $0.cryptoSet == .classic }
    let pqcKeys = identity.profile.keys.filter { $0.cryptoSet == .pqc }
    #expect(classicKeys.count == 2)
    #expect(pqcKeys.count == 2)
    #expect(classicKeys.contains(where: { $0.keyType == .signing }))
    #expect(classicKeys.contains(where: { $0.keyType == .keyAgreement }))
    #expect(pqcKeys.contains(where: { $0.keyType == .signing }))
    #expect(pqcKeys.contains(where: { $0.keyType == .keyAgreement }))
  }

  @Test func identityHasNonzeroID() throws {
    let identity = try Identity(name: "Alice", using: backend)
    #expect(identity.profile.id.contains(where: { $0 != 0 }))
  }

  @Test func twoIdentitiesHaveDifferentIDs() throws {
    let a = try Identity(name: "Alice", using: backend)
    let b = try Identity(name: "Bob", using: backend)
    #expect(a.profile.id != b.profile.id)
  }

  @Test func classicOnlyIdentityHasTwoKeys() throws {
    let identity = try Identity(name: "Classic Only", cryptoSets: [.classic], using: backend)
    #expect(identity.profile.keys.count == 2)
  }

  @Test func restoreFromPrivateKeyStore() throws {
    let original = try Identity(name: "Bob", cryptoSets: [.classic], using: backend)
    let store = original.privateKeysByKeyID
    let restored = Identity(
      profile: original.profile, privateKeysByKeyID: store, using: backend)
    #expect(restored.profile.name == "Bob")
    let msg = try restored.sign(.unsignedInt(42))
    let valid = try msg.verify(using: restored.profile, with: backend)
    #expect(valid)
  }

  @Test func keyIDsAreUniqueAcrossSets() throws {
    let identity = try Identity(name: "Alice", using: backend)
    let ids = identity.profile.keys.map { $0.id }
    #expect(Set(ids).count == ids.count)
  }
}
