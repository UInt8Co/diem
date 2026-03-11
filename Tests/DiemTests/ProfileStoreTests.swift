import DiemStoresInMemory
import DiemSwiftCrypto
import Testing

@Suite("ProfileStore") struct ProfileStoreTests {
  let backend = SwiftCryptoBackend()

  func makeIdentity(name: String = "Alice") throws -> Identity<SwiftCryptoBackend> {
    try Identity(name: name, cryptoSets: [.classic], using: backend)
  }

  @Test func storeAndRetrieve() throws {
    let store = InMemoryProfileStore()
    let identity = try makeIdentity()
    try store.store(identity.profile)
    let retrieved = try store.profile(for: identity.profile.id)
    #expect(retrieved?.id == identity.profile.id)
    #expect(retrieved?.name == identity.profile.name)
  }

  @Test func storeAlreadyExistsThrows() throws {
    let store = InMemoryProfileStore()
    let identity = try makeIdentity()
    try store.store(identity.profile)
    #expect(throws: DiemError.alreadyExists) { try store.store(identity.profile) }
  }

  @Test func updateReturnsNilForUnknown() throws {
    let store = InMemoryProfileStore()
    let identity = try makeIdentity()
    let result = try store.update(identity.profile)
    #expect(result == nil)
  }

  @Test func updateReturnsDiff() throws {
    let store = InMemoryProfileStore()
    let identity = try makeIdentity()
    try store.store(identity.profile)
    let updated = Profile(
      id: identity.profile.id, keys: identity.profile.keys, name: "Alice Updated",
      createdAt: 1_700_000_000)
    let summary = try store.update(updated)
    #expect(summary != nil)
    #expect(summary?.createdAtChange != nil)
    #expect(summary?.updated.name == "Alice Updated")
  }

  @Test func storeOrUpdateNewProfile() throws {
    let store = InMemoryProfileStore()
    let identity = try makeIdentity()
    let result = try store.storeOrUpdate(identity.profile)
    #expect(result == nil)
    #expect(try store.profile(for: identity.profile.id)?.id == identity.profile.id)
  }

  @Test func storeOrUpdateExistingProfile() throws {
    let store = InMemoryProfileStore()
    let identity = try makeIdentity()
    try store.store(identity.profile)
    let updated = Profile(id: identity.profile.id, keys: identity.profile.keys, name: "New Name")
    let summary = try store.storeOrUpdate(updated)
    #expect(summary != nil)
    #expect(summary?.updated.name == "New Name")
  }

  @Test func removeProfile() throws {
    let store = InMemoryProfileStore()
    let identity = try makeIdentity()
    try store.store(identity.profile)
    try store.remove(id: identity.profile.id)
    #expect(try store.profile(for: identity.profile.id) == nil)
  }

  @Test func allProfiles() throws {
    let store = InMemoryProfileStore()
    let a = try makeIdentity(name: "Alice")
    let b = try makeIdentity(name: "Bob")
    try store.store(a.profile)
    try store.store(b.profile)
    #expect(try store.allProfiles().count == 2)
  }

  @Test func lookupByKeyID() throws {
    let store = InMemoryProfileStore()
    let identity = try makeIdentity()
    try store.store(identity.profile)
    let kaKey = identity.profile.keys.first(where: {
      $0.keyType == .keyAgreement && $0.cryptoSet == .classic
    })!
    let found = try store.profile(forKeyID: kaKey.id)
    #expect(found?.id == identity.profile.id)
  }

  @Test func lookupByKeyIDAfterUpdate() throws {
    let store = InMemoryProfileStore()
    let identity = try makeIdentity()
    try store.store(identity.profile)
    // Create a fresh identity just to get new keys
    let identity2 = try makeIdentity(name: "Alice2")
    let updatedProfile = Profile(
      id: identity.profile.id,
      keys: identity2.profile.keys,  // different keys
      name: identity.profile.name
    )
    _ = try store.update(updatedProfile)
    // Old keys should not be found
    let oldKey = identity.profile.keys[0]
    #expect(try store.profile(forKeyID: oldKey.id) == nil)
    // New keys should be found
    let newKey = identity2.profile.keys[0]
    let found = try store.profile(forKeyID: newKey.id)
    #expect(found?.id == identity.profile.id)
  }

  @Test func lookupByKeyIDRemovedAfterRemove() throws {
    let store = InMemoryProfileStore()
    let identity = try makeIdentity()
    try store.store(identity.profile)
    let kaKey = identity.profile.keys.first(where: { $0.keyType == .keyAgreement })!
    try store.remove(id: identity.profile.id)
    #expect(try store.profile(forKeyID: kaKey.id) == nil)
  }

  @Test func encryptViaStore() throws {
    let store = InMemoryProfileStore()
    let alice = try makeIdentity()
    try store.store(alice.profile)
    let msg = try store.encrypt(
      .textString("hello"), toProfileWithID: alice.profile.id, cryptoSet: .classic,
      using: backend)
    let decrypted = try alice.decrypt(msg)
    #expect(decrypted == .textString("hello"))
  }

  @Test func verifyViaStore() throws {
    let store = InMemoryProfileStore()
    let alice = try makeIdentity()
    try store.store(alice.profile)
    let signed = try alice.sign(.textString("hi"), cryptoSet: .classic)
    let valid = try store.verify(signed, using: backend)
    #expect(valid)
  }

  @Test func verifyUnknownSenderThrows() throws {
    let store = InMemoryProfileStore()
    let alice = try makeIdentity()
    let signed = try alice.sign(.textString("hi"), cryptoSet: .classic)
    #expect(throws: DiemError.keyNotFound) { _ = try store.verify(signed, using: backend) }
  }
}
