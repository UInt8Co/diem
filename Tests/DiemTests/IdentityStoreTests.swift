import DiemStoresInMemory
import DiemSwiftCrypto
import Testing

@Suite("IdentityStore") struct IdentityStoreTests {
  let backend = SwiftCryptoBackend()

  @Test func storeAndRetrieve() throws {
    let store = InMemoryIdentityStore(backend: backend)
    let identity = try Identity(name: "Alice", cryptoSets: [.classic], using: backend)
    try store.store(identity)
    let retrieved = try store.identity(for: identity.profile.id)
    #expect(retrieved?.profile.id == identity.profile.id)
    #expect(retrieved?.profile.name == "Alice")
  }

  @Test func storeAlreadyExistsThrows() throws {
    let store = InMemoryIdentityStore(backend: backend)
    let identity = try Identity(name: "Alice", using: backend)
    try store.store(identity)
    #expect(throws: DiemError.alreadyExists) { try store.store(identity) }
  }

  @Test func storeOrUpdate() throws {
    let store = InMemoryIdentityStore(backend: backend)
    let identity = try Identity(name: "Alice", cryptoSets: [.classic], using: backend)
    try store.storeOrUpdate(identity)
    try store.storeOrUpdate(identity)
    #expect(try store.allIdentities().count == 1)
  }

  @Test func decryptViaStore() throws {
    let store = InMemoryIdentityStore(backend: backend)
    let alice = try Identity(name: "Alice", cryptoSets: [.classic], using: backend)
    try store.store(alice)
    let msg = try EncryptedMessage.encrypt(
      .textString("secret"), to: alice.profile, cryptoSet: .classic, using: backend)
    let decrypted = try store.decrypt(msg)
    #expect(decrypted == .textString("secret"))
  }

  @Test func decryptUnknownKeyThrows() throws {
    let store = InMemoryIdentityStore(backend: backend)
    let alice = try Identity(name: "Alice", cryptoSets: [.classic], using: backend)
    let bob = try Identity(name: "Bob", cryptoSets: [.classic], using: backend)
    try store.store(alice)
    // Encrypt to Bob — not in store
    let msg = try EncryptedMessage.encrypt(
      .textString("secret"), to: bob.profile, cryptoSet: .classic, using: backend)
    #expect(throws: DiemError.keyNotFound) { _ = try store.decrypt(msg) }
  }

  @Test func signViaStore() throws {
    let store = InMemoryIdentityStore(backend: backend)
    let alice = try Identity(name: "Alice", cryptoSets: [.classic], using: backend)
    try store.store(alice)
    let signed = try store.sign(
      .textString("test"), identityID: alice.profile.id, cryptoSet: .classic)
    let valid = try signed.verify(using: alice.profile, with: backend)
    #expect(valid)
  }

  @Test func encryptViaStore() throws {
    let store = InMemoryIdentityStore(backend: backend)
    let bob = try Identity(name: "Bob", cryptoSets: [.classic], using: backend)
    let msg = try store.encrypt(.textString("hi Bob"), to: bob.profile, cryptoSet: .classic)
    let decrypted = try bob.decrypt(msg)
    #expect(decrypted == .textString("hi Bob"))
  }

  @Test func removeIdentity() throws {
    let store = InMemoryIdentityStore(backend: backend)
    let alice = try Identity(name: "Alice", using: backend)
    try store.store(alice)
    try store.remove(id: alice.profile.id)
    #expect(try store.identity(for: alice.profile.id) == nil)
  }

  @Test func keyIndexClearedOnRemove() throws {
    let store = InMemoryIdentityStore(backend: backend)
    let alice = try Identity(name: "Alice", cryptoSets: [.classic], using: backend)
    try store.store(alice)
    let msg = try EncryptedMessage.encrypt(
      .textString("hi"), to: alice.profile, cryptoSet: .classic, using: backend)
    try store.remove(id: alice.profile.id)
    // Decrypt should fail after removal
    #expect(throws: DiemError.keyNotFound) { _ = try store.decrypt(msg) }
  }
}
