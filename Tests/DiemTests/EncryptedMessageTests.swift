import DiemSwiftCrypto
import Testing

@Suite("EncryptedMessage") struct EncryptedMessageTests {
  let backend = SwiftCryptoBackend()

  @Test func classicEncryptDecrypt() throws {
    let alice = try Identity(name: "Alice", cryptoSets: [.classic], using: backend)
    let kaKey = alice.profile.keys.first(where: {
      $0.keyType == .keyAgreement && $0.cryptoSet == .classic
    })!
    let payload: CBOR = .textString("hello, world")
    let msg = try EncryptedMessage.encrypt(payload, to: kaKey, using: backend)
    #expect(msg.cryptoSet == .classic)
    #expect(msg.recipientKeyID == kaKey.id)
    let decrypted = try alice.decrypt(msg)
    #expect(decrypted == payload)
  }

  @Test func pqcEncryptDecrypt() throws {
    let alice = try Identity(name: "Alice", cryptoSets: [.pqc], using: backend)
    let kaKey = alice.profile.keys.first(where: {
      $0.keyType == .keyAgreement && $0.cryptoSet == .pqc
    })!
    let payload: CBOR = .textString("post-quantum hello")
    let msg = try EncryptedMessage.encrypt(payload, to: kaKey, using: backend)
    #expect(msg.cryptoSet == .pqc)
    let decrypted = try alice.decrypt(msg)
    #expect(decrypted == payload)
  }

  @Test func crossIdentityClassicEncryptDecrypt() throws {
    let alice = try Identity(name: "Alice", cryptoSets: [.classic], using: backend)
    let bob = try Identity(name: "Bob", cryptoSets: [.classic], using: backend)
    let bobKA = bob.profile.keys.first(where: {
      $0.keyType == .keyAgreement && $0.cryptoSet == .classic
    })!
    let payload: CBOR = .textString("hi Bob")
    let msg = try EncryptedMessage.encrypt(payload, to: bobKA, using: backend)
    let decrypted = try bob.decrypt(msg)
    #expect(decrypted == payload)
    #expect(throws: DiemError.keyNotFound) { _ = try alice.decrypt(msg) }
  }

  @Test func cborRoundtrip() throws {
    let alice = try Identity(name: "Alice", cryptoSets: [.classic], using: backend)
    let kaKey = alice.profile.keys.first(where: {
      $0.keyType == .keyAgreement && $0.cryptoSet == .classic
    })!
    let msg = try EncryptedMessage.encrypt(.unsignedInt(99), to: kaKey, using: backend)
    let decoded = try EncryptedMessage.decode(msg.encode())
    #expect(decoded.cryptoSet == msg.cryptoSet)
    #expect(decoded.recipientKeyID == msg.recipientKeyID)
    #expect(decoded.encapsulatedKey == msg.encapsulatedKey)
    #expect(decoded.ciphertext == msg.ciphertext)
    let decrypted = try alice.decrypt(decoded)
    #expect(decrypted == .unsignedInt(99))
  }

  @Test func signingKeyThrowsInvalidKeyType() throws {
    let alice = try Identity(name: "Alice", cryptoSets: [.classic], using: backend)
    let signingKey = alice.profile.keys.first(where: { $0.keyType == .signing })!
    #expect(throws: DiemError.invalidKeyType) {
      _ = try EncryptedMessage.encrypt(.unsignedInt(1), to: signingKey, using: backend)
    }
  }
}
