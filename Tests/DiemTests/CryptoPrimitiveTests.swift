import DiemSwiftCrypto
import DiemStoresInMemory
import Testing

@Suite struct CryptoPrimitiveTests {
  @Test func signsAndWrapsWithSeparateKeys() throws {
    let crypto = SoftwareDeviceCrypto()
    let signing = try SoftwareSigningKey(algorithm: .ed25519)
    let wrapping = try SoftwareWrappingKey(algorithm: .x25519)
    let message = Array("primitive roundtrip".utf8)
    let signature = try signing.signature(for: message)
    #expect(try crypto.verify(signature, message: message, key: signing.publicKey))

    let context = Array("test context".utf8)
    let box = try crypto.seal(message, to: wrapping.publicKey, context: context)
    #expect(try wrapping.open(box, context: context) == message)
    #expect(throws: DiemError.decryptionFailed) {
      try wrapping.open(box, context: Array("other context".utf8))
    }
  }

  @Test func encryptedMessageAndShareRoundtrip() throws {
    let crypto = SoftwareDeviceCrypto()
    let wrapping = try SoftwareWrappingKey(algorithm: .p256Agreement)
    let payload = CBOR.array([.unsignedInt(7), .textString("hello")])
    let encrypted = try EncryptedMessage.encrypt(payload, to: wrapping.publicKey, using: crypto)
    let decoded = try EncryptedMessage.decode(encrypted.encode())
    guard case .device(let key, let encapsulatedKey) = decoded.recipient else {
      Issue.record("Expected a device recipient")
      return
    }
    #expect(key == wrapping.publicKey)
    let plaintext = try wrapping.open(
      .init(encapsulatedKey: encapsulatedKey, ciphertext: decoded.ciphertext),
      context: EncryptedMessage.context(for: key))
    #expect(try CBOR.decode(plaintext) == payload)

    let share = EncryptedShare(using: crypto)
    let ciphertext = try share.encrypt(payload, using: crypto)
    #expect(try share.decrypt(ciphertext, using: crypto) == payload)
  }

  @Test func shareInvitationBindsRecipientAndRejectsTampering() throws {
    let crypto = SoftwareDeviceCrypto()
    let share = EncryptedShare(using: crypto)
    let recipient = try SoftwareWrappingKey(algorithm: .x25519)
    let stranger = try SoftwareWrappingKey(algorithm: .x25519)
    let invitation = try EncryptedMessage.decode(share.invite(recipient.publicKey, using: crypto).encode())
    guard case .device(let key, let encapsulatedKey) = invitation.recipient else {
      Issue.record("Expected a device invitation")
      return
    }
    let context = EncryptedMessage.context(for: key)
    let box = WrappedSecret(encapsulatedKey: encapsulatedKey, ciphertext: invitation.ciphertext)
    let accepted = try EncryptedShare(
      cbor: CanonicalCBOR.decode(recipient.open(box, context: context)), using: crypto)
    #expect(accepted.id == share.id)
    #expect(throws: DiemError.decryptionFailed) { try stranger.open(box, context: context) }
    var corrupted = invitation.ciphertext
    corrupted[0] ^= 1
    #expect(throws: DiemError.decryptionFailed) {
      try recipient.open(.init(encapsulatedKey: encapsulatedKey, ciphertext: corrupted), context: context)
    }
    let signing = try SoftwareSigningKey(algorithm: .ed25519)
    #expect(throws: DiemError.roleConfusion) {
      try EncryptedMessage.encrypt(.null, to: signing.publicKey, using: crypto)
    }
  }

  @Test func shareStoreRetainsOnlyItsOwnMessages() throws {
    let crypto = SoftwareDeviceCrypto()
    let store = InMemoryShareStore()
    let share = EncryptedShare(using: crypto)
    try store.store(share)
    #expect(throws: DiemError.alreadyExists) { try store.store(share) }
    let message = try store.encrypt(.textString("stored"), toShareWithKeyID: share.id, using: crypto)
    #expect(try store.decrypt(.decode(message.encode()), using: crypto) == .textString("stored"))
    try store.remove(keyID: share.id)
    #expect(throws: DiemError.keyNotFound) { try store.decrypt(message, using: crypto) }
  }
}
