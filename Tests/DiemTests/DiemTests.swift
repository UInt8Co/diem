import DiemSwiftCrypto
import Testing

// MARK: - Profile Tests

@Suite("Profile") struct ProfileTests {
  @Test func roundtripCBOR() throws {
    let extensions = CBOR.map([
      CBORMapPair(key: .textString("role"), value: .textString("admin"))
    ])
    let keyEntry = PublicKeyEntry(
      id: [UInt8](repeating: 0xAB, count: 32),
      keyType: .signing,
      cryptoSet: .classic,
      rawBytes: [UInt8](repeating: 0xCD, count: 32)
    )
    let profile = Profile(
      keys: [keyEntry],
      name: "Alice",
      createdAt: 1_700_000_000,
      expiresAt: 1_800_000_000,
      extensions: extensions
    )
    let decoded = try Profile.decode(profile.encode())
    #expect(decoded.name == "Alice")
    #expect(decoded.createdAt == 1_700_000_000)
    #expect(decoded.expiresAt == 1_800_000_000)
    #expect(decoded.keys.count == 1)
    #expect(decoded.keys[0].id == keyEntry.id)
    #expect(decoded.keys[0].keyType == .signing)
    #expect(decoded.keys[0].cryptoSet == .classic)
    #expect(decoded.keys[0].rawBytes == keyEntry.rawBytes)
  }

  @Test func pqcKeyRoundtrip() throws {
    let keyEntry = PublicKeyEntry(
      id: [UInt8](repeating: 0x11, count: 32),
      keyType: .keyAgreement,
      cryptoSet: .pqc,
      rawBytes: [UInt8](repeating: 0x22, count: 64)
    )
    let profile = Profile(keys: [keyEntry], name: "PQC User")
    let decoded = try Profile.decode(profile.encode())
    #expect(decoded.keys[0].cryptoSet == .pqc)
    #expect(decoded.keys[0].keyType == .keyAgreement)
  }

  @Test func missingNameThrows() throws {
    let empty = CBOR.map([])
    #expect(throws: DiemError.missingField("Profile: keys or name missing")) {
      _ = try Profile.fromCBOR(empty)
    }
  }
}

// MARK: - Identity Tests

@Suite("Identity") struct IdentityTests {
  let backend = SwiftCryptoBackend()

  @Test func newIdentityHasFourKeys() throws {
    let identity = try Identity(name: "Alice", using: backend)
    #expect(identity.profile.name == "Alice")
    // 2 sets × 2 key types = 4 keys
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

  @Test func classicOnlyIdentityHasTwoKeys() throws {
    let identity = try Identity(name: "Classic Only", cryptoSets: [.classic], using: backend)
    #expect(identity.profile.keys.count == 2)
  }

  @Test func restoreFromPrivateKeyStore() throws {
    let original = try Identity(name: "Bob", cryptoSets: [.classic], using: backend)
    let store = original.privateKeysByKeyID
    let restored = Identity(profile: original.profile, privateKeysByKeyID: store, using: backend)
    #expect(restored.profile.name == "Bob")
    // Should be able to sign after restoring
    let msg = try restored.sign(.unsignedInt(42))
    let valid = try msg.verify(using: restored.profile, with: backend)
    #expect(valid)
  }

  @Test func keyIDsAreUniqueAcrossSets() throws {
    let identity = try Identity(name: "Alice", using: backend)
    let ids = identity.profile.keys.map { $0.id }
    let unique = Set(ids)
    #expect(unique.count == ids.count)
  }
}

// MARK: - EncryptedMessage Tests

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
    // Alice's identity cannot decrypt a message addressed to Bob
    #expect(throws: DiemError.keyNotFound) {
      _ = try alice.decrypt(msg)
    }
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
    // Decryption still works after CBOR round-trip
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

// MARK: - SignedMessage Tests

@Suite("SignedMessage") struct SignedMessageTests {
  let backend = SwiftCryptoBackend()

  @Test func classicSignVerify() throws {
    let alice = try Identity(name: "Alice", cryptoSets: [.classic], using: backend)
    let payload: CBOR = .textString("signed message")
    let msg = try alice.sign(payload, cryptoSet: .classic)
    #expect(msg.cryptoSet == .classic)
    #expect(msg.payload == payload)
    let valid = try msg.verify(using: alice.profile, with: backend)
    #expect(valid)
  }

  @Test func pqcSignVerify() throws {
    let alice = try Identity(name: "Alice", cryptoSets: [.pqc], using: backend)
    let payload: CBOR = .textString("pqc signed")
    let msg = try alice.sign(payload, cryptoSet: .pqc)
    #expect(msg.cryptoSet == .pqc)
    let valid = try msg.verify(using: alice.profile, with: backend)
    #expect(valid)
  }

  @Test func verifyAgainstSpecificKey() throws {
    let alice = try Identity(name: "Alice", using: backend)
    let msg = try alice.sign(.unsignedInt(7), cryptoSet: .classic)
    let sigKey = alice.profile.keys.first(where: {
      $0.keyType == .signing && $0.cryptoSet == .classic
    })!
    let valid = try msg.verify(against: sigKey, using: backend)
    #expect(valid)
  }

  @Test func bothCryptoSetsDefaultSign() throws {
    let alice = try Identity(name: "Alice", using: backend)
    // Default crypto set is classic
    let msg = try alice.sign(.textString("default"))
    #expect(msg.cryptoSet == .classic)
  }

  @Test func cborRoundtrip() throws {
    let alice = try Identity(name: "Alice", cryptoSets: [.classic], using: backend)
    let msg = try alice.sign(.unsignedInt(42), cryptoSet: .classic)
    let decoded = try SignedMessage.decode(msg.encode())
    #expect(decoded.cryptoSet == msg.cryptoSet)
    #expect(decoded.senderKeyID == msg.senderKeyID)
    #expect(decoded.payload == msg.payload)
    #expect(decoded.signature == msg.signature)
    let valid = try decoded.verify(using: alice.profile, with: backend)
    #expect(valid)
  }

  @Test func wrongProfileThrows() throws {
    let alice = try Identity(name: "Alice", cryptoSets: [.classic], using: backend)
    let bob = try Identity(name: "Bob", cryptoSets: [.classic], using: backend)
    let msg = try alice.sign(.textString("alice"), cryptoSet: .classic)
    // Bob's profile does not contain Alice's signing key
    #expect(throws: DiemError.keyNotFound) {
      _ = try msg.verify(using: bob.profile, with: backend)
    }
  }

  @Test func wrongCryptoSetKeyThrows() throws {
    let alice = try Identity(name: "Alice", using: backend)
    let classicMsg = try alice.sign(.textString("classic"), cryptoSet: .classic)
    // A PQC key does not verify a classic-set message
    let pqcKey = alice.profile.keys.first(where: {
      $0.keyType == .signing && $0.cryptoSet == .pqc
    })!
    #expect(throws: DiemError.invalidKeyType) {
      _ = try classicMsg.verify(against: pqcKey, using: backend)
    }
  }
}
