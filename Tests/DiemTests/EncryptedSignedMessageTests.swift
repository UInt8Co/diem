import DiemSwiftCrypto
import Testing

@Suite("EncryptedSignedMessage") struct EncryptedSignedMessageTests {
  let backend = SwiftCryptoBackend()

  // MARK: - Encrypt and decrypt+verify

  @Test func classicEncryptDecryptVerify() throws {
    let alice = try Identity(name: "Alice", cryptoSets: [.classic], using: backend)
    let bob = try Identity(name: "Bob", cryptoSets: [.classic], using: backend)
    let payload: CBOR = .textString("hello, Bob")
    let signed = try alice.sign(payload, cryptoSet: .classic)
    let msg = try EncryptedSignedMessage.encrypt(
      signed, to: bob.profile, cryptoSet: .classic, using: backend)
    if case .profileKey(let cryptoSet, _, _) = msg.message.recipient {
      #expect(cryptoSet == .classic)
    } else {
      Issue.record("Expected profileKey recipient type")
    }
    let result = try msg.decryptAndVerify(using: bob, senderProfile: alice.profile)
    #expect(result.payload == payload)
    #expect(result.cryptoSet == .classic)
  }

  @Test func pqcEncryptDecryptVerify() throws {
    let alice = try Identity(name: "Alice", cryptoSets: [.pqc], using: backend)
    let bob = try Identity(name: "Bob", cryptoSets: [.pqc], using: backend)
    let payload: CBOR = .textString("pqc hello, Bob")
    let signed = try alice.sign(payload, cryptoSet: .pqc)
    let msg = try EncryptedSignedMessage.encrypt(
      signed, to: bob.profile, cryptoSet: .pqc, using: backend)
    if case .profileKey(let cryptoSet, _, _) = msg.message.recipient {
      #expect(cryptoSet == .pqc)
    } else {
      Issue.record("Expected profileKey recipient type")
    }
    let result = try msg.decryptAndVerify(using: bob, senderProfile: alice.profile)
    #expect(result.payload == payload)
  }

  @Test func encryptToSpecificKey() throws {
    let alice = try Identity(name: "Alice", cryptoSets: [.classic], using: backend)
    let bob = try Identity(name: "Bob", cryptoSets: [.classic], using: backend)
    let bobKA = bob.profile.keys.first(where: {
      $0.keyType == .keyAgreement && $0.cryptoSet == .classic
    })!
    let signed = try alice.sign(.unsignedInt(1), cryptoSet: .classic)
    let msg = try EncryptedSignedMessage.encrypt(signed, to: bobKA, using: backend)
    let result = try msg.decryptAndVerify(using: bob, senderProfile: alice.profile)
    #expect(result.payload == .unsignedInt(1))
  }

  // MARK: - decryptAndVerifyPayload

  @Test func decryptAndVerifyPayloadViaSenderProfile() throws {
    let alice = try Identity(name: "Alice", cryptoSets: [.classic], using: backend)
    let bob = try Identity(name: "Bob", cryptoSets: [.classic], using: backend)
    let payload: CBOR = .textString("payload shortcut")
    let msg = try alice.signAndEncrypt(payload, to: bob.profile)
    let extracted = try msg.decryptAndVerifyPayload(using: bob, senderProfile: alice.profile)
    #expect(extracted == payload)
  }

  @Test func decryptAndVerifyPayloadViaSigningKey() throws {
    let alice = try Identity(name: "Alice", cryptoSets: [.classic], using: backend)
    let bob = try Identity(name: "Bob", cryptoSets: [.classic], using: backend)
    let aliceSigKey = alice.profile.keys.first(where: {
      $0.keyType == .signing && $0.cryptoSet == .classic
    })!
    let payload: CBOR = .unsignedInt(99)
    let msg = try alice.signAndEncrypt(payload, to: bob.profile)
    let extracted = try msg.decryptAndVerifyPayload(using: bob, against: aliceSigKey)
    #expect(extracted == payload)
  }

  // MARK: - Identity.signAndEncrypt

  @Test func identitySignAndEncryptDefaultCryptoSet() throws {
    let alice = try Identity(name: "Alice", using: backend)
    let bob = try Identity(name: "Bob", using: backend)
    let payload: CBOR = .textString("sign and encrypt")
    let msg = try alice.signAndEncrypt(payload, to: bob.profile)
    // Both have all keys; negotiation should pick PQC (higher priority).
    if case .profileKey(let cryptoSet, _, _) = msg.message.recipient {
      #expect(cryptoSet == .pqc)
    } else {
      Issue.record("Expected profileKey recipient type")
    }
    let result = try msg.decryptAndVerify(using: bob, senderProfile: alice.profile)
    #expect(result.payload == payload)
    #expect(result.cryptoSet == .pqc)
  }

  @Test func identitySignAndEncryptPQC() throws {
    let alice = try Identity(name: "Alice", cryptoSets: [.pqc], using: backend)
    let bob = try Identity(name: "Bob", cryptoSets: [.pqc], using: backend)
    let payload: CBOR = .textString("pqc sign and encrypt")
    let msg = try alice.signAndEncrypt(payload, to: bob.profile, cryptoSet: .pqc)
    let result = try msg.decryptAndVerify(using: bob, senderProfile: alice.profile)
    #expect(result.payload == payload)
    #expect(result.cryptoSet == .pqc)
  }

  // MARK: - Verify against specific key

  @Test func decryptAndVerifyAgainstSpecificKey() throws {
    let alice = try Identity(name: "Alice", cryptoSets: [.classic], using: backend)
    let bob = try Identity(name: "Bob", cryptoSets: [.classic], using: backend)
    let aliceSigKey = alice.profile.keys.first(where: {
      $0.keyType == .signing && $0.cryptoSet == .classic
    })!
    let msg = try alice.signAndEncrypt(.textString("hi Bob"), to: bob.profile)
    let result = try msg.decryptAndVerify(using: bob, against: aliceSigKey)
    #expect(result.payload == .textString("hi Bob"))
  }

  // MARK: - CBOR round-trip

  @Test func cborRoundtrip() throws {
    let alice = try Identity(name: "Alice", cryptoSets: [.classic], using: backend)
    let bob = try Identity(name: "Bob", cryptoSets: [.classic], using: backend)
    let msg = try alice.signAndEncrypt(.unsignedInt(42), to: bob.profile)
    let decoded = try EncryptedSignedMessage.decode(msg.encode())
    #expect(decoded.message.recipient == msg.message.recipient)
    #expect(decoded.message.ciphertext == msg.message.ciphertext)
    let result = try decoded.decryptAndVerifyPayload(using: bob, senderProfile: alice.profile)
    #expect(result == .unsignedInt(42))
  }

  // MARK: - Error cases

  @Test func wrongRecipientCannotDecrypt() throws {
    let alice = try Identity(name: "Alice", cryptoSets: [.classic], using: backend)
    let bob = try Identity(name: "Bob", cryptoSets: [.classic], using: backend)
    let carol = try Identity(name: "Carol", cryptoSets: [.classic], using: backend)
    let msg = try alice.signAndEncrypt(.textString("for Bob"), to: bob.profile)
    #expect(throws: DiemError.keyNotFound) {
      _ = try msg.decryptAndVerify(using: carol, senderProfile: alice.profile)
    }
  }

  @Test func wrongSenderProfileThrowsKeyNotFound() throws {
    let alice = try Identity(name: "Alice", cryptoSets: [.classic], using: backend)
    let bob = try Identity(name: "Bob", cryptoSets: [.classic], using: backend)
    let carol = try Identity(name: "Carol", cryptoSets: [.classic], using: backend)
    let msg = try alice.signAndEncrypt(.textString("from Alice"), to: bob.profile)
    #expect(throws: DiemError.keyNotFound) {
      _ = try msg.decryptAndVerify(using: bob, senderProfile: carol.profile)
    }
  }

  @Test func wrongSigningKeyThrowsVerificationFailed() throws {
    let alice = try Identity(name: "Alice", cryptoSets: [.classic], using: backend)
    let bob = try Identity(name: "Bob", cryptoSets: [.classic], using: backend)
    let carol = try Identity(name: "Carol", cryptoSets: [.classic], using: backend)
    let carolSigKey = carol.profile.keys.first(where: {
      $0.keyType == .signing && $0.cryptoSet == .classic
    })!
    let msg = try alice.signAndEncrypt(.textString("from Alice"), to: bob.profile)
    #expect(throws: DiemError.verificationFailed) {
      _ = try msg.decryptAndVerify(using: bob, against: carolSigKey)
    }
  }

  // MARK: - Crypto set negotiation

  @Test func negotiationPicksPQCWhenBothSupport() throws {
    let alice = try Identity(name: "Alice", using: backend)
    let bob = try Identity(name: "Bob", using: backend)
    let msg = try alice.signAndEncrypt(.textString("negotiated"), to: bob.profile)
    if case .profileKey(let cryptoSet, _, _) = msg.message.recipient {
      #expect(cryptoSet == .pqc)
    } else {
      Issue.record("Expected profileKey recipient type")
    }
    let result = try msg.decryptAndVerify(using: bob, senderProfile: alice.profile)
    #expect(result.cryptoSet == .pqc)
  }

  @Test func negotiationFallsBackToClassicWhenRecipientLacksPQC() throws {
    let alice = try Identity(name: "Alice", using: backend)
    let bob = try Identity(name: "Bob", cryptoSets: [.classic], using: backend)
    let msg = try alice.signAndEncrypt(.textString("classic fallback"), to: bob.profile)
    if case .profileKey(let cryptoSet, _, _) = msg.message.recipient {
      #expect(cryptoSet == .classic)
    } else {
      Issue.record("Expected profileKey recipient type")
    }
    let result = try msg.decryptAndVerify(using: bob, senderProfile: alice.profile)
    #expect(result.cryptoSet == .classic)
  }

  @Test func negotiationFallsBackToClassicWhenSenderLacksPQC() throws {
    let alice = try Identity(name: "Alice", cryptoSets: [.classic], using: backend)
    let bob = try Identity(name: "Bob", using: backend)
    let msg = try alice.signAndEncrypt(.textString("classic fallback"), to: bob.profile)
    if case .profileKey(let cryptoSet, _, _) = msg.message.recipient {
      #expect(cryptoSet == .classic)
    } else {
      Issue.record("Expected profileKey recipient type")
    }
    let result = try msg.decryptAndVerify(using: bob, senderProfile: alice.profile)
    #expect(result.cryptoSet == .classic)
  }

  @Test func negotiationThrowsWhenNoCommonSet() throws {
    // Build a profile that only advertises an imaginary unsupported set by giving it no
    // key-agreement keys at all — easiest proxy for "no shared set".
    let alice = try Identity(name: "Alice", cryptoSets: [.classic], using: backend)
    let bob = try Identity(name: "Bob", cryptoSets: [.pqc], using: backend)
    #expect(throws: DiemError.keyNotFound) {
      _ = try alice.signAndEncrypt(.textString("no match"), to: bob.profile)
    }
  }

  @Test func encryptedMessageNegotiationPicksPQC() throws {
    let alice = try Identity(name: "Alice", using: backend)
    let payload: CBOR = .textString("encrypted negotiate")
    let msg = try EncryptedMessage.encrypt(payload, to: alice.profile, using: backend)
    if case .profileKey(let cryptoSet, _, _) = msg.recipient {
      #expect(cryptoSet == .pqc)
    } else {
      Issue.record("Expected profileKey recipient type")
    }
    let decrypted = try alice.decrypt(msg)
    #expect(decrypted == payload)
  }

  @Test func encryptedSignedMessageStaticNegotiation() throws {
    let alice = try Identity(name: "Alice", using: backend)
    let bob = try Identity(name: "Bob", using: backend)
    let signed = try alice.sign(.textString("static negotiate"), cryptoSet: .classic)
    let msg = try EncryptedSignedMessage.encrypt(signed, to: bob.profile, using: backend)
    if case .profileKey(let cryptoSet, _, _) = msg.message.recipient {
      #expect(cryptoSet == .pqc)
    } else {
      Issue.record("Expected profileKey recipient type")
    }
    let result = try msg.decryptAndVerify(using: bob, senderProfile: alice.profile)
    #expect(result.payload == .textString("static negotiate"))
  }
}
