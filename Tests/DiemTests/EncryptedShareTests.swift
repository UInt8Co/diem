import DiemSwiftCrypto
import Testing

@Suite("EncryptedShare") struct EncryptedShareTests {
  let backend = SwiftCryptoBackend()

  @Test func generateShare() throws {
    let share = EncryptedShare.generate(using: backend)
    #expect(share.crypto == .aes256gcm)
    #expect(share.key.count == 32)  // AES-256 uses 32-byte keys
    #expect(share.keyID.count == 32)
  }

  @Test func encryptDecrypt() throws {
    let share = EncryptedShare.generate(using: backend)
    let payload: CBOR = .textString("hello, world")
    let ciphertext = try share.encrypt(payload, using: backend)
    #expect(ciphertext.count > 0)
    let decrypted = try share.decrypt(ciphertext, using: backend)
    #expect(decrypted == payload)
  }

  @Test func encryptDecryptComplexPayload() throws {
    let share = EncryptedShare.generate(using: backend)
    let payload: CBOR = .map([
      CBORMapPair(key: .textString("name"), value: .textString("Alice")),
      CBORMapPair(key: .textString("age"), value: .unsignedInt(30)),
      CBORMapPair(key: .textString("active"), value: .bool(true)),
    ])
    let ciphertext = try share.encrypt(payload, using: backend)
    let decrypted = try share.decrypt(ciphertext, using: backend)
    #expect(decrypted == payload)
  }

  @Test func wrongKeyDecryptionFails() throws {
    let share1 = EncryptedShare.generate(using: backend)
    let share2 = EncryptedShare.generate(using: backend)
    let payload: CBOR = .textString("secret")
    let ciphertext = try share1.encrypt(payload, using: backend)
    #expect(throws: DiemError.decryptionFailed) {
      _ = try share2.decrypt(ciphertext, using: backend)
    }
  }

  @Test func inviteToPublicKey() throws {
    let alice = try Identity(name: "Alice", cryptoSets: [.classic], using: backend)
    let aliceKA = alice.profile.keys.first(where: {
      $0.keyType == .keyAgreement && $0.cryptoSet == .classic
    })!

    let share = EncryptedShare.generate(using: backend)
    let invitation = try share.invite(aliceKA, using: backend)

    #expect(invitation.cryptoSet == .classic)
    #expect(invitation.recipientKeyID == aliceKA.id)
    #expect(invitation.encapsulatedKey != nil)
  }

  @Test func inviteToProfileWithCryptoSet() throws {
    let alice = try Identity(name: "Alice", cryptoSets: [.classic, .pqc], using: backend)
    let share = EncryptedShare.generate(using: backend)

    let invitation = try share.invite(alice.profile, cryptoSet: .classic, using: backend)
    #expect(invitation.cryptoSet == .classic)
  }

  @Test func inviteToProfileAutoNegotiation() throws {
    let alice = try Identity(name: "Alice", cryptoSets: [.classic, .pqc], using: backend)
    let share = EncryptedShare.generate(using: backend)

    let invitation = try share.invite(alice.profile, using: backend)
    // Should prefer PQC when both support it
    #expect(invitation.cryptoSet == .pqc)
  }

  @Test func inviteToProfileClassicOnly() throws {
    let alice = try Identity(name: "Alice", cryptoSets: [.classic], using: backend)
    let share = EncryptedShare.generate(using: backend)

    let invitation = try share.invite(alice.profile, using: backend)
    #expect(invitation.cryptoSet == .classic)
  }

  @Test func fromInvite() throws {
    let alice = try Identity(name: "Alice", cryptoSets: [.classic], using: backend)
    let share = EncryptedShare.generate(using: backend)

    let invitation = try share.invite(alice.profile, cryptoSet: .classic, using: backend)
    let receivedShare = try EncryptedShare.fromInvite(invitation, using: alice)

    #expect(receivedShare.crypto == share.crypto)
    #expect(receivedShare.key == share.key)
    #expect(receivedShare.keyID == share.keyID)
  }

  @Test func inviteAndUseShare() throws {
    let alice = try Identity(name: "Alice", cryptoSets: [.classic], using: backend)
    let bob = try Identity(name: "Bob", cryptoSets: [.classic], using: backend)

    // Create a share and encrypt a message
    let share = EncryptedShare.generate(using: backend)
    let payload: CBOR = .textString("shared secret message")
    let ciphertext = try share.encrypt(payload, using: backend)

    // Invite Alice and Bob
    let aliceInvite = try share.invite(alice.profile, using: backend)
    let bobInvite = try share.invite(bob.profile, using: backend)

    // Both should be able to accept and decrypt
    let aliceShare = try EncryptedShare.fromInvite(aliceInvite, using: alice)
    let bobShare = try EncryptedShare.fromInvite(bobInvite, using: bob)

    let aliceDecrypted = try aliceShare.decrypt(ciphertext, using: backend)
    let bobDecrypted = try bobShare.decrypt(ciphertext, using: backend)

    #expect(aliceDecrypted == payload)
    #expect(bobDecrypted == payload)
  }

  @Test func cborRoundtrip() throws {
    let share = EncryptedShare.generate(using: backend)
    let encoded = share.encode()
    let decoded = try EncryptedShare.decode(encoded)

    #expect(decoded.crypto == share.crypto)
    #expect(decoded.key == share.key)
    #expect(decoded.keyID == share.keyID)
  }

  @Test func compatibleCryptoSets() throws {
    #expect(EncryptedShare.Crypto.aes256gcm.compatibleCryptoSets == [.classic, .pqc])
  }

  @Test func encryptedMessageToShare() throws {
    let share = EncryptedShare.generate(using: backend)
    let payload: CBOR = .textString("test message")

    let message = try EncryptedMessage.encrypt(payload, to: share, using: backend)

    if case .share(let crypto, let shareKeyID) = message.recipientType {
      #expect(crypto == .aes256gcm)
      #expect(shareKeyID == share.keyID)
    } else {
      Issue.record("Expected share recipient type")
    }
  }

  @Test func encryptedMessageShareRoundtrip() throws {
    let share = EncryptedShare.generate(using: backend)
    let payload: CBOR = .unsignedInt(42)

    let message = try EncryptedMessage.encrypt(payload, to: share, using: backend)
    let encoded = message.encode()
    let decoded = try EncryptedMessage.decode(encoded)

    if case .share(let crypto, let shareKeyID) = decoded.recipientType {
      #expect(crypto == share.crypto)
      #expect(shareKeyID == share.keyID)
    } else {
      Issue.record("Expected share recipient type")
    }

    let decrypted = try share.decrypt(decoded.ciphertext, using: backend)
    #expect(decrypted == payload)
  }

  @Test func multipleRecipientsViaShare() throws {
    let alice = try Identity(name: "Alice", cryptoSets: [.classic], using: backend)
    let bob = try Identity(name: "Bob", cryptoSets: [.classic], using: backend)
    let charlie = try Identity(name: "Charlie", cryptoSets: [.pqc], using: backend)

    // Create a share
    let share = EncryptedShare.generate(using: backend)

    // Encrypt multiple messages for the group
    let message1: CBOR = .textString("First message")
    let message2: CBOR = .textString("Second message")
    let message3: CBOR = .textString("Third message")

    let encrypted1 = try EncryptedMessage.encrypt(message1, to: share, using: backend)
    let encrypted2 = try EncryptedMessage.encrypt(message2, to: share, using: backend)
    let encrypted3 = try EncryptedMessage.encrypt(message3, to: share, using: backend)

    // Send invitations to all recipients
    let aliceInvite = try share.invite(alice.profile, using: backend)
    let bobInvite = try share.invite(bob.profile, using: backend)
    let charlieInvite = try share.invite(charlie.profile, using: backend)

    // All recipients accept invitations
    let aliceShare = try EncryptedShare.fromInvite(aliceInvite, using: alice)
    let bobShare = try EncryptedShare.fromInvite(bobInvite, using: bob)
    let charlieShare = try EncryptedShare.fromInvite(charlieInvite, using: charlie)

    // All can decrypt all messages
    #expect(try aliceShare.decrypt(encrypted1.ciphertext, using: backend) == message1)
    #expect(try aliceShare.decrypt(encrypted2.ciphertext, using: backend) == message2)
    #expect(try aliceShare.decrypt(encrypted3.ciphertext, using: backend) == message3)

    #expect(try bobShare.decrypt(encrypted1.ciphertext, using: backend) == message1)
    #expect(try bobShare.decrypt(encrypted2.ciphertext, using: backend) == message2)
    #expect(try bobShare.decrypt(encrypted3.ciphertext, using: backend) == message3)

    #expect(try charlieShare.decrypt(encrypted1.ciphertext, using: backend) == message1)
    #expect(try charlieShare.decrypt(encrypted2.ciphertext, using: backend) == message2)
    #expect(try charlieShare.decrypt(encrypted3.ciphertext, using: backend) == message3)
  }

  @Test func mixedProfileAndShareMessages() throws {
    let alice = try Identity(name: "Alice", cryptoSets: [.classic], using: backend)
    let bob = try Identity(name: "Bob", cryptoSets: [.classic], using: backend)

    // Create a share and invite Alice
    let share = EncryptedShare.generate(using: backend)
    let aliceInvite = try share.invite(alice.profile, using: backend)
    let aliceShare = try EncryptedShare.fromInvite(aliceInvite, using: alice)

    // Send one message to the share (Alice can read)
    let sharedPayload: CBOR = .textString("group message")
    let sharedMessage = try EncryptedMessage.encrypt(sharedPayload, to: share, using: backend)

    // Send one message directly to Bob (only Bob can read)
    let bobPayload: CBOR = .textString("private message to Bob")
    let bobMessage = try EncryptedMessage.encrypt(bobPayload, to: bob.profile, using: backend)

    // Alice can decrypt the shared message
    #expect(try aliceShare.decrypt(sharedMessage.ciphertext, using: backend) == sharedPayload)

    // Bob can decrypt his private message
    #expect(try bob.decrypt(bobMessage) == bobPayload)

    // Verify message types are different
    if case .profile = bobMessage.recipientType {
      // Profile message - correct
    } else {
      Issue.record("Expected profile recipient type for bobMessage")
    }

    if case .share = sharedMessage.recipientType {
      // Share message - correct
    } else {
      Issue.record("Expected share recipient type for sharedMessage")
    }
  }
}
