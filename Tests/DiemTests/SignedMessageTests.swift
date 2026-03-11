import DiemSwiftCrypto
import Testing

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

  @Test func defaultCryptoSetIsClassic() throws {
    let alice = try Identity(name: "Alice", using: backend)
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
    #expect(throws: DiemError.keyNotFound) {
      _ = try msg.verify(using: bob.profile, with: backend)
    }
  }

  @Test func wrongCryptoSetKeyThrows() throws {
    let alice = try Identity(name: "Alice", using: backend)
    let classicMsg = try alice.sign(.textString("classic"), cryptoSet: .classic)
    let pqcKey = alice.profile.keys.first(where: {
      $0.keyType == .signing && $0.cryptoSet == .pqc
    })!
    #expect(throws: DiemError.invalidKeyType) {
      _ = try classicMsg.verify(against: pqcKey, using: backend)
    }
  }
}
