import Diem
import Testing

@Suite struct SealedIdentitySeedTests {
  let backend = TestBackend()

  @Test(arguments: [PublicKey.Algorithm.ed25519, .mlDSA65])
  func roundTripAndBinding(algorithm: PublicKey.Algorithm) async throws {
    let seed = try IdentitySeed.generate(using: backend)
    let identity = try await seed.identityKey(algorithm, using: backend).publicKey
    let recipient = try await backend.makeEncryptionKey(.p256)
    let sealed = try await seed.sealed(to: recipient.publicKey, identity: identity, using: backend)
    let decoded = try SealedIdentitySeed(encoding: sealed.encoding)
    #expect(decoded == sealed)
    #expect(try await decoded.open(with: recipient, using: backend).entropy == seed.entropy)
    let wrongRecipient = try await backend.makeEncryptionKey(.p256)
    await #expect(throws: DiemError.identityMismatch) {
      try await decoded.open(with: wrongRecipient, using: backend)
    }
    let other = try IdentitySeed.generate(using: backend)
    await #expect(throws: DiemError.identityMismatch) {
      try await other.sealed(to: recipient.publicKey, identity: identity, using: backend)
    }
    var fields = try CBOR(decoding: sealed.encoding).recordValue(requiredKeys: 0..<6)
    let context = CBOR.record(fields.filter { $0.key < 4 }).encoded
    for plaintext in [other.entropy, [UInt8](repeating: 0, count: 31)] {
      let box = try await backend.seal(plaintext, to: recipient.publicKey, context: context)
      fields[4] = .bytes(box.encapsulatedKey); fields[5] = .bytes(box.ciphertext)
      let invalid = try SealedIdentitySeed(encoding: CBOR.record(fields).encoded)
      await #expect(throws: DiemError.decryptionFailed) {
        try await invalid.open(with: recipient, using: backend)
      }
    }
    fields[1] = .unsigned(3)
    #expect(throws: DiemError.invalidEncoding) {
      try SealedIdentitySeed(encoding: CBOR.record(fields).encoded)
    }
    fields[1] = .unsigned(1)
    var ciphertext = sealed.box.ciphertext; ciphertext[0] ^= 1
    fields[4] = .bytes(sealed.box.encapsulatedKey); fields[5] = .bytes(ciphertext)
    let tampered = try SealedIdentitySeed(encoding: CBOR.record(fields).encoded)
    await #expect(throws: (any Error).self) {
      try await tampered.open(with: recipient, using: backend)
    }
  }
}
