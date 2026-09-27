import Diem
import DiemSwiftCrypto
import Testing

@Suite struct CryptoPrimitiveTests {
  let backend = SwiftCryptoBackend()

  @Test func sha2MatchesFIPSVectors() {
    func hex(_ bytes: [UInt8]) -> String {
      bytes.map { ($0 < 16 ? "0" : "") + String($0, radix: 16) }.joined()
    }
    #expect(hex(SHA2.sha256([])) == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    #expect(hex(SHA2.sha256(Array("abc".utf8))) == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
    #expect(
      hex(SHA2.sha256(Array("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq".utf8)))
        == "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1")
    #expect(
      hex(SHA2.sha512(Array("abc".utf8)))
        == "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f")
    #expect(
      hex(SHA2.sha512([UInt8](repeating: 0x61, count: 1_000_000))).hasPrefix("e718483d0ce76964"))
  }

  @Test(arguments: PublicKey.Algorithm.allCases)
  func signedMessagesVerifyOnlyAgainstTheirKey(algorithm: PublicKey.Algorithm) async throws {
    let key = try await backend.makePrivateKey(algorithm, for: .device)
    let other = try await backend.makePrivateKey(algorithm, for: .device)
    let signed = try await SignedMessage(signing: Array("hello".utf8), with: key)
    let decoded = try SignedMessage(encoding: signed.encoding)
    try await decoded.verify(by: key.publicKey, using: backend)
    await #expect(throws: DiemError.invalidSignature) {
      try await decoded.verify(by: other.publicKey, using: backend)
    }
    let tampered = SignedMessage(message: Array("hellp".utf8), signature: signed.signature)
    await #expect(throws: DiemError.invalidSignature) {
      try await tampered.verify(by: key.publicKey, using: backend)
    }
    #expect(decoded.digest == Digest(hashing: Array("hello".utf8)))
  }

  @Test func softwareKeysRestoreFromTheirSecret() async throws {
    for algorithm in PublicKey.Algorithm.allCases {
      let key = try await backend.makePrivateKey(algorithm, for: .identity)
      let restored = try await backend.makePrivateKey(
        algorithm, for: .identity, restoring: key.rawRepresentation)
      #expect(restored.publicKey == key.publicKey && restored.protection == .software)
    }
    for algorithm in EncryptionPublicKey.Algorithm.allCases {
      let key = try await backend.makeEncryptionKey(algorithm)
      let restored = try await backend.makeEncryptionKey(algorithm, restoring: key.rawRepresentation)
      #expect(restored.publicKey == key.publicKey)
    }
  }

  @Test func defaultsArePostQuantum() async throws {
    #expect(try await backend.makePrivateKey(for: .device).publicKey.algorithm == .mlDSA65)
    #expect(try await backend.makeEncryptionKey().publicKey.algorithm == .xWing)
    #expect(try await IdentityPrivateKey.generate(using: backend).publicKey.key.algorithm == .mlDSA65)
    #expect(try await DevicePrivateKey.generate(using: backend).publicKey.key.algorithm == .mlDSA65)
  }

  @Test func publicKeyEncodingIsPurposeAndAlgorithmQualified() async throws {
    let key = try await backend.makePrivateKey(.ed25519, for: .device).publicKey
    #expect(try PublicKey(encoding: key.encoding) == key)
    #expect(key.id == Digest(hashing: key.encoding))
    // The same key material for another purpose is another key with another ID.
    let asIdentity = try PublicKey(
      purpose: .identity, algorithm: .ed25519, rawRepresentation: key.rawRepresentation)
    #expect(asIdentity != key && asIdentity.id != key.id)
    let encryption = try await backend.makeEncryptionKey(.x25519).publicKey
    // Same length, different role: the purpose and algorithm codes keep the roles apart.
    #expect(throws: DiemError.invalidKey) { try PublicKey(encoding: encryption.encoding) }
    #expect(throws: DiemError.invalidKey) { try EncryptionPublicKey(encoding: key.encoding) }
    #expect(throws: DiemError.invalidKey) {
      try PublicKey(purpose: .device, algorithm: .p256, rawRepresentation: [UInt8](repeating: 5, count: 65))
    }
  }

  @Test func keysActOnlyForTheirPurpose() async throws {
    let identityKey = try await backend.makePrivateKey(for: .identity)
    let deviceKey = try await backend.makePrivateKey(for: .device)
    #expect(throws: DiemError.invalidKey) { try DevicePrivateKey(identityKey) }
    #expect(throws: DiemError.invalidKey) { try IdentityPrivateKey(deviceKey) }
    #expect(throws: DiemError.invalidKey) { try DevicePublicKey(identityKey.publicKey) }
    #expect(throws: DiemError.invalidKey) { try IdentityPublicKey(deviceKey.publicKey) }
  }

  @Test(arguments: EncryptionPublicKey.Algorithm.allCases)
  func sealedBoxesOpenOnlyWithTheirContext(algorithm: EncryptionPublicKey.Algorithm) async throws {
    let key = try await backend.makeEncryptionKey(algorithm)
    let box = try await backend.seal([1, 2, 3], to: key.publicKey, context: [9])
    #expect(try await key.open(box, context: [9]) == [1, 2, 3])
    await #expect(throws: DiemError.decryptionFailed) { try await key.open(box, context: [8]) }
  }
}
