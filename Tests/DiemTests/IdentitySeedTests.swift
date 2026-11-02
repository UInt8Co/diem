@testable import Diem
import DiemSwiftCrypto
import Foundation
import Testing

@Suite struct IdentitySeedTests {
  let backend = TestBackend()

  @Test func committedVectorsEncodeDecodeAndDerive() async throws {
    struct Fixture: Decodable {
      struct Vector: Decodable {
        let entropy, phrase: String
        let seed, identityKey: [String: String]
        struct Sealed: Decodable { let encoding, recipientPrivateKey: String }
        let sealed: [Sealed]
      }
      struct Equivalent: Decodable { let entropy, phrase: String }
      let vectors: [Vector]
      let equivalent: [Equivalent]
      let invalid: [String]
    }
    func bytes(_ hex: String) -> [UInt8] {
      stride(from: 0, to: hex.count, by: 2).map {
        UInt8(hex.dropFirst($0).prefix(2), radix: 16)!
      }
    }
    let url = URL(filePath: #filePath).deletingLastPathComponent()
      .appending(path: "../Vectors/identity-seed.json")
    let fixture = try JSONDecoder().decode(Fixture.self, from: Data(contentsOf: url))
    for vector in fixture.vectors {
      let seed = try IdentitySeed(entropy: bytes(vector.entropy))
      #expect(seed.phrase == vector.phrase)
      #expect(try IdentitySeed(phrase: vector.phrase).entropy == seed.entropy)
      for algorithm: PublicKey.Algorithm in [.ed25519, .mlDSA65] {
        let code = String(algorithm.rawValue)
        #expect(try seed.seed(for: algorithm) == bytes(vector.seed[code]!))
        let key = try await seed.identityKey(algorithm, using: backend)
        #expect(key.publicKey.key.encoding == bytes(vector.identityKey[code]!))
        #expect(key.protection == .software)
      }
      for box in vector.sealed {
        let sealed = try SealedIdentitySeed(encoding: bytes(box.encoding))
        let recipient = try await backend.makeEncryptionKey(.p256, restoring: bytes(box.recipientPrivateKey))
        #expect(try await sealed.open(with: recipient, using: backend).entropy == seed.entropy)
      }
    }
    for vector in fixture.equivalent {
      #expect(try IdentitySeed(phrase: vector.phrase).entropy == bytes(vector.entropy))
    }
    for phrase in fixture.invalid {
      #expect(throws: DiemError.invalidEncoding) { try IdentitySeed(phrase: phrase) }
    }
  }

  @Test func generatedPhrasesRoundTrip() throws {
    let seed = try IdentitySeed.generate(using: backend)
    #expect(seed.words.count == IdentitySeed.wordCount)
    #expect(try IdentitySeed(phrase: seed.phrase).entropy == seed.entropy)
    #expect(throws: DiemError.invalidKey) { try IdentitySeed(entropy: [UInt8](repeating: 0, count: 16)) }
    #expect(throws: DiemError.unsupportedAlgorithm) { try seed.seed(for: .p256) }
  }

  @Test(arguments: [PublicKey.Algorithm.ed25519, .mlDSA65])
  func recoveryCertifiesAFreshDevice(algorithm: PublicKey.Algorithm) async throws {
    let seed = try IdentitySeed.generate(using: backend)
    let key = try await seed.identityKey(algorithm, using: backend)
    let owner = try await TestIdentity(.data([1]), identityKey: key,
      deviceKey: .generate(using: backend), using: backend)
    let restored = try IdentitySeed(phrase: seed.phrase)
    let matching = try await restored.identityKey(matching: owner.profile.identityKey, using: backend)
    let device = try await DevicePrivateKey.generate(.p256, using: backend)
    let profile = try await owner.profile.enrolling(device, identityKey: matching, using: backend)
    try await profile.verify(using: backend)
    #expect(profile.devices.count == 2)
    #expect(profile.id == owner.profile.id)
    let wrong = try IdentitySeed.generate(using: backend)
    await #expect(throws: DiemError.identityMismatch) {
      try await wrong.identityKey(matching: key.publicKey, using: backend)
    }
    await #expect(throws: DiemError.unsupportedAlgorithm) {
      try await seed.identityKey(.p256, using: backend)
    }
  }
}
