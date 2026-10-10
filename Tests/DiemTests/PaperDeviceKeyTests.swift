import Diem
import DiemSwiftCrypto
import Foundation
import Testing

@Suite struct PaperDeviceKeyTests {
  let backend = TestBackend()

  @Test func committedVectorsEncodeDecodeAndDerive() async throws {
    struct Fixture: Decodable {
      struct Vector: Decodable {
        let entropy, phrase: String
        let seed, deviceKey: [String: String]
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
      .appending(path: "../Vectors/paper-device-key.json")
    let fixture = try JSONDecoder().decode(Fixture.self, from: Data(contentsOf: url))
    for vector in fixture.vectors {
      let paper = try PaperDeviceKey(entropy: bytes(vector.entropy))
      #expect(paper.phrase == vector.phrase)
      #expect(try PaperDeviceKey(phrase: vector.phrase).entropy == paper.entropy)
      for algorithm: PublicKey.Algorithm in [.ed25519, .mlDSA65] {
        let code = String(algorithm.rawValue)
        #expect(try paper.seed(for: algorithm) == bytes(vector.seed[code]!))
        let key = try await paper.deviceKey(algorithm, using: backend)
        #expect(key.publicKey.key.encoding == bytes(vector.deviceKey[code]!))
        #expect(key.protection == .software)
      }
    }
    for vector in fixture.equivalent {
      #expect(try PaperDeviceKey(phrase: vector.phrase).entropy == bytes(vector.entropy))
    }
    for phrase in fixture.invalid {
      #expect(throws: DiemError.invalidEncoding) { try PaperDeviceKey(phrase: phrase) }
    }
  }

  @Test func generatedPhrasesRoundTrip() throws {
    let paper = try PaperDeviceKey.generate(using: backend)
    #expect(paper.words.count == PaperDeviceKey.wordCount)
    #expect(try PaperDeviceKey(phrase: paper.phrase).entropy == paper.entropy)
    #expect(throws: DiemError.invalidKey) { try PaperDeviceKey(entropy: [UInt8](repeating: 0, count: 16)) }
    #expect(throws: DiemError.unsupportedAlgorithm) { try paper.seed(for: .p256) }
  }

  @Test(arguments: [PublicKey.Algorithm.ed25519, .mlDSA65])
  func aListedPaperProvesUntilItIsRemoved(algorithm: PublicKey.Algorithm) async throws {
    var owner = try await TestIdentity(.data([1]), using: backend)
    let paper = try PaperDeviceKey.generate(using: backend)
    try await owner.add(paper.deviceKey(algorithm, using: backend).publicKey)

    let restored = try PaperDeviceKey(phrase: paper.phrase)
    let key = try await restored.deviceKey(listedIn: owner.profile, using: backend)
    #expect(key.publicKey.key.algorithm == algorithm)
    let signedIn = try await TestIdentity(profile: owner.profile, deviceKey: key, using: backend)
    try await signedIn.prove([7]).verify(against: owner.profile, using: backend)
    // A device key cannot manage the device set.
    await #expect(throws: DiemError.identityKeyRequired) {
      try await signedIn.adding(DevicePrivateKey.generate(using: backend).publicKey)
    }

    // Renewal by a device holding the identity key keeps the paper certified.
    backend.advance(by: DeviceCertificate.defaultLifetime - 60)
    try await owner.renew()
    backend.advance(by: 120)
    #expect(try await restored.deviceKey(listedIn: owner.profile, using: backend).publicKey
      == key.publicKey)
    try await owner.profile.verify(using: backend)

    try await owner.remove(key.publicKey.id)
    await #expect(throws: DiemError.deviceNotListed) {
      try await restored.deviceKey(listedIn: owner.profile, using: backend)
    }
  }
}
