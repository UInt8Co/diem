import Diem
import DiemSwiftCrypto
import Foundation

/// Swift Crypto at a fixed time, so the fixture's validity periods are stable.
struct FixedTime: CryptoBackend {
  let base = SwiftCryptoBackend()
  let now: UInt64
  func randomBytes(count: Int) -> [UInt8] { base.randomBytes(count: count) }
  func makePrivateKey(
    _ algorithm: PublicKey.Algorithm, for purpose: PublicKey.Purpose, restoring raw: [UInt8]?
  ) async throws -> PrivateKey
  { try await base.makePrivateKey(algorithm, for: purpose, restoring: raw) }
  func isValidSignature(_ signature: [UInt8], for message: [UInt8], by key: PublicKey)
    async throws -> Bool
  { try await base.isValidSignature(signature, for: message, by: key) }
  func makeEncryptionKey(_ algorithm: EncryptionPublicKey.Algorithm, restoring raw: [UInt8]?)
    async throws -> EncryptionPrivateKey
  { try await base.makeEncryptionKey(algorithm, restoring: raw) }
  func seal(_ plaintext: [UInt8], to key: EncryptionPublicKey, context: [UInt8]) async throws
    -> SealedBox
  { try await base.seal(plaintext, to: key, context: context) }
}

extension [UInt8] {
  var hex: String { map { String(format: "%02x", $0) }.joined() }
}

let backend = FixedTime(now: 1_800_000_000)
if CommandLine.arguments.contains("--identity-seed") {
  let url = URL(fileURLWithPath: "Tests/Vectors/identity-seed.json")
  var fixture = try JSONSerialization.jsonObject(with: Data(contentsOf: url)) as! [String: Any]
  var result: [[String: Any]] = []
  for var vector in fixture["vectors"] as! [[String: Any]] {
    let hex = vector["entropy"] as! String
    let entropy = stride(from: 0, to: hex.count, by: 2).map {
      UInt8(hex.dropFirst($0).prefix(2), radix: 16)!
    }
    let seed = try IdentitySeed(entropy: entropy)
    var contexts: [String: String] = [:], seeds: [String: String] = [:]
    var keys: [String: String] = [:], sealed: [[String: String]] = []
    for algorithm: PublicKey.Algorithm in [.ed25519, .mlDSA65] {
      let code = String(algorithm.rawValue)
      let key = try await seed.identityKey(algorithm, using: backend)
      contexts[code] = CBOR.record([0: .text("Diem/identity-seed"), 1: .unsigned(1),
        2: .unsigned(1), 3: .unsigned(algorithm.rawValue)]).encoded.hex
      seeds[code] = key.rawRepresentation!.hex
      keys[code] = key.publicKey.key.encoding.hex
      let recipient = try await backend.makeEncryptionKey(.p256)
      let box = try await seed.sealed(to: recipient.publicKey, identity: key.publicKey, using: backend)
      sealed.append([
        "encoding": box.encoding.hex,
        "context": CBOR.record([0: .text("Diem/sealed-identity-seed"), 1: .unsigned(1),
          2: .bytes(key.publicKey.key.encoding), 3: .bytes(recipient.publicKey.encoding)]).encoded.hex,
        "encapsulatedKey": box.box.encapsulatedKey.hex, "ciphertext": box.box.ciphertext.hex,
        "recipientPublicKey": recipient.publicKey.rawRepresentation.hex,
        "recipientPrivateKey": recipient.rawRepresentation!.hex,
      ])
    }
    vector["context"] = contexts; vector["seed"] = seeds; vector["identityKey"] = keys
    vector["sealed"] = sealed
    result.append(vector)
  }
  fixture["vectors"] = result
  let json = try JSONSerialization.data(withJSONObject: fixture, options: [.prettyPrinted, .sortedKeys])
  print(String(decoding: json, as: UTF8.self))
} else {
  var vectors: [[String: Any]] = []
  for algorithm: PublicKey.Algorithm in [.mlDSA65, .ed25519, .p256] {
    let root = try await backend.makePrivateKey(algorithm, for: .identity)
    let identityKey = try IdentityPrivateKey(root)
    let deviceKey = try await DevicePrivateKey.generate(algorithm, using: backend)
    let identity = try await BasicIdentity<ProfileRecord>(
      ProfileFields(domains: [DomainName("vectors.example")],
        application: [ProfileFields.firstApplicationKey: .bytes(Array("cross-language profile".utf8))]),
      identityKey: identityKey, deviceKey: deviceKey, using: backend)
    let profile = identity.profile
    let proof = try await identity.prove(Array("cross-language proof".utf8))
    vectors.append([
      "algorithm": algorithm.rawValue,
      "identityKey": profile.identityKey.key.encoding.hex,
      "identityID": profile.id.bytes.hex,
      "deviceKey": deviceKey.publicKey.key.encoding.hex,
      "deviceID": deviceKey.publicKey.id.bytes.hex,
      "certificateMessage": profile.devices[0].signedMessage.message.hex,
      "certificateSignature": profile.devices[0].signedMessage.signature.hex,
      "contentMessage": profile.signedContent.message.hex,
      "contentSignature": profile.signedContent.signature.hex,
      "profile": profile.encoding.hex,
      "proofMessage": proof.signedMessage.message.hex,
      "proofSignature": proof.signedMessage.signature.hex,
      "proof": proof.encoding.hex,
    ])
  }
  let json = try JSONSerialization.data(
    withJSONObject: ["protocol": "Diem/v4", "now": backend.now, "vectors": vectors],
    options: [.prettyPrinted, .sortedKeys])
  print(String(decoding: json, as: UTF8.self))

}
