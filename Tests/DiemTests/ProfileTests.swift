import DiemSwiftCrypto
import Testing

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
    let profileID = [UInt8](repeating: 0x01, count: 16)
    let profile = Profile(
      id: profileID,
      keys: [keyEntry],
      name: "Alice",
      createdAt: 1_700_000_000,
      expiresAt: 1_800_000_000,
      extensions: extensions
    )
    let decoded = try Profile.decode(profile.encode())
    #expect(decoded.id == profileID)
    #expect(decoded.name == "Alice")
    #expect(decoded.createdAt == 1_700_000_000)
    #expect(decoded.expiresAt == 1_800_000_000)
    #expect(decoded.keys.count == 1)
    #expect(decoded.keys[0].id == keyEntry.id)
    #expect(decoded.keys[0].keyType == .signing)
    #expect(decoded.keys[0].cryptoSet == .classic)
    #expect(decoded.keys[0].rawBytes == keyEntry.rawBytes)
  }

  @Test func hexID() {
    let profile = Profile(id: [0x00, 0xFF, 0xAB, 0x12], keys: [], name: "Test")
    #expect(profile.hexID == "00ffab12")
  }

  @Test func pqcKeyRoundtrip() throws {
    let keyEntry = PublicKeyEntry(
      id: [UInt8](repeating: 0x11, count: 32),
      keyType: .keyAgreement,
      cryptoSet: .pqc,
      rawBytes: [UInt8](repeating: 0x22, count: 64)
    )
    let profile = Profile(
      id: [UInt8](repeating: 0x02, count: 16), keys: [keyEntry], name: "PQC User")
    let decoded = try Profile.decode(profile.encode())
    #expect(decoded.keys[0].cryptoSet == .pqc)
    #expect(decoded.keys[0].keyType == .keyAgreement)
  }

  @Test func missingFieldThrows() throws {
    let empty = CBOR.map([])
    #expect(throws: DiemError.missingField("Profile: id, keys, or name missing")) {
      _ = try Profile.fromCBOR(empty)
    }
  }
}
