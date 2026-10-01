import Diem
import Testing

@Suite struct CanonicalCBORTests {
  @Test func integerAndContainerBoundaries() throws {
    let values: [CBOR] = [
      .unsigned(0), .unsigned(23), .unsigned(24), .unsigned(255), .unsigned(256),
      .unsigned(65535), .unsigned(65536), .unsigned(4_294_967_295), .unsigned(4_294_967_296),
      .unsigned(.max), .negative(-1), .negative(-24), .negative(.min),
      .bytes([]), .text("😀 ß"), .array([]), .map([:]), .bool(false), .bool(true), .null,
    ]
    for value in values {
      #expect(try CBOR(decoding: value.encoded) == value)
      #expect(throws: DiemError.invalidEncoding) { try CBOR(decoding: value.encoded + [0]) }
    }
    for count in [23, 24, 255, 256, 65535, 65536] {
      let value = CBOR.bytes([UInt8](repeating: 7, count: count))
      #expect(try CBOR(decoding: value.encoded) == value)
    }
  }

  @Test func mapsEncodeInCanonicalKeyOrder() throws {
    let map = CBOR.map([.text("aa"): .unsigned(1), .unsigned(0): .unsigned(2), .text("b"): .unsigned(3)])
    #expect(map.encoded == [0xa3, 0, 2, 0x61, 0x62, 3, 0x62, 0x61, 0x61, 1])
    #expect(try CBOR(decoding: map.encoded) == map)
    // Out-of-order and duplicate keys.
    #expect(throws: DiemError.invalidEncoding) { try CBOR(decoding: [0xa2, 1, 0, 0, 0]) }
    #expect(throws: DiemError.invalidEncoding) { try CBOR(decoding: [0xa2, 0, 0, 0, 0]) }
  }

  @Test func rejectsNonCanonicalAndUnsupportedEncodings() {
    for malformed: [UInt8] in [
      [0x18, 0x00],  // non-minimal integer
      [0x9f, 0xff],  // indefinite array
      [0xf9, 0, 0],  // float
      [0xc0, 0],  // tag
      [0x62, 0xc3, 0x28],  // invalid UTF-8
      [0x3b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],  // below Int64.min
    ] {
      #expect(throws: DiemError.invalidEncoding) { try CBOR(decoding: malformed) }
    }
    let deep = [UInt8](repeating: 0x81, count: CBOR.maximumDepth + 1) + [0]
    #expect(throws: DiemError.invalidEncoding) { try CBOR(decoding: deep) }
  }

  @Test func deterministicMalformedInputCorpusIsBounded() {
    var state: UInt64 = 0x656e_6572_6174_6f72
    for count in 0..<10_000 {
      let bytes: [UInt8] = (0..<(count % 64)).map { _ in
        state = state &* 6_364_136_223_846_793_005 &+ 1
        return UInt8(truncatingIfNeeded: state >> 32)
      }
      if let value = try? CBOR(decoding: bytes) { #expect(value.encoded == bytes) }
    }
  }

  @Test func typedAccessorsRejectOtherShapes() throws {
    #expect(try CBOR.bytes([1, 2]).bytesValue(count: 2) == [1, 2])
    #expect(throws: DiemError.invalidEncoding) { try CBOR.bytes([1]).bytesValue(count: 2) }
    #expect(throws: DiemError.invalidEncoding) { try CBOR.text("1").unsignedValue() }
    #expect(throws: DiemError.invalidEncoding) { try CBOR.array([]).arrayValue(count: 1) }
  }
}

@Suite struct RecordEncodingTests {
  @Test func recordsRequireIntegerKeysAndRequiredFields() throws {
    let value = CBOR.record([0: .text("record"), 1: .unsigned(1), 100: .bool(true)])
    #expect(try value.recordValue(requiredKeys: 0..<2)[100] == .bool(true))
    #expect(throws: DiemError.invalidEncoding) { try value.recordValue(requiredKeys: 0..<3) }
    #expect(throws: DiemError.invalidEncoding) {
      try CBOR.map([.text("0"): .unsigned(1)]).recordValue(requiredKeys: 0..<1)
    }
    #expect(throws: DiemError.invalidEncoding) {
      try CBOR.map([.negative(-1): .unsigned(1)]).recordValue(requiredKeys: 0..<0)
    }
  }

  @Test func publicKeyExtensionsRetainTheirIdentity() throws {
    let key = try PublicKey(purpose: .identity, algorithm: .ed25519,
      rawRepresentation: [UInt8](repeating: 7, count: 32))
    var fields = try CBOR(decoding: key.encoding).recordValue(requiredKeys: 0..<5)
    fields[100] = .text("future")
    let encoding = CBOR.record(fields).encoded
    let decoded = try PublicKey(encoding: encoding)
    #expect(decoded.encoding == encoding)
    #expect(decoded.id == Digest(hashing: encoding))
    #expect(decoded.id != key.id)
  }

  @Test func profileExtensionsKeepSignedContentVerifiable() async throws {
    let backend = TestBackend()
    let identity = try await Identity(data: [], using: backend)
    var fields = try CBOR(decoding: identity.profile.encoding).recordValue(requiredKeys: 0..<5)
    fields[100] = .text("future")
    let encoded = CBOR.record(fields).encoded
    let profile = try Profile(encoding: encoded)
    try await profile.verify(using: backend)
    #expect(profile.encoding == encoded)
    #expect(profile.digest == identity.profile.digest)
  }
}
