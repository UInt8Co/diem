import Diem
import DiemTesting
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
  @Test func recordsKeyFieldsByIntegerOrApplicationID() throws {
    let notes = try ApplicationID("org.example.notes")
    let value = CBOR.record([0: .text("record"), 1: .unsigned(1), 100: .bool(true)],
      applications: [notes: .text("note")])
    let applicationEntry: [UInt8] = [0x71] + Array("org.example.notes".utf8) + [0x64] + Array("note".utf8)
    #expect(Array(value.encoded.suffix(23)) == applicationEntry)
    let record = try value.recordValue(requiredKeys: 0..<2)
    #expect(record[100] == .bool(true) && record[notes] == .text("note"))
    #expect(record.value == value)
    #expect(try value.recordValue(tag: .text("record"), version: 1, requiredKeys: 0..<2) == record)
    #expect(throws: DiemError.invalidEncoding) {
      try value.recordValue(tag: .text("record"), version: 2, requiredKeys: 0..<2)
    }
    #expect(throws: DiemError.invalidEncoding) { try value.recordValue(requiredKeys: 0..<3) }
    let retained = record.extensions(above: 1)
    #expect(retained == CBOR.Record(fields: [100: .bool(true)], applications: [notes: .text("note")]))
    #expect(CBOR.record([0: .text("record"), 1: .unsigned(1)], retaining: retained) == value)
    // Keys are unsigned integers or application IDs; nothing else.
    for key: CBOR in [.text("0"), .text("notes"), .text("Org.example"), .negative(-1), .bytes([0]), .null] {
      #expect(throws: DiemError.invalidEncoding) {
        try CBOR.map([key: .unsigned(1)]).recordValue(requiredKeys: 0..<0)
      }
    }
  }

  @Test func applicationIDsAreReverseDNSNames() throws {
    for name in ["com.blahim", "org.example.notes", "a.b", "x1.y-2.z3"] {
      #expect(try ApplicationID(name).name == name)
    }
    for name in ["", "com", "Com.example", "1com.example", "-com.example", "com..example",
      "com.example.", "com.-example", "com.example-", "com.ex_ample", "com.exämple",
      "com." + String(repeating: "a", count: 64),
      String(repeating: "a.", count: 126) + "ab"] {
      #expect(throws: DiemError.invalidEncoding) { try ApplicationID(name) }
    }
    #expect(try ApplicationID("com.b") < ApplicationID("com.blahim"))
  }

  @Test func publicKeyExtensionsRetainTheirIdentity() throws {
    let key = try PublicKey(purpose: .identity, algorithm: .ed25519,
      rawRepresentation: [UInt8](repeating: 7, count: 32))
    var fields = try CBOR(decoding: key.encoding).recordValue(requiredKeys: 0..<5)
    fields[100] = .text("future")
    fields[ApplicationID.test] = .text("annotation")
    let encoding = fields.value.encoded
    let decoded = try PublicKey(encoding: encoding)
    #expect(decoded.encoding == encoding)
    #expect(decoded.id == Digest(hashing: encoding))
    #expect(decoded.id != key.id)
  }

  @Test func profileExtensionsKeepSignedContentVerifiable() async throws {
    let backend = TestBackend()
    let identity = try await TestIdentity(.data([]), using: backend)
    var fields = try CBOR(decoding: identity.profile.encoding).recordValue(requiredKeys: 0..<5)
    fields[100] = .text("future")
    fields[ApplicationID.test] = .text("annotation")
    let encoded = fields.value.encoded
    let profile = try ProfileRecord(encoding: encoded)
    try await profile.verify(using: backend)
    #expect(profile.encoding == encoded)
    #expect(profile.digest == identity.profile.digest)
  }
}
