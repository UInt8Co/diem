import DiemPortable
import Testing

@Suite struct CanonicalCBORTests {
  @Test func integerAndContainerBoundaries() throws {
    let values: [CBOR] = [
      .unsignedInt(0), .unsignedInt(23), .unsignedInt(24), .unsignedInt(255),
      .unsignedInt(256), .unsignedInt(65535), .unsignedInt(65536),
      .unsignedInt(4_294_967_295), .unsignedInt(4_294_967_296), .unsignedInt(.max),
      .negativeInt(-1), .negativeInt(-24), .negativeInt(.min),
      .byteString([]), .textString("😀 ß"), .array([]), .map([]), .bool(false), .bool(true), .null,
    ]
    for value in values {
      #expect(try CanonicalCBOR.decode(value.encode()) == value)
      #expect(throws: DiemError.invalidCBOR) { try CanonicalCBOR.decode(value.encode() + [0]) }
    }
    for count in [23, 24, 255, 256, 65535, 65536] {
      let value = CBOR.byteString(ArraySlice(repeating: 7, count: count))
      #expect(try CanonicalCBOR.decode(value.encode()) == value)
    }
  }
  @Test func mapOrderingAndDuplicateRejection() throws {
    let map = CBOR.map([
      .init(key: .textString("aa"), value: .unsignedInt(1)),
      .init(key: .unsignedInt(0), value: .unsignedInt(2)),
      .init(key: .textString("b"), value: .unsignedInt(3)),
    ])
    #expect(
      try CanonicalCBOR.decode(map.encode()).encode() == [
        0xa3, 0, 2, 0x61, 0x62, 3, 0x62, 0x61, 0x61, 1,
      ])
    let duplicate = CBOR.map([
      .init(key: .unsignedInt(0), value: .null), .init(key: .unsignedInt(0), value: .null),
    ])
    #expect(throws: DiemError.invalidCBOR) { try CanonicalCBOR.encode(duplicate) }
  }
  @Test func deterministicMalformedInputCorpusIsBounded() throws {
    var state: UInt64 = 0x656e_6572_6174_6f72
    for count in 0..<10_000 {
      let bytes: [UInt8] = (0..<(count % 64)).map { _ in
        state = state &* 6_364_136_223_846_793_005 &+ 1
        return UInt8(truncatingIfNeeded: state >> 32)
      }
      if let value = try? CanonicalCBOR.decode(bytes) {
        #expect(value.encode() == bytes)
      }
    }
    #expect(throws: DiemError.invalidCBOR) {
      try CanonicalCBOR.decode([0x3b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff])
    }
  }
}
