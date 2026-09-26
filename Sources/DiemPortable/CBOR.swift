/// Diem's deterministic CBOR subset, independent of Foundation and platform APIs.
/// Network decoding always goes through the bounded CanonicalCBOR validator.
public indirect enum CBOR: Sendable, Equatable {
  case unsignedInt(UInt64)
  case negativeInt(Int64)
  case byteString(ArraySlice<UInt8>)
  case textString(String)
  case array([CBOR])
  case map([CBORMapPair])
  case bool(Bool)
  case null

  public func byteStringValue() -> [UInt8]? {
    guard case .byteString(let value) = self else { return nil }
    return Array(value)
  }
  public func textStringValue() -> [UInt8]? {
    guard case .textString(let value) = self else { return nil }
    return Array(value.utf8)
  }
  public func arrayValue() throws(DiemError) -> [CBOR]? {
    guard case .array(let value) = self else { return nil }
    return value
  }
  public func mapValue() throws(DiemError) -> [CBORMapPair]? {
    guard case .map(let value) = self else { return nil }
    return value
  }
  public func encode() -> [UInt8] {
    var output: [UInt8] = []
    append(to: &output)
    return output
  }
  public static func decode(_ encoded: [UInt8]) throws(DiemError) -> Self {
    try CanonicalCBOR.decode(encoded)
  }

  private func append(to output: inout [UInt8]) {
    func head(_ major: UInt8, _ n: UInt64) -> [UInt8] {
      if n < 24 { return [(major << 5) | UInt8(n)] }
      let length: Int = n <= 255 ? 1 : n <= 65535 ? 2 : n <= 4_294_967_295 ? 4 : 8
      let tag: UInt8 = length == 1 ? 24 : length == 2 ? 25 : length == 4 ? 26 : 27
      return [(major << 5) | tag]
        + (0..<length).reversed().map { UInt8(truncatingIfNeeded: n >> ($0 * 8)) }
    }
    switch self {
    case .unsignedInt(let n): output += head(0, n)
    case .negativeInt(let n):
      precondition(n < 0, "CBOR negativeInt must be negative")
      output += head(1, UInt64(-(n + 1)))
    case .byteString(let b):
      output += head(2, UInt64(b.count))
      output += b
    case .textString(let s):
      let b = Array(s.utf8)
      output += head(3, UInt64(b.count))
      output += b
    case .array(let values):
      output += head(4, UInt64(values.count))
      for value in values { value.append(to: &output) }
    case .map(let pairs):
      let sorted = pairs.map { ($0.key.encode(), $0.value) }.sorted {
        $0.0.count != $1.0.count ? $0.0.count < $1.0.count : $0.0.lexicographicallyPrecedes($1.0)
      }
      output += head(5, UInt64(sorted.count))
      for (key, value) in sorted {
        output += key
        value.append(to: &output)
      }
    case .bool(let b): output.append(b ? 0xf5 : 0xf4)
    case .null: output.append(0xf6)
    }
  }

  /// Called only after the allocation/depth/canonical validation pass.
  package static func decodeValidated(_ input: [UInt8]) throws(DiemError) -> Self {
    var offset = 0
    func read() throws(DiemError) -> Self {
      let first = input[offset]
      offset += 1
      let major = first >> 5
      let extra = first & 31
      if major == 7 { return extra == 22 ? .null : .bool(extra == 21) }
      var n = UInt64(extra)
      if extra >= 24 {
        n = 0
        for _ in 0..<(1 << (extra - 24)) {
          n = n << 8 | UInt64(input[offset])
          offset += 1
        }
      }
      switch major {
      case 0: return .unsignedInt(n)
      case 1:
        guard n <= UInt64(Int64.max) else { throw DiemError.invalidCBOR }
        return .negativeInt(-1 - Int64(n))
      case 2, 3:
        let b = input[offset..<(offset + Int(n))]
        offset += Int(n)
        return major == 2 ? .byteString(b) : .textString(String(decoding: b, as: UTF8.self))
      case 4:
        var values: [CBOR] = []
        for _ in 0..<n { values.append(try read()) }
        return .array(values)
      case 5:
        var pairs: [CBORMapPair] = []
        for _ in 0..<n { pairs.append(try CBORMapPair(key: read(), value: read())) }
        return .map(pairs)
      default: throw DiemError.invalidCBOR
      }
    }
    return try read()
  }
}

public struct CBORMapPair: Sendable, Equatable {
  public let key: CBOR
  public let value: CBOR
  public init(key: CBOR, value: CBOR) {
    self.key = key
    self.value = value
  }
}
