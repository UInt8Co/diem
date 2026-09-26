/// The bounded deterministic CBOR subset used by signed records.
/// RFC 8949 length-first map ordering; no tags, floats, indefinite lengths or duplicates.
/// Validate before asking the lazy CBOR decoder to allocate or traverse a container.
public enum CanonicalCBOR {
  public static let maximumBytes = 262_144
  public static let maximumDepth = 16
  public static let maximumItems = 8_192

  public static func decode(_ bytes: [UInt8]) throws(DiemError) -> CBOR {
    guard bytes.count <= maximumBytes else { throw DiemError.invalidCBOR }
    var reader = Reader(bytes: bytes)
    try reader.value(depth: 0)
    guard reader.offset == bytes.count else { throw DiemError.invalidCBOR }
    return try CBOR.decodeValidated(bytes)
  }

  public static func encode(_ value: CBOR) throws(DiemError) -> [UInt8] {
    let bytes = value.encode()
    _ = try decode(bytes)
    return bytes
  }

  public static func array(_ bytes: [UInt8], count: Int) throws(DiemError) -> [CBOR] {
    guard let values = try decode(bytes).arrayValue(), values.count == count else {
      throw DiemError.invalidCBOR
    }
    return values
  }

  private struct Reader {
    let bytes: [UInt8]
    var offset = 0
    var items = 0

    mutating func byte() throws(DiemError) -> UInt8 {
      guard offset < bytes.count else { throw DiemError.invalidCBOR }
      defer { offset += 1 }
      return bytes[offset]
    }

    mutating func value(depth: Int) throws(DiemError) {
      items += 1
      guard depth <= maximumDepth, items <= maximumItems else { throw DiemError.invalidCBOR }
      let head = try byte()
      let major = head >> 5
      let extra = head & 31
      if major == 7 {
        guard (20...22).contains(extra) else { throw DiemError.invalidCBOR }
        return
      }
      guard major <= 5, extra <= 27 else { throw DiemError.invalidCBOR }
      var length = UInt64(extra)
      if extra >= 24 {
        length = 0
        for _ in 0..<(1 << (extra - 24)) { length = (length << 8) | UInt64(try byte()) }
        let minima: [UInt64] = [24, 256, 65_536, 4_294_967_296]
        guard length >= minima[Int(extra - 24)] else { throw DiemError.invalidCBOR }
      }
      if major <= 1 { return }
      guard length <= UInt64(bytes.count - offset) else { throw DiemError.invalidCBOR }
      switch major {
      case 2, 3:
        let end = offset + Int(length)
        if major == 3 {
          let raw = bytes[offset..<end]
          guard Array(String(decoding: raw, as: UTF8.self).utf8) == Array(raw) else {
            throw DiemError.invalidCBOR
          }
        }
        offset = end
      case 4:
        for _ in 0..<length { try value(depth: depth + 1) }
      case 5:
        var previous: ArraySlice<UInt8>?
        for _ in 0..<length {
          let start = offset
          try value(depth: depth + 1)
          let key = bytes[start..<offset]
          if let previous {
            guard
              previous.count < key.count
                || (previous.count == key.count && previous.lexicographicallyPrecedes(key))
            else {
              throw DiemError.invalidCBOR
            }
          }
          previous = key
          try value(depth: depth + 1)
        }
      default: throw DiemError.invalidCBOR
      }
    }
  }
}

// Fixed-position records remove ambiguous field aliases. Extensions use strict maps.
public func bytes(_ value: [UInt8]) -> CBOR { .byteString(ArraySlice(value)) }
public func uint(_ value: CBOR) throws(DiemError) -> UInt64 {
  guard case .unsignedInt(let v) = value else { throw DiemError.invalidCBOR }
  return v
}
public func octets(_ value: CBOR, count: Int? = nil) throws(DiemError) -> [UInt8] {
  guard let v = value.byteStringValue(), count == nil || v.count == count else {
    throw DiemError.invalidCBOR
  }
  return v
}
public func string(_ value: CBOR) throws(DiemError) -> String {
  guard let v = value.textStringValue() else { throw DiemError.invalidCBOR }
  return String(decoding: v, as: UTF8.self)
}
public func record(_ value: CBOR, count: Int) throws(DiemError) -> [CBOR] {
  guard let v = try value.arrayValue(), v.count == count else { throw DiemError.invalidCBOR }
  return v
}
