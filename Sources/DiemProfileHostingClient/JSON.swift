// RFC 8259 syntax; number tokens stay decimal text until a schema requests an integer.
indirect enum JSON: Equatable {
  case object([String: JSON]), array([JSON]), string(String), number(String), bool(Bool), null

  static let maximumBytes = 262_144
  static let maximumDepth = 16

  init(_ bytes: [UInt8]) throws(ProfileHostingError) {
    guard bytes.count <= Self.maximumBytes else { throw .invalidResponse }
    var reader = Reader(bytes: bytes)
    self = try reader.value(depth: 0)
    reader.whitespace()
    guard reader.offset == bytes.count else { throw .invalidResponse }
  }

  func object() throws(ProfileHostingError) -> [String: JSON] {
    guard case .object(let value) = self else { throw .invalidResponse }
    return value
  }

  func array() throws(ProfileHostingError) -> [JSON] {
    guard case .array(let value) = self else { throw .invalidResponse }
    return value
  }

  func string() throws(ProfileHostingError) -> String {
    guard case .string(let value) = self else { throw .invalidResponse }
    return value
  }

  func integer() throws(ProfileHostingError) -> Int64 {
    guard case .number(let text) = self, let value = Int64(text) else {
      throw .invalidResponse
    }
    return value
  }

  func unsigned() throws(ProfileHostingError) -> UInt64 {
    guard case .number(let text) = self, let value = UInt64(text) else {
      throw .invalidResponse
    }
    return value
  }

  private struct Reader {
    let bytes: [UInt8]
    var offset = 0
    var next: UInt8? { offset < bytes.count ? bytes[offset] : nil }

    mutating func whitespace() {
      while let b = next, b == 32 || b == 9 || b == 10 || b == 13 { offset += 1 }
    }

    mutating func take(_ b: UInt8) -> Bool {
      guard next == b else { return false }
      offset += 1
      return true
    }

    mutating func require(_ b: UInt8) throws(ProfileHostingError) {
      guard take(b) else { throw .invalidResponse }
    }

    mutating func value(depth: Int) throws(ProfileHostingError) -> JSON {
      guard depth <= JSON.maximumDepth else { throw .invalidResponse }
      whitespace()
      guard let first = next else { throw .invalidResponse }
      switch first {
      case 123:
        offset += 1
        whitespace()
        var entries: [String: JSON] = [:]
        if take(125) { return .object(entries) }
        repeat {
          whitespace()
          let key = try text()
          guard entries[key] == nil else { throw .invalidResponse }
          whitespace()
          try require(58)
          entries[key] = try value(depth: depth + 1)
          whitespace()
          if take(125) { return .object(entries) }
          try require(44)
        } while true
      case 91:
        offset += 1
        whitespace()
        var values: [JSON] = []
        if take(93) { return .array(values) }
        repeat {
          values.append(try value(depth: depth + 1))
          whitespace()
          if take(93) { return .array(values) }
          try require(44)
        } while true
      case 34: return .string(try text())
      case 116: try literal("true"); return .bool(true)
      case 102: try literal("false"); return .bool(false)
      case 110: try literal("null"); return .null
      case 45, 48...57: return .number(try number())
      default: throw .invalidResponse
      }
    }

    mutating func literal(_ text: String) throws(ProfileHostingError) {
      for b in text.utf8 { try require(b) }
    }

    mutating func digits() throws(ProfileHostingError) {
      let start = offset
      while let b = next, (48...57).contains(b) { offset += 1 }
      guard offset > start else { throw .invalidResponse }
    }

    mutating func number() throws(ProfileHostingError) -> String {
      let start = offset
      _ = take(45)
      if !take(48) { try digits() }
      if take(46) { try digits() }
      if take(101) || take(69) {
        if !take(43) { _ = take(45) }
        try digits()
      }
      return String(decoding: bytes[start..<offset], as: UTF8.self)
    }

    mutating func hex() throws(ProfileHostingError) -> UInt32 {
      var value: UInt32 = 0
      for _ in 0..<4 {
        guard let b = next else { throw .invalidResponse }
        offset += 1
        let digit: UInt8
        switch b {
        case 48...57: digit = b - 48
        case 65...70: digit = b - 55
        case 97...102: digit = b - 87
        default: throw .invalidResponse
        }
        value = value * 16 + UInt32(digit)
      }
      return value
    }

    mutating func text() throws(ProfileHostingError) -> String {
      try require(34)
      var output: [UInt8] = []
      while let b = next {
        offset += 1
        if b == 34 {
          let text = String(decoding: output, as: UTF8.self)
          guard Array(text.utf8) == output else { throw .invalidResponse }
          return text
        }
        guard b >= 32 else { throw .invalidResponse }
        if b != 92 { output.append(b); continue }
        guard let escape = next else { throw .invalidResponse }
        offset += 1
        switch escape {
        case 34, 92, 47: output.append(escape)
        case 98: output.append(8)
        case 102: output.append(12)
        case 110: output.append(10)
        case 114: output.append(13)
        case 116: output.append(9)
        case 117:
          var scalar = try hex()
          if (0xd800...0xdbff).contains(scalar) {
            try require(92)
            try require(117)
            let low = try hex()
            guard (0xdc00...0xdfff).contains(low) else { throw .invalidResponse }
            scalar = 0x10000 + (scalar - 0xd800) * 1024 + low - 0xdc00
          }
          guard let value = Unicode.Scalar(scalar) else { throw .invalidResponse }
          output += String(value).utf8
        default: throw .invalidResponse
        }
      }
      throw .invalidResponse
    }
  }
}

extension Dictionary where Key == String, Value == JSON {
  func field(_ name: String) throws(ProfileHostingError) -> JSON {
    guard let value = self[name] else { throw .invalidResponse }
    return value
  }
}
