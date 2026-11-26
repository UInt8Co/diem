/// Strict unpadded base64url (RFC 4648 §5) without padding, line breaks or whitespace.
///
/// Decoding accepts only the canonical spelling: the URL-safe alphabet, no `=`, a length
/// that is not 1 modulo 4, and zero unused bits in the last character. Each byte string
/// therefore has exactly one accepted text form.
public enum Base64URL {
  private static let alphabet = Array(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_".utf8)

  /// The unpadded base64url text of `bytes`.
  public static func encode(_ bytes: some Sequence<UInt8>) -> String {
    var output: [UInt8] = []
    var buffer: UInt32 = 0
    var bits = 0
    for byte in bytes {
      buffer = buffer << 8 | UInt32(byte)
      bits += 8
      while bits >= 6 {
        bits -= 6
        output.append(alphabet[Int((buffer >> bits) & 63)])
      }
      buffer &= (1 << bits) - 1
    }
    if bits > 0 { output.append(alphabet[Int((buffer << (6 - bits)) & 63)]) }
    return String(decoding: output, as: UTF8.self)
  }

  /// The bytes that `text` canonically encodes, or nil. Text that would decode to more
  /// than `maximumBytes` is refused before decoding.
  public static func decode(_ text: String, maximumBytes: Int = .max) -> [UInt8]? {
    decode(utf8: text.utf8, maximumBytes: maximumBytes)
  }

  /// The bytes that the ASCII `utf8` canonically encodes, or nil.
  public static func decode(utf8 text: some Collection<UInt8>, maximumBytes: Int = .max)
    -> [UInt8]?
  {
    let count = text.count
    guard count % 4 != 1, count / 4 <= maximumBytes / 3,
      count / 4 * 3 + max(0, count % 4 - 1) <= maximumBytes
    else { return nil }
    var output: [UInt8] = []
    output.reserveCapacity(count / 4 * 3 + 2)
    var buffer: UInt32 = 0
    var bits = 0
    for character in text {
      let value: UInt8
      switch character {
      case 65...90: value = character - 65
      case 97...122: value = character - 71
      case 48...57: value = character + 4
      case 45: value = 62
      case 95: value = 63
      default: return nil
      }
      buffer = buffer << 6 | UInt32(value)
      bits += 6
      if bits >= 8 {
        bits -= 8
        output.append(UInt8(truncatingIfNeeded: buffer >> bits))
        buffer &= (1 << bits) - 1
      }
    }
    return buffer == 0 ? output : nil
  }
}
