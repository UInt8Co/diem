// MARK: - Hex String Utilities

/// Converts an array of bytes to a lowercase hexadecimal string.
///
/// This is a Foundation-free implementation using manual hex conversion.
///
/// - Parameter bytes: The byte array to convert.
/// - Returns: A hexadecimal string representation of the bytes.
///
/// Example:
/// ```swift
/// let bytes: [UInt8] = [0x01, 0x02, 0xFF]
/// bytes.hexString // "0102ff"
/// ```
public func hexString(from bytes: [UInt8]) -> String {
  let hexDigits: [UInt8] = [
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,  // '0'-'7'
    0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66,  // '8'-'9', 'a'-'f'
  ]

  var result: [UInt8] = []
  result.reserveCapacity(bytes.count * 2)

  for byte in bytes {
    result.append(hexDigits[Int(byte >> 4)])
    result.append(hexDigits[Int(byte & 0x0F)])
  }

  return String(decoding: result, as: UTF8.self)
}

extension Array where Element == UInt8 {
  /// Returns a lowercase hexadecimal string representation of this byte array.
  public var hexString: String {
    DiemPortable.hexString(from: self)
  }
}
