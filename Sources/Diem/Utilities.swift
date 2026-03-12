// MARK: - Hex String Utilities

/// Converts an array of bytes to a lowercase hexadecimal string.
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
  bytes.map { String(format: "%02x", $0) }.joined()
}

extension Array where Element == UInt8 {
  /// Returns a lowercase hexadecimal string representation of this byte array.
  public var hexString: String {
    Diem.hexString(from: self)
  }
}
