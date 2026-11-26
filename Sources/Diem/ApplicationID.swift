/// The reverse-DNS name of an application, such as `com.example.notes`, which keys that
/// application's fields in Diem records.
///
/// A name has at least two labels separated by `.`. Each label is 1 to 63 bytes of
/// lowercase ASCII letters, digits and `-`, and neither starts nor ends with `-`; the first
/// label starts with a letter. The whole name is at most 253 bytes.
public struct ApplicationID: Hashable, Comparable, Sendable, CustomStringConvertible {
  public static let maximumLength = 253

  public let name: String

  /// `name`, if it is a valid application ID; otherwise ``DiemError/invalidEncoding``.
  public init(_ name: String) throws(DiemError) {
    guard Self.isValid(name) else { throw .invalidEncoding }
    self.name = name
  }

  /// Whether `name` is a valid application ID.
  public static func isValid(_ name: String) -> Bool {
    let bytes = name.utf8
    guard bytes.count <= maximumLength, let first = bytes.first, (97...122).contains(first) else {
      return false
    }
    // Byte checks keep validation ASCII-only and free of Unicode tables.
    let labels = bytes.split(separator: 46, omittingEmptySubsequences: false)
    return labels.count >= 2 && labels.allSatisfy { label in
      !label.isEmpty && label.count <= 63 && label.first != 45 && label.last != 45
        && label.allSatisfy { (97...122).contains($0) || (48...57).contains($0) || $0 == 45 }
    }
  }

  public var description: String { name }

  /// Byte order of the names, which is also their order as canonical CBOR map keys of
  /// equal length.
  public static func < (lhs: ApplicationID, rhs: ApplicationID) -> Bool {
    lhs.name.utf8.lexicographicallyPrecedes(rhs.name.utf8)
  }
}
