/// A DNS domain that can name a profile: at least two lowercase letter-digit-hyphen
/// labels of 1 to 63 bytes, 253 bytes in all.
public struct DomainName: Hashable, Sendable, CustomStringConvertible {
  public static let maximumLength = 253

  public let name: String

  /// `name`, if it is already a lowercase domain.
  public init(_ name: String) throws(DiemError) {
    guard Self.isValid(name) else { throw .invalidDomain }
    self.name = name
  }

  /// `raw` with ASCII letters lowercased, or `nil` when that is not a domain.
  public init?(normalizing raw: String) {
    // Only ASCII folds: Unicode lowercasing maps some non-ASCII letters, such as the
    // Kelvin sign, onto ASCII ones.
    let lowered = String(decoding: raw.utf8.map { (65...90).contains($0) ? $0 + 32 : $0 }, as: UTF8.self)
    try? self.init(lowered)
  }

  /// Whether `value` is a lowercase domain.
  public static func isValid(_ value: String) -> Bool {
    let bytes = value.utf8
    guard bytes.count <= maximumLength, bytes.contains(46) else {
      return false
    }
    // DNS wire names are ASCII. Byte validation avoids Unicode casing and grapheme tables.
    return bytes.split(separator: 46, omittingEmptySubsequences: false).allSatisfy { label in
      !label.isEmpty && label.count <= 63 && label.first != 45 && label.last != 45
        && label.allSatisfy { (97...122).contains($0) || (48...57).contains($0) || $0 == 45 }
    }
  }

  public var description: String { name }
}
