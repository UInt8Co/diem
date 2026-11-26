import Diem
import DiemTesting

typealias TestIdentity = BasicIdentity<ProfileRecord>

extension ProfileFields {
  /// Opaque test data in the first application field.
  static func data(_ bytes: [UInt8]) -> Self {
    Self(application: [firstApplicationKey: .bytes(bytes)])
  }
}
