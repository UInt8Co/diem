import Diem
import DiemTesting

typealias TestIdentity = BasicIdentity<ProfileRecord>

extension ApplicationID {
  /// The application whose field holds test data.
  static let test = try! ApplicationID("org.example.test")
}

extension ProfileFields {
  /// Opaque test data in the test application's field.
  static func data(_ bytes: [UInt8]) -> Self {
    Self(applications: [.test: .bytes(bytes)])
  }
}
