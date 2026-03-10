import Crypto
@_exported import Diem

/// A convenience type alias for ``Identity`` backed by ``SwiftCryptoBackend``.
public typealias DiemIdentity = Identity<SwiftCryptoBackend>
