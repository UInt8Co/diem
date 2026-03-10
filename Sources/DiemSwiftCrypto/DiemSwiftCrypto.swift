@_exported import Diem
import Crypto

/// A convenience type alias for ``Identity`` backed by ``SwiftCryptoBackend``.
public typealias DiemIdentity = Identity<SwiftCryptoBackend>
