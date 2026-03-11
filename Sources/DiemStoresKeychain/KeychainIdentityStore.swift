import CBOR
import DiemStores
import DiemSwiftCrypto

#if canImport(Security)
  import Security
  import Foundation

  /// A Keychain-backed ``IdentityStore`` for ``SwiftCryptoBackend`` identities.
  ///
  /// Each identity is stored as a `kSecClassGenericPassword` item:
  /// - `kSecAttrService`: the store's `service` identifier (configurable).
  /// - `kSecAttrAccount`: the identity's ``Profile/hexID``.
  /// - `kSecValueData`: CBOR-encoded bytes of the form `{0: profile_cbor_bytes, 1: [[key_id, priv_key], ...]}`.
  ///
  /// All Keychain operations use synchronous `SecItem*` calls on the calling thread.
  public final class KeychainIdentityStore: IdentityStore {
    public typealias Backend = SwiftCryptoBackend

    public let backend: SwiftCryptoBackend
    /// The Keychain service attribute value used to namespace items.
    public let service: String

    public init(backend: SwiftCryptoBackend = SwiftCryptoBackend(), service: String = "diem") {
      self.backend = backend
      self.service = service
    }

    // MARK: - IdentityStore

    public func store(_ identity: Identity<SwiftCryptoBackend>) throws {
      let hexID = identity.profile.hexID
      guard try keychainData(account: hexID) == nil else { throw DiemError.alreadyExists }
      let data = try serialize(identity)
      try keychainAdd(account: hexID, data: data)
    }

    public func update(_ identity: Identity<SwiftCryptoBackend>) throws {
      let hexID = identity.profile.hexID
      let data = try serialize(identity)
      if try keychainData(account: hexID) != nil {
        try keychainUpdate(account: hexID, data: data)
      } else {
        try keychainAdd(account: hexID, data: data)
      }
    }

    public func identity(for id: [UInt8]) throws -> Identity<SwiftCryptoBackend>? {
      let hexID = hexString(id)
      guard let data = try keychainData(account: hexID) else { return nil }
      return try deserialize(data)
    }

    public func allIdentities() throws -> [Identity<SwiftCryptoBackend>] {
      let query: [CFString: Any] = [
        kSecClass: kSecClassGenericPassword,
        kSecAttrService: service,
        kSecReturnAttributes: true,
        kSecReturnData: true,
        kSecMatchLimit: kSecMatchLimitAll,
      ]
      var result: CFTypeRef?
      let status = SecItemCopyMatching(query as CFDictionary, &result)
      guard status == errSecSuccess else {
        if status == errSecItemNotFound { return [] }
        throw DiemError.keyNotFound
      }
      guard let items = result as? [[CFString: Any]] else { return [] }
      return try items.compactMap { item in
        guard let data = item[kSecValueData] as? Data else { return nil }
        return try? deserialize([UInt8](data))
      }
    }

    public func remove(id: [UInt8]) throws {
      let hexID = hexString(id)
      let query: [CFString: Any] = [
        kSecClass: kSecClassGenericPassword,
        kSecAttrService: service,
        kSecAttrAccount: hexID,
      ]
      let status = SecItemDelete(query as CFDictionary)
      guard status == errSecSuccess || status == errSecItemNotFound else {
        throw DiemError.keyNotFound
      }
    }

    // MARK: - Serialisation

    /// CBOR wire format: {0: profile_cbor_bytes, 1: [[key_id, priv_key], ...]}
    private func serialize(_ identity: Identity<SwiftCryptoBackend>) throws -> [UInt8] {
      let profileBytes = identity.profile.encode()
      let privKeyPairs = identity.privateKeysByKeyID.map { (id, privKey) in
        CBOR.array([
          .byteString(ArraySlice(id)),
          .byteString(ArraySlice(privKey)),
        ])
      }
      let cbor = CBOR.map([
        CBORMapPair(key: .unsignedInt(0), value: .byteString(ArraySlice(profileBytes))),
        CBORMapPair(key: .unsignedInt(1), value: .array(privKeyPairs)),
      ])
      return cbor.encode()
    }

    private func deserialize(_ bytes: [UInt8]) throws -> Identity<SwiftCryptoBackend> {
      let cbor: CBOR
      do { cbor = try CBOR.decode(bytes) } catch { throw DiemError.invalidCBOR }
      guard let pairs = try cbor.mapValue() else { throw DiemError.invalidCBOR }
      var profileBytes: [UInt8]?
      var privKeyMap: [[UInt8]: [UInt8]] = [:]
      for pair in pairs {
        guard case .unsignedInt(let k) = pair.key else { continue }
        switch k {
        case 0:
          profileBytes = pair.value.byteStringValue()
        case 1:
          let elements = try pair.value.arrayValue() ?? []
          for elem in elements {
            guard let arr = try elem.arrayValue(), arr.count == 2,
              let keyID = arr[0].byteStringValue(),
              let privKey = arr[1].byteStringValue()
            else { continue }
            privKeyMap[keyID] = privKey
          }
        default: break
        }
      }
      guard let profileBytes else { throw DiemError.missingField("profile bytes") }
      let profile = try Profile.decode(profileBytes)
      return Identity(profile: profile, privateKeysByKeyID: privKeyMap, using: backend)
    }

    // MARK: - Keychain helpers

    private func keychainData(account: String) throws -> [UInt8]? {
      let query: [CFString: Any] = [
        kSecClass: kSecClassGenericPassword,
        kSecAttrService: service,
        kSecAttrAccount: account,
        kSecReturnData: true,
        kSecMatchLimit: kSecMatchLimitOne,
      ]
      var result: CFTypeRef?
      let status = SecItemCopyMatching(query as CFDictionary, &result)
      if status == errSecItemNotFound { return nil }
      guard status == errSecSuccess, let data = result as? Data else {
        throw DiemError.keyNotFound
      }
      return [UInt8](data)
    }

    private func keychainAdd(account: String, data: [UInt8]) throws {
      let query: [CFString: Any] = [
        kSecClass: kSecClassGenericPassword,
        kSecAttrService: service,
        kSecAttrAccount: account,
        kSecValueData: Data(data),
      ]
      let status = SecItemAdd(query as CFDictionary, nil)
      guard status == errSecSuccess else { throw DiemError.encryptionFailed }
    }

    private func keychainUpdate(account: String, data: [UInt8]) throws {
      let query: [CFString: Any] = [
        kSecClass: kSecClassGenericPassword,
        kSecAttrService: service,
        kSecAttrAccount: account,
      ]
      let attributes: [CFString: Any] = [kSecValueData: Data(data)]
      let status = SecItemUpdate(query as CFDictionary, attributes as CFDictionary)
      guard status == errSecSuccess else { throw DiemError.keyNotFound }
    }

    private func hexString(_ bytes: [UInt8]) -> String {
      bytes.reduce(into: "") { result, byte in
        let hi = (byte >> 4) & 0x0F
        let lo = byte & 0x0F
        result.append(Character(UnicodeScalar(hi < 10 ? 48 &+ hi : 87 &+ hi)))
        result.append(Character(UnicodeScalar(lo < 10 ? 48 &+ lo : 87 &+ lo)))
      }
    }
  }
#endif
