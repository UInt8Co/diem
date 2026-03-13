import CBOR
import Diem
import DiemStores
import DiemSwiftCrypto

#if canImport(Security)
  import Foundation
  import Security

  /// A Keychain-backed ``/DiemStores/ShareStore`` for ``/Diem/EncryptedShare`` storage.
  ///
  /// Each encrypted share is stored as a `kSecClassGenericPassword` item:
  /// - `kSecAttrService`: the store's `service` identifier (configurable).
  /// - `kSecAttrAccount`: the share's ``/Diem/EncryptedShare/hexID``.
  /// - `kSecValueData`: CBOR-encoded bytes of the share.
  ///
  /// All Keychain operations use synchronous `SecItem*` calls on the calling thread.
  public final class KeychainShareStore: ShareStore {
    /// Configuration for Keychain storage behavior.
    public struct Configuration: Sendable {
      /// The Keychain service attribute value used to namespace items.
      public let service: String

      /// Whether to enable data protection (kSecAttrAccessible).
      /// When true, uses `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`.
      /// When false, uses `kSecAttrAccessibleAlways`.
      public let useDataProtection: Bool

      /// Whether items should sync via iCloud Keychain.
      /// Sets `kSecAttrSynchronizable`.
      public let syncable: Bool

      /// The accessibility level for Keychain items.
      /// Only used when `useDataProtection` is true.
      public let accessibility: Accessibility

      /// Keychain accessibility levels.
      public enum Accessibility: Sendable {
        /// Data accessible after first unlock, this device only (most secure).
        case afterFirstUnlockThisDeviceOnly
        /// Data accessible after first unlock, may sync.
        case afterFirstUnlock
        /// Data accessible when unlocked, this device only.
        case whenUnlockedThisDeviceOnly
        /// Data accessible when unlocked, may sync.
        case whenUnlocked
        /// Data accessible always (least secure, deprecated by Apple).
        case always

        fileprivate var cfValue: CFString {
          switch self {
          case .afterFirstUnlockThisDeviceOnly:
            return kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
          case .afterFirstUnlock:
            return kSecAttrAccessibleAfterFirstUnlock
          case .whenUnlockedThisDeviceOnly:
            return kSecAttrAccessibleWhenUnlockedThisDeviceOnly
          case .whenUnlocked:
            return kSecAttrAccessibleWhenUnlocked
          case .always:
            return kSecAttrAccessibleAlways
          }
        }
      }

      public init(
        service: String = "diem.shares",
        useDataProtection: Bool = true,
        syncable: Bool = false,
        accessibility: Accessibility = .afterFirstUnlockThisDeviceOnly
      ) {
        self.service = service
        self.useDataProtection = useDataProtection
        self.syncable = syncable
        self.accessibility = accessibility
      }
    }

    public let backend: SwiftCryptoBackend
    public let configuration: Configuration

    public init(
      backend: SwiftCryptoBackend = SwiftCryptoBackend(),
      configuration: Configuration = Configuration()
    ) {
      self.backend = backend
      self.configuration = configuration
    }

    // MARK: - ShareStore

    public func store(_ share: EncryptedShare) throws {
      let hexID = share.hexID
      guard try keychainData(account: hexID) == nil else { throw DiemError.alreadyExists }
      let data = share.encode()
      try keychainAdd(account: hexID, data: data)
    }

    public func update(_ share: EncryptedShare) throws -> Bool {
      let hexID = share.hexID
      let data = share.encode()
      if try keychainData(account: hexID) != nil {
        try keychainUpdate(account: hexID, data: data)
        return true
      } else {
        return false
      }
    }

    public func share(for keyID: [UInt8]) throws -> EncryptedShare? {
      let hexID = hexString(keyID)
      guard let data = try keychainData(account: hexID) else { return nil }
      return try EncryptedShare.decode(data, using: backend)
    }

    public func allShares() throws -> [EncryptedShare] {
      let query: [CFString: Any] = [
        kSecClass: kSecClassGenericPassword,
        kSecAttrService: configuration.service,
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
      return items.compactMap { item in
        guard let data = item[kSecValueData] as? Data else { return nil }
        return try? EncryptedShare.decode([UInt8](data), using: backend)
      }
    }

    public func remove(keyID: [UInt8]) throws {
      let hexID = hexString(keyID)
      let query: [CFString: Any] = [
        kSecClass: kSecClassGenericPassword,
        kSecAttrService: configuration.service,
        kSecAttrAccount: hexID,
      ]
      let status = SecItemDelete(query as CFDictionary)
      guard status == errSecSuccess || status == errSecItemNotFound else {
        throw DiemError.keyNotFound
      }
    }

    // MARK: - Keychain helpers

    private func keychainData(account: String) throws -> [UInt8]? {
      let query: [CFString: Any] = [
        kSecClass: kSecClassGenericPassword,
        kSecAttrService: configuration.service,
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
      var query: [CFString: Any] = [
        kSecClass: kSecClassGenericPassword,
        kSecAttrService: configuration.service,
        kSecAttrAccount: account,
        kSecValueData: Data(data),
      ]

      // Add accessibility if data protection is enabled
      if configuration.useDataProtection {
        query[kSecAttrAccessible] = configuration.accessibility.cfValue
      } else {
        query[kSecAttrAccessible] = kSecAttrAccessibleAlways
      }

      // Add syncable attribute
      query[kSecAttrSynchronizable] = configuration.syncable

      let status = SecItemAdd(query as CFDictionary, nil)
      guard status == errSecSuccess else { throw DiemError.encryptionFailed }
    }

    private func keychainUpdate(account: String, data: [UInt8]) throws {
      let query: [CFString: Any] = [
        kSecClass: kSecClassGenericPassword,
        kSecAttrService: configuration.service,
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
