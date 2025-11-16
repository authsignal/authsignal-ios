import Foundation
import Security

class KeyManager {
  private let keyTagPrefix = "authsignal_signing_key"
  private let keyTag: String
  
  init(keySuffix: String) {
    keyTag = "\(keyTagPrefix)_\(keySuffix)"
  }
  
  func getKey(username: String? = nil) -> SecKey? {
    let userKeyTag = getUserKeyTag(username: username)
    let legacyKeyTag = getLegacyKeyTag()
    
    // Fall back to legacy key tag for backwards compatibility
    return loadKey(tag: userKeyTag) ?? loadKey(tag: legacyKeyTag)
  }

  func getOrCreatePublicKey(
    keychainAccess: KeychainAccess,
    userPresenceRequired: Bool = false,
    username: String? = nil
  ) -> String? {
    let publicKey = getPublicKey(username: username)

    if publicKey != nil {
      return publicKey
    }

    return createKey(
      keychainAccess: keychainAccess,
      userPresenceRequired: userPresenceRequired,
      username: username
    )
  }

  func getPublicKey(username: String? = nil) -> String? {
    guard let secKey = getKey(username: username) else {
      return nil
    }

    return derivePublicKey(secKey: secKey)
  }

  func deleteKeyPair(username: String? = nil) -> Bool {
    let userKeyTag = getUserKeyTag(username: username)

    let success = deleteKey(tag: userKeyTag)
    
    if (success) {
      return true
    }
    
    // Fall back to deleting legacy key
    let legacyKeyTag =  getLegacyKeyTag()
    
    return deleteKey(tag: legacyKeyTag)
  }

  func derivePublicKey(secKey: SecKey) -> String? {
    guard let publicKey = SecKeyCopyPublicKey(secKey) else {
      Logger.error("Error copying public key")

      return nil
    }

    var error: Unmanaged<CFError>?

    guard let cfdata = SecKeyCopyExternalRepresentation(publicKey, &error) else {
      Logger.error("Error exporting public key")

      return nil
    }

    let publicKeyDER = createSubjectPublicKeyInfo(rawPublicKeyData: cfdata as Data)

    return publicKeyDER.base64EncodedString()
  }
  
  private func createKey(
    keychainAccess: KeychainAccess,
    userPresenceRequired: Bool,
    username: String? = nil
  ) -> String? {
    let flags: SecAccessControlCreateFlags = userPresenceRequired == true ? [.privateKeyUsage, .userPresence] : [.privateKeyUsage]
    
    let access = SecAccessControlCreateWithFlags(
      kCFAllocatorDefault,
      getAccessibilitySecAttr(keychainAccess: keychainAccess),
      flags,
      nil)!

    let userKeyTag = getUserKeyTag(username: username)

    let attributes: [String: Any] = [
      kSecAttrKeyType as String: kSecAttrKeyTypeEC,
      kSecAttrKeySizeInBits as String: 256,
      kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
      kSecPrivateKeyAttrs as String: [
        kSecAttrIsPermanent as String: true,
        kSecAttrApplicationTag as String: userKeyTag.data(using: .utf8)!,
        kSecAttrAccessControl as String: access,
      ] as [String: Any],
    ]

    var error: Unmanaged<CFError>?

    guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
      let err = error!.takeRetainedValue() as Error

      print(err)

      return nil
    }

    return derivePublicKey(secKey: privateKey)
  }
  
  private func deleteKey(tag: String) -> Bool {
    let query: [String: Any] = [
      kSecClass as String: kSecClassKey,
      kSecAttrApplicationTag as String: tag.data(using: .utf8)!,
      kSecAttrKeyType as String: kSecAttrKeyTypeEC,
      kSecReturnRef as String: true,
    ]

    let status = SecItemDelete(query as CFDictionary)

    guard status == errSecSuccess else {
      return false
    }

    return true
  }

  private func loadKey(tag: String) -> SecKey? {
    let query: [String: Any] = [
      kSecClass as String: kSecClassKey,
      kSecAttrApplicationTag as String: tag.data(using: .utf8)!,
      kSecAttrKeyType as String: kSecAttrKeyTypeEC,
      kSecReturnRef as String: true,
    ]

    var item: CFTypeRef?

    let status = SecItemCopyMatching(query as CFDictionary, &item)

    guard status == errSecSuccess else {
      return nil
    }

    return (item as! SecKey)
  }

  private func createSubjectPublicKeyInfo(rawPublicKeyData: Data) -> Data {
    let secp256r1Header = Data(_: [
      0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08,
      0x2a,
      0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
    ])

    return secp256r1Header + rawPublicKeyData
  }
  
  private func getAccessibilitySecAttr(keychainAccess: KeychainAccess) -> CFString {
    switch keychainAccess {
    case .afterFirstUnlock:
      return kSecAttrAccessibleAfterFirstUnlock
    case .afterFirstUnlockThisDeviceOnly:
      return kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
    case .whenUnlockedThisDeviceOnly:
      return kSecAttrAccessibleWhenUnlockedThisDeviceOnly
    case .whenUnlocked:
      return kSecAttrAccessibleWhenUnlocked
    case .whenPasscodeSetThisDeviceOnly:
      return kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly
    }
  }
  
  private func getUserKeyTag(username: String?) -> String {
    let cleanUsername = username?
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .replacingOccurrences(of: "[^A-Za-z0-9_-]", with: "-", options: .regularExpression)
    
    return cleanUsername.map { "\(keyTag)_\($0)" } ?? keyTag
  }
  
  private func getLegacyKeyTag() -> String {
    return keyTagPrefix
  }
}
