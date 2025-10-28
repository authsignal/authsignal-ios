import Foundation
import Security

class KeyManager {
  private let keyName = "authsignal_signing_key"
  private let scopedKeyName: String
  
  init(keySuffix: String) {
    scopedKeyName = "\(keyName)_\(keySuffix)"
  }
  
  func getKey() -> SecKey? {
    return loadKey(name: scopedKeyName) ?? loadKey(name: keyName)
  }

  func getOrCreatePublicKey(
    keychainAccess: KeychainAccess,
    userPresenceRequired: Bool = false,
  ) -> String? {
    let publicKey = getPublicKey()

    if publicKey != nil {
      return publicKey
    }

    return createKeyPair(
      keychainAccess: keychainAccess,
      userPresenceRequired: userPresenceRequired
    )
  }

  func getPublicKey() -> String? {
    guard let secKey = getKey() else {
      return nil
    }

    return derivePublicKey(secKey: secKey)
  }

  func createKeyPair(keychainAccess: KeychainAccess, userPresenceRequired: Bool) -> String? {
    let flags: SecAccessControlCreateFlags = userPresenceRequired == true ? [.privateKeyUsage, .userPresence] : [.privateKeyUsage]
    
    let access = SecAccessControlCreateWithFlags(
      kCFAllocatorDefault,
      getAccessibilitySecAttr(keychainAccess: keychainAccess),
      flags,
      nil)!

    let tag = scopedKeyName.data(using: .utf8)!

    let attributes: [String: Any] = [
      kSecAttrKeyType as String: kSecAttrKeyTypeEC,
      kSecAttrKeySizeInBits as String: 256,
      kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
      kSecPrivateKeyAttrs as String: [
        kSecAttrIsPermanent as String: true,
        kSecAttrApplicationTag as String: tag,
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

  func deleteKeyPair() -> Bool {
    let nameToDelete = loadKey(name: scopedKeyName) != nil ? scopedKeyName : keyName
    
    let tag = nameToDelete.data(using: .utf8)!

    let query: [String: Any] = [
      kSecClass as String: kSecClassKey,
      kSecAttrApplicationTag as String: tag,
      kSecAttrKeyType as String: kSecAttrKeyTypeEC,
      kSecReturnRef as String: true,
    ]

    let status = SecItemDelete(query as CFDictionary)

    guard status == errSecSuccess else {
      return false
    }

    return true
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

  private func loadKey(name: String) -> SecKey? {
    let tag = name.data(using: .utf8)!

    let query: [String: Any] = [
      kSecClass as String: kSecClassKey,
      kSecAttrApplicationTag as String: tag,
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
}
