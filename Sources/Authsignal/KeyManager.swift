import Foundation
import Security

class KeyManager {
  private static let keyName = "authsignal_signing_key"

  static func getKey() -> SecKey? {
    return loadKey(name: keyName)
  }

  static func getOrCreatePublicKey() -> String? {
    let publicKey = getPublicKey()

    if publicKey != nil {
      return publicKey
    }

    return createKeyPair()
  }

  static func getPublicKey() -> String? {
    guard let secKey = loadKey(name: keyName) else {
      return nil
    }

    return derivePublicKey(secKey: secKey)
  }

  static func createKeyPair() -> String? {
    let access = SecAccessControlCreateWithFlags(
      kCFAllocatorDefault,
      kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
      [.privateKeyUsage],
      nil)!

    let tag = keyName.data(using: .utf8)!

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

  static func deleteKeyPair() -> Bool {
    let tag = keyName.data(using: .utf8)!

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

  static func derivePublicKey(secKey: SecKey) -> String? {
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

  static func loadKey(name: String) -> SecKey? {
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

  private static func createSubjectPublicKeyInfo(rawPublicKeyData: Data) -> Data {
    let secp256r1Header = Data(_: [
      0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08,
      0x2a,
      0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
    ])

    return secp256r1Header + rawPublicKeyData
  }
}
