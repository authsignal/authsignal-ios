import Foundation
import Security

class PinManager {
  private let service = "authsignal_pin"
  
  func createPin(pin: String, username: String) {
    let pinData = pin.data(using: .utf8)!
    
    let query: [String: Any] = [
      kSecClass as String: kSecClassGenericPassword,
      kSecAttrService as String: service,
      kSecAttrAccount as String: username,
      kSecValueData as String: pinData,
      kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
    ]
    
    let status = SecItemAdd(query as CFDictionary, nil)
    
    if status == errSecDuplicateItem {
      let updateQuery: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: service,
        kSecAttrAccount as String: username
      ]
        
      let updateAttributes: [String: Any] = [
        kSecValueData as String: pinData
      ]
        
      SecItemUpdate(
        updateQuery as CFDictionary,
        updateAttributes as CFDictionary
      )
    }
  }
    
  func validatePin(pin: String, username: String) -> Bool {
    let query: [String: Any] = [
      kSecClass as String: kSecClassGenericPassword,
      kSecAttrService as String: service,
      kSecAttrAccount as String: username,
      kSecReturnData as String: true,
      kSecMatchLimit as String: kSecMatchLimitOne
    ]
      
    var result: AnyObject?
    let status = SecItemCopyMatching(query as CFDictionary, &result)
      
    guard status == errSecSuccess,
      let data = result as? Data,
      let storedPin = String(data: data, encoding: .utf8) else {
        return false
    }
    
    return storedPin == pin.trimmingCharacters(in: .whitespaces)
  }
    
  func getAllUsernames() -> [String] {
    let query: [String: Any] = [
      kSecClass as String: kSecClassGenericPassword,
      kSecAttrService as String: service,
      kSecReturnAttributes as String: true,
      kSecMatchLimit as String: kSecMatchLimitAll
    ]
    
    var result: AnyObject?
    let status = SecItemCopyMatching(query as CFDictionary, &result)
    
    guard status == errSecSuccess,
      let items = result as? [[String: Any]] else {
        return []
    }
    
    return items.compactMap { $0[kSecAttrAccount as String] as? String }
  }
    
  func usernameExists(_ username: String) -> Bool {
    let query: [String: Any] = [
      kSecClass as String: kSecClassGenericPassword,
      kSecAttrService as String: service,
      kSecAttrAccount as String: username,
      kSecReturnData as String: false
    ]
    
    let status = SecItemCopyMatching(query as CFDictionary, nil)
    
    return status == errSecSuccess
  }
    
  func deletePin(username: String) {
    let query: [String: Any] = [
      kSecClass as String: kSecClassGenericPassword,
      kSecAttrService as String: service,
      kSecAttrAccount as String: username
    ]
    
    SecItemDelete(query as CFDictionary)
  }
  
  func deleteAll() {
    let query: [String: Any] = [
      kSecClass as String: kSecClassGenericPassword,
      kSecAttrService as String: service
    ]
    
    SecItemDelete(query as CFDictionary)
  }
  
  func validateFormat(pin: String) -> Bool {
    guard pin.count >= 4 else {
      return false
    }
       
    return pin.allSatisfy { $0.isNumber }
  }
}
