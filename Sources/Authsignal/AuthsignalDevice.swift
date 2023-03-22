import Security
import Foundation

public class AuthsignalDevice {
  static var api: DeviceAPI {
    return DeviceAPI()
  }
  
  static public func addCredential(accessToken: String) async -> Bool {
    guard let publicKey = KeyManager.getOrCreatePublicKey() else {
      print("Error adding credential: unable to generate key pair.")
      
      return false
    }
    
    return await api.addCredential(accessToken: accessToken, publicKey: publicKey)
  }
  
  static public func removeCredential() async -> Bool {
    let secKey = KeyManager.getKey()
    
    guard let secKey = secKey else {
      print("Error removing credential: no credential found.")
      
      return false
    }
    
    let publicKey = KeyManager.derivePublicKey(secKey: secKey)
    
    guard let publicKey = publicKey else {
      print("Error removing credential: unable to derive public key.")
      
      return false
    }
    
    var signature: String? = nil
    
    do {
      signature = try Signature.sign(message: "authsignal-remove-credential", privateKey: secKey)
    } catch {
      print("Error generating signature: \(error).")
      
      return false
    }
    
    let success = await api.removeCredential(publicKey: publicKey, signature: signature!)
    
    if (success) {
      return KeyManager.deleteKeyPair()
    }
    
    return false
  }
  
  static public func getChallenge() async -> String? {
    guard let publicKey = KeyManager.getPublicKey() else {
      print("Error getting challenge: device not enrolled.")
      
      return nil
    }

    return await api.getChallenge(publicKey: publicKey)
  }
  
  static public func updateChallenge(_ challengeId: String, withApproval approved: Bool) async -> Void {
    let secKey = KeyManager.getKey()
    
    guard let secKey = secKey else {
      print("Error updating challenge: device not enrolled.")
      
      return
    }
    
    let publicKey = KeyManager.derivePublicKey(secKey: secKey)
    
    guard let publicKey = publicKey else {
      print("Error updating challenge: unable to derive public key.")
      
      return
    }
    
    var signature: String? = nil
    
    do {
      signature = try Signature.sign(message: challengeId, privateKey: secKey)
    } catch {
      print("Error generating signature: \(error).")
      
      return
    }
    
    return await api.updateChallenge(challengeId, publicKey: publicKey, signature: signature!, approved: approved)
  }
}
