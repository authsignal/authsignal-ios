import Security
import Foundation

public class AuthsignalDevice {
  static var api: DeviceAPI {
    return DeviceAPI()
  }
  
  static public func enrollWithAccessToken(_ accessToken: String) async -> Bool {
    guard let publicKey = KeyManager.getOrCreatePublicKey() else {
      print("Error enrolling: unable to generate key pair.")
      
      return false
    }
    
    return await api.enrollWithAccessToken(accessToken, publicKey: publicKey)
  }
  
  static public func getChallenge() async -> String? {
    guard let publicKey = KeyManager.getPublicKey() else {
      print("Error getting challenge: device not enrolled.")
      
      return nil
    }

    return await api.getChallenge(publicKey: publicKey)
  }
  
  static public func updateChallenge(_ challengeId: String, withApproval approved: Bool) async -> Void {
    let publicKey = KeyManager.getPublicKey()
    
    let secKey = KeyManager.loadKey(name: KeyManager.keyName)

    guard let publicKey = publicKey, let secKey = secKey else {
      print("Error updating challenge: device not enrolled.")
      
      return
    }
    
    var signature: String? = nil
    
    do {
      signature = try Signature.sign(message: challengeId, privateKey: secKey)
    } catch {
      print("Error generating signature: \(error).")
      
      return;
    }
    
    return await api.updateChallenge(challengeId, publicKey: publicKey, signature: signature!, approved: approved)
  }
}
