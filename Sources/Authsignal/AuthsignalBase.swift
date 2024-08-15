import Foundation
import Security
import UIKit

public class AuthsignalBase {
  internal var token: String? = nil
  
  public func setToken(token: String) {
    self.token = token
  }
  
  func handleTokenNotSetError<T: Decodable>() -> AuthsignalResponse<T> {
    let error = "A token has not been set. Call 'setToken' first."
    
    Logger.error("Error: \(error)")
    
    return AuthsignalResponse(error: error)
  }
}

