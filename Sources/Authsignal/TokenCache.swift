import Foundation

public class TokenCache {
  public var token: String? = nil
  
  static let shared = TokenCache()
  
  func handleTokenNotSetError<T: Decodable>() -> AuthsignalResponse<T> {
    let error = "A token has not been set. Call 'setToken' first."
    
    Logger.error("Error: \(error)")
    
    return AuthsignalResponse(error: error)
  }
}
