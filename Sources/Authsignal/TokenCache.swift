import Foundation

public class TokenCache {
  public var token: String? = nil
  
  public static let shared = TokenCache()
  
  func handleTokenNotSetError<T: Decodable>() -> AuthsignalResponse<T> {
    let error = "A token has not been set. Call 'setToken' first."
    let errorCode = "TOKEN_NOT_SET"
    
    Logger.error("Error: \(error)")
    
    return AuthsignalResponse(error: error, errorCode: errorCode)
  }
}
