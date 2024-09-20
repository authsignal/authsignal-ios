import Foundation

public class TokenCache {
  private var _token: String? = nil
  
  public var token: String? {
    get { return _token }
    set {
      if (!(newValue ?? "").isEmpty) {
        _token = newValue
      }
    }
  }
  
  public static let shared = TokenCache()
  
  func handleTokenNotSetError<T: Decodable>() -> AuthsignalResponse<T> {
    let error = "A token has not been set. Call 'setToken' first."
    let errorCode = "token_not_set"
    
    Logger.error("Error: \(error)")
    
    return AuthsignalResponse(error: error, errorCode: errorCode)
  }
}
