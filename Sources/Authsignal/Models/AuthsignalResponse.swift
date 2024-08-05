import AuthenticationServices

public struct AuthsignalResponse<T> {
  public let data: T?
  public let error: String?
  public let errorCode: ASAuthorizationError.Code?
  
  init(data: T, error: String?) {
    self.data = data
    self.error = nil
    self.errorCode = nil
  }
  
  init(data: T) {
    self.data = data
    self.error = nil
    self.errorCode = nil
  }
  
  init(error: String? = nil, errorCode: ASAuthorizationError.Code? = nil) {
    self.data = nil
    self.error = error
    self.errorCode = errorCode
  }
}
