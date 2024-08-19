import AuthenticationServices

public struct AuthsignalResponse<T> {
  public let data: T?
  public let error: String?
  public let errorCode: String?
  
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
  
  init(error: String? = nil, errorCode: String? = nil) {
    self.data = nil
    self.error = error
    self.errorCode = errorCode
  }
}
