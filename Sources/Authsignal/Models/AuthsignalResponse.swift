import AuthenticationServices

public struct AuthsignalResponse<T> {
  public let data: T?
  public let error: String?
  public let errorCode: String?
  public let nativeErrorDomain: String?
  public let nativeErrorCode: Int?

  init(data: T, error: String?, errorCode: String? = nil) {
    self.data = data
    self.error = nil
    self.errorCode = nil
    self.nativeErrorDomain = nil
    self.nativeErrorCode = nil
  }

  init(data: T) {
    self.data = data
    self.error = nil
    self.errorCode = nil
    self.nativeErrorDomain = nil
    self.nativeErrorCode = nil
  }

  init(
    error: String? = nil,
    errorCode: String? = nil,
    nativeErrorDomain: String? = nil,
    nativeErrorCode: Int? = nil
  ) {
    self.data = nil
    self.error = error
    self.errorCode = errorCode
    self.nativeErrorDomain = nativeErrorDomain
    self.nativeErrorCode = nativeErrorCode
  }

  init(error: String?, errorCode: String? = nil, nativeError: Error) {
    let nsError = nativeError as NSError

    self.init(
      error: error,
      errorCode: errorCode,
      nativeErrorDomain: nsError.domain,
      nativeErrorCode: nsError.code
    )
  }
}
