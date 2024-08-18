import Foundation
import Security
import UIKit

public class AuthsignalTOTP {
  private let api: TOTPAPIClient
  private let cache: TokenCache

  public init(tenantID: String, baseURL: String, cache: TokenCache) {
    self.api = TOTPAPIClient(tenantID: tenantID, baseURL: baseURL)
    self.cache = cache
  }

  public func enroll() async -> AuthsignalResponse<EnrollTOTPResponse> {
    guard let token = cache.token else { return cache.handleTokenNotSetError() }
    
    return await api.enrollTOTP(token: token)
  }
  
  public func verify(code: String) async -> AuthsignalResponse<VerifyResponse> {
    guard let token = cache.token else { return cache.handleTokenNotSetError() }
    
    return await api.verifyTOTP(token: token, code: code)
  }
}
