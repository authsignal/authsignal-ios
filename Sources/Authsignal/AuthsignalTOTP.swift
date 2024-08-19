import Foundation
import Security
import UIKit

public class AuthsignalTOTP {
  private let api: TOTPAPIClient
  private let cache = TokenCache.shared

  public init(tenantID: String, baseURL: String) {
    self.api = TOTPAPIClient(tenantID: tenantID, baseURL: baseURL)
  }

  public func enroll() async -> AuthsignalResponse<EnrollTOTPResponse> {
    guard let token = cache.token else { return cache.handleTokenNotSetError() }
    
    return await api.enrollTOTP(token: token)
  }
  
  public func verify(code: String) async -> AuthsignalResponse<VerifyResponse> {
    guard let token = cache.token else { return cache.handleTokenNotSetError() }
    
    let verifyResponse = await api.verifyTOTP(token: token, code: code)
    
    if let responseToken = verifyResponse.data?.token {
      cache.token = responseToken
    }
    
    return verifyResponse
  }
}
