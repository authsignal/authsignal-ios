import Foundation
import Security
import UIKit

public class AuthsignalSMS {
  private let api: SMSAPIClient
  private let cache = TokenCache.shared
  
  public init(tenantID: String, baseURL: String) {
    self.api = SMSAPIClient(tenantID: tenantID, baseURL: baseURL)
  }

  public func enroll(phoneNumber: String) async -> AuthsignalResponse<EnrollResponse> {
    guard let token = cache.token else { return cache.handleTokenNotSetError() }
    
    return await api.enrollSMS(token: token, phoneNumber: phoneNumber)
  }
  
  public func challenge() async -> AuthsignalResponse<ChallengeResponse> {
    guard let token = cache.token else { return cache.handleTokenNotSetError() }
    
    return await api.challengeSMS(token: token)
  }
  
  public func verify(code: String) async -> AuthsignalResponse<VerifyResponse> {
    guard let token = cache.token else { return cache.handleTokenNotSetError() }
    
    let verifyResponse = await api.verifySMS(token: token, code: code)
    
    if let responseToken = verifyResponse.data?.token {
      cache.token = responseToken
    }
    
    return verifyResponse
  }
}
