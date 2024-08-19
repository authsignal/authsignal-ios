import Foundation
import Security
import UIKit

public class AuthsignalEmail {
  private let api: EmailAPIClient
  private let cache = TokenCache.shared

  public init(tenantID: String, baseURL: String) {
    self.api = EmailAPIClient(tenantID: tenantID, baseURL: baseURL)
  }

  public func enroll(email: String) async -> AuthsignalResponse<EnrollResponse> {
    guard let token = cache.token else { return cache.handleTokenNotSetError() }
    
    return await api.enrollEmail(token: token, email: email)
  }
  
  public func challenge() async -> AuthsignalResponse<ChallengeResponse> {
    guard let token = cache.token else { return cache.handleTokenNotSetError() }
    
    return await api.challengeEmail(token: token)
  }
  
  public func verify(code: String) async -> AuthsignalResponse<VerifyResponse> {
    guard let token = cache.token else { return cache.handleTokenNotSetError() }
    
    let verifyResponse = await api.verifyEmail(token: token, code: code)
    
    if let responseToken = verifyResponse.data?.token {
      cache.token = responseToken
    }
    
    return verifyResponse
  }
}
