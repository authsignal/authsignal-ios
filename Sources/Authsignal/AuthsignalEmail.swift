import Foundation
import Security
import UIKit

public class AuthsignalEmail: AuthsignalBase {
  private let api: EmailAPIClient

  public init(tenantID: String, baseURL: String) {
    api = EmailAPIClient(tenantID: tenantID, baseURL: baseURL)
  }

  public func enroll(email: String) async -> AuthsignalResponse<EnrollResponse> {
    guard let token = self.token else { return handleTokenNotSetError() }
    
    return await api.enrollEmail(token: token, email: email)
  }
  
  public func challenge() async -> AuthsignalResponse<ChallengeResponse> {
    guard let token = self.token else { return handleTokenNotSetError() }
    
    return await api.challengeEmail(token: token)
  }
  
  public func verify(code: String) async -> AuthsignalResponse<VerifyResponse> {
    guard let token = self.token else { return handleTokenNotSetError() }
    
    return await api.verifyEmail(token: token, code: code)
  }
}
