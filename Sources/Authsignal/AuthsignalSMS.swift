import Foundation
import Security
import UIKit

public class AuthsignalSMS: AuthsignalBase {
  private let api: SMSAPIClient
  
  public init(tenantID: String, baseURL: String) {
    api = SMSAPIClient(tenantID: tenantID, baseURL: baseURL)
  }

  public func enroll(phoneNumber: String) async -> AuthsignalResponse<EnrollResponse> {
    guard let token = self.token else { return handleTokenNotSetError() }
    
    return await api.enrollSMS(token: token, phoneNumber: phoneNumber)
  }
  
  public func challenge() async -> AuthsignalResponse<ChallengeResponse> {
    guard let token = self.token else { return handleTokenNotSetError() }
    
    return await api.challengeSMS(token: token)
  }
  
  public func verify(code: String) async -> AuthsignalResponse<VerifyResponse> {
    guard let token = self.token else { return handleTokenNotSetError() }
    
    return await api.verifySMS(token: token, code: code)
  }
}
