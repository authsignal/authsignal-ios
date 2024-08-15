import Foundation
import Security
import UIKit

public class AuthsignalSms: AuthsignalBase {
  private let api: SmsApiClient
  
  public init(tenantId: String, baseUrl: String) {
    api = SmsApiClient(tenantId: tenantId, baseUrl: baseUrl)
  }

  public func enroll(phoneNumber: String) async -> AuthsignalResponse<EnrollResponse> {
    guard let token = self.token else { return handleTokenNotSetError() }
    
    return await api.enrollSms(token: token, phoneNumber: phoneNumber)
  }
  
  public func challenge() async -> AuthsignalResponse<ChallengeResponse> {
    guard let token = self.token else { return handleTokenNotSetError() }
    
    return await api.challengeSms(token: token)
  }
  
  public func verify(code: String) async -> AuthsignalResponse<VerifyResponse> {
    guard let token = self.token else { return handleTokenNotSetError() }
    
    return await api.verifySms(token: token, code: code)
  }
}
