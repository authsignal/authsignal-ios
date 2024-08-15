import Foundation
import Security
import UIKit

public class AuthsignalTOTP: AuthsignalBase {
  private let api: TOTPAPIClient

  public init(tenantID: String, baseURL: String) {
    api = TOTPAPIClient(tenantID: tenantID, baseURL: baseURL)
  }

  public func enroll() async -> AuthsignalResponse<EnrollTOTPResponse> {
    guard let token = self.token else { return handleTokenNotSetError() }
    
    return await api.enrollTOTP(token: token)
  }
  
  public func verify(code: String) async -> AuthsignalResponse<VerifyResponse> {
    guard let token = self.token else { return handleTokenNotSetError() }
    
    return await api.verifyTOTP(token: token, code: code)
  }
}
