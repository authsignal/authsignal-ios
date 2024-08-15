import Foundation
import Security
import UIKit

public class AuthsignalTotp: AuthsignalBase {
  private let api: TotpApiClient

  public init(tenantId: String, baseUrl: String) {
    api = TotpApiClient(tenantId: tenantId, baseUrl: baseUrl)
  }

  public func enroll() async -> AuthsignalResponse<EnrollTotpResponse> {
    guard let token = self.token else { return handleTokenNotSetError() }
    
    return await api.enrollTotp(token: token)
  }
  
  public func verify(code: String) async -> AuthsignalResponse<VerifyResponse> {
    guard let token = self.token else { return handleTokenNotSetError() }
    
    return await api.verifyTotp(token: token, code: code)
  }
}
