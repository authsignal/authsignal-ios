import Foundation
import Security
import UIKit

public class Authsignal {
  public let email: AuthsignalEmail
  public let passkey: AuthsignalPasskey
  public let push: AuthsignalPush
  public let sms: AuthsignalSMS
  public let totp: AuthsignalTOTP

  public init(tenantID: String, baseURL: String) {
    email = AuthsignalEmail(tenantID: tenantID, baseURL: baseURL)
    sms = AuthsignalSMS(tenantID: tenantID, baseURL: baseURL)
    totp = AuthsignalTOTP(tenantID: tenantID, baseURL: baseURL)
    
    passkey = AuthsignalPasskey(tenantID: tenantID, baseURL: baseURL)
    push = AuthsignalPush(tenantID: tenantID, baseURL: baseURL)
  }
  
  public func setToken(token: String) {
    TokenCache.shared.token = token
  }
}
