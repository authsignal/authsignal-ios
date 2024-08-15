import Foundation
import Security
import UIKit

public class Authsignal {
  public let email: AuthsignalEmail
  public let passkey: AuthsignalPasskey
  public let push: AuthsignalPush
  public let sms: AuthsignalSms
  public let totp: AuthsignalTotp

  public init(tenantId: String, baseUrl: String) {
    email = AuthsignalEmail(tenantId: tenantId, baseUrl: baseUrl)
    passkey = AuthsignalPasskey(tenantId: tenantId, baseUrl: baseUrl)
    push = AuthsignalPush(tenantId: tenantId, baseUrl: baseUrl)
    sms = AuthsignalSms(tenantId: tenantId, baseUrl: baseUrl)
    totp = AuthsignalTotp(tenantId: tenantId, baseUrl: baseUrl)
  }
  
  public func setToken(token: String) {
    email.setToken(token: token)
    sms.setToken(token: token)
    totp.setToken(token: token)
  }
}
