import Foundation
import Security
import UIKit

public class Authsignal {
  public let email: AuthsignalEmail
  public let passkey: AuthsignalPasskey
  public let push: AuthsignalPush
  public let device: AuthsignalDevice
  public let sms: AuthsignalSMS
  public let whatsapp: AuthsignalWhatsApp
  public let totp: AuthsignalTOTP

  public init(tenantID: String, baseURL: String, deviceID: String? = nil) {
    email = AuthsignalEmail(tenantID: tenantID, baseURL: baseURL)
    passkey = AuthsignalPasskey(tenantID: tenantID, baseURL: baseURL, deviceID: deviceID)
    push = AuthsignalPush(tenantID: tenantID, baseURL: baseURL)
    device = AuthsignalDevice(tenantID: tenantID, baseURL: baseURL)
    sms = AuthsignalSMS(tenantID: tenantID, baseURL: baseURL)
    whatsapp = AuthsignalWhatsApp(tenantID: tenantID, baseURL: baseURL)
    totp = AuthsignalTOTP(tenantID: tenantID, baseURL: baseURL)
  }
  
  public func setToken(token: String) {
    TokenCache.shared.token = token
  }
}
