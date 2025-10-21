import Foundation
import Security
import UIKit

public class Authsignal {
  public let app: AuthsignalInApp
  public let email: AuthsignalEmail
  public let passkey: AuthsignalPasskey
  public let push: AuthsignalPush
  public let qrCode: AuthsignalQRCode
  public let sms: AuthsignalSMS
  public let totp: AuthsignalTOTP
  public let whatsapp: AuthsignalWhatsApp

  public init(tenantID: String, baseURL: String, deviceID: String? = nil) {
    app = AuthsignalInApp(tenantID: tenantID, baseURL: baseURL)
    email = AuthsignalEmail(tenantID: tenantID, baseURL: baseURL)
    passkey = AuthsignalPasskey(tenantID: tenantID, baseURL: baseURL, deviceID: deviceID)
    push = AuthsignalPush(tenantID: tenantID, baseURL: baseURL)
    qrCode = AuthsignalQRCode(tenantID: tenantID, baseURL: baseURL)
    sms = AuthsignalSMS(tenantID: tenantID, baseURL: baseURL)
    totp = AuthsignalTOTP(tenantID: tenantID, baseURL: baseURL)
    whatsapp = AuthsignalWhatsApp(tenantID: tenantID, baseURL: baseURL)
  }
  
  public func setToken(token: String) {
    TokenCache.shared.token = token
  }
}
