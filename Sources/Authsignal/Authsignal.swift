import Foundation
import Security
import UIKit

public class Authsignal {
  public let inapp: AuthsignalInApp
  public let email: AuthsignalEmail
  public let passkey: AuthsignalPasskey
  public let push: AuthsignalPush
  public let qr: AuthsignalQRCode
  public let sms: AuthsignalSMS
  public let totp: AuthsignalTOTP
  public let whatsapp: AuthsignalWhatsApp

  private let _deviceID: String?

  public init(tenantID: String, baseURL: String, deviceID: String? = nil, retries: Int = 2) {
    inapp = AuthsignalInApp(tenantID: tenantID, baseURL: baseURL, retries: retries)
    email = AuthsignalEmail(tenantID: tenantID, baseURL: baseURL, retries: retries)
    passkey = AuthsignalPasskey(tenantID: tenantID, baseURL: baseURL, deviceID: deviceID, retries: retries)
    push = AuthsignalPush(tenantID: tenantID, baseURL: baseURL, retries: retries)
    qr = AuthsignalQRCode(tenantID: tenantID, baseURL: baseURL, retries: retries)
    sms = AuthsignalSMS(tenantID: tenantID, baseURL: baseURL, retries: retries)
    totp = AuthsignalTOTP(tenantID: tenantID, baseURL: baseURL, retries: retries)
    whatsapp = AuthsignalWhatsApp(tenantID: tenantID, baseURL: baseURL, retries: retries)

    _deviceID = deviceID
  }

  public func setToken(token: String) {
    TokenCache.shared.token = token
  }

  public func getDeviceID() async -> String {
    if let deviceID = _deviceID {
      return deviceID
    }

    return await DeviceCache.shared.getDefaultDeviceID()
  }
}
