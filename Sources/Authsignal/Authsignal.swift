import Foundation
import Security
import UIKit

public class Authsignal {
  public let email: AuthsignalEmail
  public let passkey: AuthsignalPasskey
  public let push: AuthsignalPush
  public let sms: AuthsignalSMS
  public let totp: AuthsignalTOTP
  
  public let cache: TokenCache

  public init(tenantID: String, baseURL: String) {
    cache = TokenCache.shared
    
    email = AuthsignalEmail(tenantID: tenantID, baseURL: baseURL, cache: cache)
    sms = AuthsignalSMS(tenantID: tenantID, baseURL: baseURL, cache: cache)
    totp = AuthsignalTOTP(tenantID: tenantID, baseURL: baseURL, cache: cache)
    
    passkey = AuthsignalPasskey(tenantID: tenantID, baseURL: baseURL)
    push = AuthsignalPush(tenantID: tenantID, baseURL: baseURL)
  }
  
  public func setToken(token: String) {
    cache.token = token
  }
}
