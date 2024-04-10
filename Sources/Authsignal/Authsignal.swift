import Foundation
import Security
import UIKit

public class Authsignal {
  public let push: AuthsignalPush
  public let passkey: AuthsignalPasskey

  public init(tenantID: String, baseURL: String, deviceID: String? = nil) {
    push = AuthsignalPush(tenantID: tenantID, baseURL: baseURL, deviceID: deviceID)
    passkey = AuthsignalPasskey(tenantID: tenantID, baseURL: baseURL, deviceID: deviceID)
  }
}
