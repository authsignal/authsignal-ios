import Foundation
import Security
import UIKit

public class Authsignal {
  public let push: AuthsignalPush
  public let passkey: AuthsignalPasskey

  public init(tenantID: String, baseURL: String) {
    push = AuthsignalPush(tenantID: tenantID, baseURL: baseURL)
    passkey = AuthsignalPasskey(tenantID: tenantID, baseURL: baseURL)
  }
}
