import Foundation
import Security
import UIKit

public class Authsignal {
  public let push: AuthsignalPush
  public let passkey: AuthsignalPasskey

  public init(clientID: String, baseURL: String) {
    push = AuthsignalPush(clientID: clientID, baseURL: baseURL)
    passkey = AuthsignalPasskey(clientID: clientID, baseURL: baseURL)
  }
}
