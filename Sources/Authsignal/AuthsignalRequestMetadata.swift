import Foundation
import UIKit

struct AuthsignalWrapperSDKMetadata {
  let sdk: String
  let version: String
  let userAgentToken: String
}

@objc public class AuthsignalRequestMetadata: NSObject {
  private static let nativeSDK = "ios"
  private static let nativeVersion = "2.12.0"
  private static let nativeUserAgentToken = "AuthsignalIOSSDK"
  private static var wrapperSDKMetadata: AuthsignalWrapperSDKMetadata?

  @objc public static func setWrapperSDK(_ sdk: String, version: String, userAgentToken: String) {
    wrapperSDKMetadata = AuthsignalWrapperSDKMetadata(
      sdk: sdk,
      version: version,
      userAgentToken: userAgentToken
    )
  }

  @objc public static func clearWrapperSDK() {
    wrapperSDKMetadata = nil
  }

  static func headers(tenantID: String) -> [String: String] {
    var headers = [
      "User-Agent": userAgent(),
      "X-Authsignal-SDK": wrapperSDKMetadata?.sdk ?? nativeSDK,
      "X-Authsignal-Version": wrapperSDKMetadata?.version ?? nativeVersion,
      "X-Authsignal-Tenant-ID": tenantID,
    ]

    if wrapperSDKMetadata != nil {
      headers["X-Authsignal-Native-SDK"] = nativeSDK
      headers["X-Authsignal-Native-Version"] = nativeVersion
    }

    return headers
  }

  private static func userAgent() -> String {
    "\(baseUserAgent()) \(userAgentProductTokens())"
  }

  private static func userAgentProductTokens() -> String {
    let nativeProduct = "\(nativeUserAgentToken)/\(nativeVersion)"

    if let wrapperSDKMetadata = wrapperSDKMetadata {
      return "\(wrapperSDKMetadata.userAgentToken)/\(wrapperSDKMetadata.version) \(nativeProduct)"
    }

    return nativeProduct
  }

  private static func baseUserAgent() -> String {
    let device = UIDevice.current
    let platform = device.userInterfaceIdiom == .pad ? "iPad" : "iPhone"
    let osPrefix = platform == "iPad" ? "CPU OS" : "CPU iPhone OS"
    let osVersion = device.systemVersion.replacingOccurrences(of: ".", with: "_")

    return "Mozilla/5.0 (\(platform); \(osPrefix) \(osVersion) like Mac OS X)"
  }
}
