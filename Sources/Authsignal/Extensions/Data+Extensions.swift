import Foundation

extension Data {
  public init?(base64URLEncoded: String, options: Data.Base64DecodingOptions = []) {
    self.init(base64Encoded: base64URLEncoded.base64URLUnescaped(), options: options)
  }

  public func base64URLEncodedString() -> String {
    return base64EncodedString().base64URLEscaped()
  }
}
