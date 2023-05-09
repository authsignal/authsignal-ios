import Foundation

extension String {
  public func base64URLUnescaped() -> String {
    return replacingOccurrences(of: "-", with: "+")
      .replacingOccurrences(of: "_", with: "/")
      .appending(String(repeating: "=", count: 4 - (self.count % 4)))
  }

  public func base64URLEscaped() -> String {
    return replacingOccurrences(of: "+", with: "-")
      .replacingOccurrences(of: "/", with: "_")
      .replacingOccurrences(of: "=", with: "")
  }
}
