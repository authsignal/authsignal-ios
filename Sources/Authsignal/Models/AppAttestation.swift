public struct AppAttestation: Codable {
  public let token: String
  public let keyId: String?

  public init(token: String, keyId: String? = nil) {
    self.token = token
    self.keyId = keyId
  }
}
