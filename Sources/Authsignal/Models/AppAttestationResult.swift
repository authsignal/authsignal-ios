public struct AppAttestationResult: Codable {
  public let integrityToken: String
  public let keyId: String?

  public init(integrityToken: String, keyId: String? = nil) {
    self.integrityToken = integrityToken
    self.keyId = keyId
  }
}
