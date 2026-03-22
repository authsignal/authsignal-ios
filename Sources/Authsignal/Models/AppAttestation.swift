public struct AppAttestation: Codable {
  public let attestationToken: String
  public let keyId: String?

  public init(attestationToken: String, keyId: String? = nil) {
    self.attestationToken = attestationToken
    self.keyId = keyId
  }
}
