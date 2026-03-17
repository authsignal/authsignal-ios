public enum AppAttestationProvider: String, Codable {
  case apple
}

public struct AppAttestation: Codable {
  public let provider: AppAttestationProvider
  public let token: String
  public let keyId: String?

  public init(provider: AppAttestationProvider, token: String, keyId: String? = nil) {
    self.provider = provider
    self.token = token
    self.keyId = keyId
  }
}
