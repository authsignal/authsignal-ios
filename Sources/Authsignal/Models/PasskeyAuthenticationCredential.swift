public struct PasskeyAuthenticationCredential: Codable {
  public let id: String
  public let rawId: String
  public let type: String
  public let authenticatorAttachment: String
  public let response: PasskeyAuthenticationCredentialResponse
}

public struct PasskeyAuthenticationCredentialResponse: Codable {
  public let authenticatorData: String
  public let clientDataJSON: String
  public let signature: String
  public let userHandle: String
}
