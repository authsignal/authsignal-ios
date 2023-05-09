public struct PasskeyRegistrationCredential: Codable {
  public let id: String
  public let rawId: String
  public let type: String
  public let authenticatorAttachment: String
  public let response: PasskeyRegistrationCredentialResponse
}

public struct PasskeyRegistrationCredentialResponse: Codable {
  public let attestationObject: String?
  public let clientDataJSON: String
}
