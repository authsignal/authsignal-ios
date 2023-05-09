public struct AuthenticationOptsResponse: Codable {
  public let challengeId: String
  public let options: AuthenticationOpts
}

public struct AuthenticationOpts: Codable {
  public let challenge: String
  public let rpId: String
  public let allowCredentials: [AuthenticationOptsCredential]
}

public struct AuthenticationOptsCredential: Codable {
  public let id: String
  public let type: String
}
