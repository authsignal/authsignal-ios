public struct VerifyRequest: Codable {
  public let challengeId: String
  public let authenticationCredential: PasskeyAuthenticationCredential
  public let deviceId: String?
}
