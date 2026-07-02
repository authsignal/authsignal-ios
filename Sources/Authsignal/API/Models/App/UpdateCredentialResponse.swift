public struct UpdateCredentialResponse: Codable {
  public let userAuthenticatorId: String
  public let userId: String
  public let lastVerifiedAt: String
  // Echoes the request's pushToken; absent for keep-alive calls that omit the token.
  public let pushToken: String?
  public let expiresAt: String?
}
