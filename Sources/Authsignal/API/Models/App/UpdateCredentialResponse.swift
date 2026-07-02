public struct UpdateCredentialResponse: Codable {
  public let userAuthenticatorId: String
  public let userId: String
  public let lastVerifiedAt: String
  public let pushToken: String?
  public let expiresAt: Double?
}
