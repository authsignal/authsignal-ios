public struct CredentialResponse: Codable {
  public let userAuthenticatorId: String
  public let verifiedAt: String
  public let userId: String
  public let lastVerifiedAt: String?
  public let expiresAt: String?
}
