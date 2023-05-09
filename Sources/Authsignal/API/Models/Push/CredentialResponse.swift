public struct CredentialResponse: Codable {
  public let userAuthenticatorId: String
  public let verifiedAt: String
  public let lastVerifiedAt: String?
}
