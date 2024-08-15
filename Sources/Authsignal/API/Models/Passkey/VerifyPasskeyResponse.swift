public struct VerifyPasskeyResponse: Codable {
  public let isVerified: Bool
  public let accessToken: String?
  public let userId: String?
  public let userAuthenticatorId: String?
  public let username: String?
  public let userDisplayName: String?
}
