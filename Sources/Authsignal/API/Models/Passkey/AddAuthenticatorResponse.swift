public struct AddAuthenticatorResponse: Codable {
  public let isVerified: Bool
  public let accessToken: String?
  public let userAuthenticatorId: String?
}
