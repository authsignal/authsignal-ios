public struct EnrollTotpResponse: Codable {
  public let userAuthenticatorId: String
  public let uri: String
  public let secret: String
}
