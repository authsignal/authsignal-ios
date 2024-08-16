public struct VerifyResponse: Codable {
  public let isVerified: Bool
  public let accessToken: String?
  public let failureReason: String?
}
