public struct ClaimChallengeResponse: Codable {
  public let success: Bool
  public let ipAddress: String?
  public let userAgent: String?
  public let actionCode: String?
  public let idempotencyKey: String?
  public let custom: [String: JSONValue]?
  public let user: ChallengeUserResponse?
}
