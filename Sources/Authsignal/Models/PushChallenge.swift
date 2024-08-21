public struct PushChallenge: Codable {
  public let challengeId: String
  public let actionCode: String?
  public let idempotencyKey: String?
  public let deviceId: String?
  public let userAgent: String?
  public let ipAddress: String?
}
