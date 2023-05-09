public struct UpdateChallengeRequest: Codable {
  public let challengeId: String
  public let publicKey: String
  public let approved: Bool
  public let signature: String
  public let verificationCode: String?
}
