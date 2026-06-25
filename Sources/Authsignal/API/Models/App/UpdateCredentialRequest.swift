public struct UpdateCredentialRequest: Codable {
  public let challengeId: String
  public let publicKey: String
  public let signature: String
  public let pushToken: String
}
