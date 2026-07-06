public struct UpdateCredentialRequest: Codable {
  public let challengeId: String
  public let publicKey: String
  public let signature: String
  public let pushToken: String?
  public let resetExpiry: Bool?

  public init(
    challengeId: String,
    publicKey: String,
    signature: String,
    pushToken: String? = nil,
    resetExpiry: Bool? = nil
  ) {
    self.challengeId = challengeId
    self.publicKey = publicKey
    self.signature = signature
    self.pushToken = pushToken
    self.resetExpiry = resetExpiry
  }
}
