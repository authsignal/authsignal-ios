public struct UpdateCredentialRequest: Codable {
  public let challengeId: String
  public let publicKey: String
  public let signature: String
  public let pushToken: String?
  public let extend: Bool?

  public init(
    challengeId: String,
    publicKey: String,
    signature: String,
    pushToken: String? = nil,
    extend: Bool? = nil
  ) {
    self.challengeId = challengeId
    self.publicKey = publicKey
    self.signature = signature
    self.pushToken = pushToken
    self.extend = extend
  }
}
