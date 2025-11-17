public struct VerifyPinResponse: Codable {
  public let isVerified: Bool
  public let token: String?
  public let userId: String?
  
  init(isVerified: Bool, token: String? = nil, userId: String? = nil) {
    self.isVerified = isVerified
    self.token = token
    self.userId = userId
  }
}
