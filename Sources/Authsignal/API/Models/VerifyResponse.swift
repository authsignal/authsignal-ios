public struct VerifyResponse: Codable {
  public let isVerified: Bool
  public let token: String?
  public let failureReason: String?
  
  enum CodingKeys: String, CodingKey {
    case isVerified
    case token = "accessToken"
    case failureReason
  }
}
