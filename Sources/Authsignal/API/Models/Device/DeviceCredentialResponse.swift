public struct DeviceCredentialResponse: Codable {
  public let userAuthenticatorId: String
  public let userId: String
  public let verifiedAt: String
  public let lastVerifiedAt: String?
} 
