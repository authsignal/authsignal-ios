public struct VerifyDeviceRequest: Codable {
  public let challengeId: String
  public let publicKey: String
  public let signature: String
} 
