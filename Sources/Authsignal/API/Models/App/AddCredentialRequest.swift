public struct AddCredentialRequest: Codable {
  public let publicKey: String
  public let deviceName: String
  public let devicePlatform: String
  public let appAttestation: AppAttestation?

  public init(
    publicKey: String,
    deviceName: String,
    devicePlatform: String,
    appAttestation: AppAttestation? = nil
  ) {
    self.publicKey = publicKey
    self.deviceName = deviceName
    self.devicePlatform = devicePlatform
    self.appAttestation = appAttestation
  }
}
