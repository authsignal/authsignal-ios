public struct AddCredentialRequest: Codable {
  public let publicKey: String
  public let deviceName: String
  public let devicePlatform: String
  let deviceIntegrity: AddCredentialDeviceIntegrity?

  public init(
    publicKey: String,
    deviceName: String,
    devicePlatform: String,
    deviceIntegrity: DeviceIntegrity? = nil
  ) {
    self.publicKey = publicKey
    self.deviceName = deviceName
    self.devicePlatform = devicePlatform
    self.deviceIntegrity = deviceIntegrity.map {
      AddCredentialDeviceIntegrity(provider: "APP_ATTEST", token: $0.integrityToken, keyId: $0.keyId)
    }
  }
}

struct AddCredentialDeviceIntegrity: Codable {
  let provider: String
  let token: String
  let keyId: String?
}
