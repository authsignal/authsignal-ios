public struct AddCredentialRequest: Codable {
  public let publicKey: String
  public let deviceName: String
  public let devicePlatform: String
  let appAttestation: AddCredentialAppAttestation?

  public init(
    publicKey: String,
    deviceName: String,
    devicePlatform: String,
    appAttestation: AppAttestation? = nil
  ) {
    self.publicKey = publicKey
    self.deviceName = deviceName
    self.devicePlatform = devicePlatform
    self.appAttestation = appAttestation.map {
      AddCredentialAppAttestation(provider: "APP_ATTEST", token: $0.attestationToken, keyId: $0.keyId)
    }
  }
}

struct AddCredentialAppAttestation: Codable {
  let provider: String
  let token: String
  let keyId: String?
}
