public struct AddCredentialRequest: Codable {
  public let publicKey: String
  public let deviceName: String
  public let devicePlatform: String
  let performAttestation: AddCredentialAttestation?

  public init(
    publicKey: String,
    deviceName: String,
    devicePlatform: String,
    performAttestation: AppAttestationResult? = nil
  ) {
    self.publicKey = publicKey
    self.deviceName = deviceName
    self.devicePlatform = devicePlatform
    self.performAttestation = performAttestation.map {
      AddCredentialAttestation(provider: "APP_ATTEST", token: $0.integrityToken, keyId: $0.keyId)
    }
  }
}

struct AddCredentialAttestation: Codable {
  let provider: String
  let token: String
  let keyId: String?
}
