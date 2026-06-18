public struct Authenticator: Codable {
  public let userAuthenticatorId: String?
  public let verificationMethod: String?
  public let webauthnCredential: WebauthnCredential?
}

public struct WebauthnCredential: Codable {
  public let credentialId: String
}

func buildAcceptedCredentialIds(
  authenticators: [Authenticator],
  currentCredentialId: String
) -> [String] {
  var credentialIds = authenticators
    .filter { $0.verificationMethod == "PASSKEY" }
    .compactMap { $0.webauthnCredential?.credentialId }

  if !credentialIds.contains(currentCredentialId) {
    credentialIds.append(currentCredentialId)
  }

  return credentialIds
}
