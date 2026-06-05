public struct Authenticator: Codable {
  public let userAuthenticatorId: String?
  public let verificationMethod: String?
  public let webauthnCredential: WebauthnCredential?
}

public struct WebauthnCredential: Codable {
  public let credentialId: String
}

/// Builds the set of credential IDs to report to the system via the Signal API:
/// every passkey the server currently accepts, plus the credential just used
/// (in case the server list is briefly stale), de-duplicated.
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
