public struct AddPasskeyAuthenticatorRequest: Codable {
  public let challengeId: String
  public let registrationCredential: PasskeyRegistrationCredential
  public let deviceId: String?
}
