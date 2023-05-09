public struct AddAuthenticatorRequest: Codable {
  public let challengeId: String
  public let registrationCredential: PasskeyRegistrationCredential
}
