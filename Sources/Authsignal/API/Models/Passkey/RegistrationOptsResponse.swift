public struct RegistrationOptsResponse: Codable {
  public let challengeId: String
  public let options: RegistrationOpts
}

public struct RegistrationOpts: Codable {
  public let challenge: String
  public let rp: RegistrationOptsRelyingParty
  public let user: RegistrationOptsUser
  public let excludeCredentials: [RegistrationOptsExcludedCredential]
}

public struct RegistrationOptsRelyingParty: Codable {
  public let id: String
}

public struct RegistrationOptsUser: Codable {
  public let id: String
  public let name: String
  public let displayName: String
}

public struct RegistrationOptsExcludedCredential: Codable {
  public let id: String
  public let type: String
}
