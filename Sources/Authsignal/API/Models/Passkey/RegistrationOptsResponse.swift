public struct RegistrationOptsResponse: Codable {
  public let challengeId: String
  public let options: RegistrationOpts
}

public struct RegistrationOpts: Codable {
  public let challenge: String
  public let rp: RegistrationOptsRelyingParty
  public let user: RegistrationOptsUser
}

public struct RegistrationOptsRelyingParty: Codable {
  public let id: String
}

public struct RegistrationOptsUser: Codable {
  public let id: String
  public let displayName: String
}
