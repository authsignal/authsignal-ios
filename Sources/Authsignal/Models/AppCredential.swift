import Foundation

public struct AppCredential: Codable {
  public let credentialId: String
  public let createdAt: String
  public let userId: String
  public let lastAuthenticatedAt: String?
  public let expiresAt: Double?

  public init(
    credentialId: String,
    createdAt: String,
    userId: String,
    lastAuthenticatedAt: String?,
    expiresAt: Double? = nil
  ) {
    self.credentialId = credentialId
    self.createdAt = createdAt
    self.userId = userId
    self.lastAuthenticatedAt = lastAuthenticatedAt
    self.expiresAt = expiresAt
  }

  public var isExpired: Bool {
    guard let expiresAt = expiresAt else {
      return false
    }

    return Date(timeIntervalSince1970: expiresAt) < Date()
  }
}
