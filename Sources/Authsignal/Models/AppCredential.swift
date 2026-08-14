import Foundation

public struct AppCredential: Codable {
  public let credentialId: String
  public let createdAt: String
  public let userId: String
  public let lastAuthenticatedAt: String?
  public let expiresAt: String?
  public let erroredAt: String?
  public let errorCode: String?

  public init(
    credentialId: String,
    createdAt: String,
    userId: String,
    lastAuthenticatedAt: String?,
    expiresAt: String? = nil,
    erroredAt: String? = nil,
    errorCode: String? = nil
  ) {
    self.credentialId = credentialId
    self.createdAt = createdAt
    self.userId = userId
    self.lastAuthenticatedAt = lastAuthenticatedAt
    self.expiresAt = expiresAt
    self.erroredAt = erroredAt
    self.errorCode = errorCode
  }
}
