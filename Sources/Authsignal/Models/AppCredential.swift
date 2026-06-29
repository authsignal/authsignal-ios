import Foundation

public struct AppCredential: Codable {
  public let credentialId: String
  public let createdAt: String
  public let userId: String
  public let lastAuthenticatedAt: String?
  public let expiresAt: String?

  public init(
    credentialId: String,
    createdAt: String,
    userId: String,
    lastAuthenticatedAt: String?,
    expiresAt: String? = nil
  ) {
    self.credentialId = credentialId
    self.createdAt = createdAt
    self.userId = userId
    self.lastAuthenticatedAt = lastAuthenticatedAt
    self.expiresAt = expiresAt
  }

  /// Whether the credential's lease has lapsed, based on `expiresAt`.
  /// Returns `false` when the server does not provide an expiry (no expiry configured).
  public var isExpired: Bool {
    guard let expiresAt = expiresAt,
          let expiryDate = ISO8601DateFormatter().date(from: expiresAt)
    else {
      return false
    }

    return expiryDate < Date()
  }
}
