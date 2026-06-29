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
  /// Returns `false` when the server does not provide an expiry (no expiry
  /// configured) or when the value cannot be parsed (fail-open), matching the
  /// serverless `isExpired` semantics.
  public var isExpired: Bool {
    guard let expiresAt = expiresAt,
          let expiryDate = AppCredential.parseISODate(expiresAt)
    else {
      return false
    }

    return expiryDate < Date()
  }

  /// Parses an ISO 8601 timestamp emitted by the server (Luxon `DateTime.toISO()`),
  /// which includes fractional seconds and a numeric timezone offset
  /// (e.g. `2026-06-30T12:42:38.416+12:00`). Falls back to parsing without
  /// fractional seconds so values that ever lack milliseconds still parse.
  static func parseISODate(_ value: String) -> Date? {
    let withFractional = ISO8601DateFormatter()
    withFractional.formatOptions = [.withInternetDateTime, .withFractionalSeconds]

    if let date = withFractional.date(from: value) {
      return date
    }

    let withoutFractional = ISO8601DateFormatter()
    withoutFractional.formatOptions = [.withInternetDateTime]

    return withoutFractional.date(from: value)
  }
}
