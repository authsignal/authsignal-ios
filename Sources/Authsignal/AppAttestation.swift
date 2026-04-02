import Foundation
import DeviceCheck
import CryptoKit

class AppAttestation {
  static func resolveIntegrity(token: String) async -> AppAttestationResult? {
    if #available(iOS 14.0, *), DCAppAttestService.shared.isSupported {
      do {
        guard let idempotencyKey = extractIdempotencyKey(from: token) else {
          Logger.error("Failed to extract idempotencyKey from token")
          return nil
        }

        let nonceData = Data(idempotencyKey.utf8)
        let nonceHash = Data(SHA256.hash(data: nonceData))

        let keyId = try await DCAppAttestService.shared.generateKey()
        let integrityData = try await DCAppAttestService.shared.attestKey(keyId, clientDataHash: nonceHash)
        let integrityToken = integrityData.base64EncodedString()

        return AppAttestationResult(integrityToken: integrityToken, keyId: keyId)
      } catch {
        Logger.error("App Attest failed: \(error.localizedDescription)")
      }
    }

    return nil
  }

  private static func extractIdempotencyKey(from token: String) -> String? {
    let parts = token.split(separator: ".")
    guard parts.count >= 2 else { return nil }

    let payload = String(parts[1]).base64URLUnescaped()
    guard let data = Data(base64Encoded: payload) else { return nil }
    guard let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return nil }
    guard let other = json["other"] as? [String: Any] else { return nil }

    return other["idempotencyKey"] as? String
  }
}
