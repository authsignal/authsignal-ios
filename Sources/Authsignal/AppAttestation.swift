import Foundation
import DeviceCheck
import CryptoKit

class AppAttestation {
  static func resolve(api: BaseAPIClient, token: String, performAttestation: Bool) async -> AuthsignalResponse<AppAttestationResult?> {
    guard performAttestation else { return AuthsignalResponse(data: nil) }

    let challengeResponse = await api.challenge(token: token)

    guard let nonce = challengeResponse.data?.nonce else {
      return AuthsignalResponse(error: challengeResponse.error ?? "Error generating challenge.")
    }

    return AuthsignalResponse(data: await resolve(nonce: nonce))
  }

  private static func resolve(nonce: String) async -> AppAttestationResult? {
    if #available(iOS 14.0, *), DCAppAttestService.shared.isSupported {
      do {
        let nonceData = Data(nonce.utf8)
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
}
