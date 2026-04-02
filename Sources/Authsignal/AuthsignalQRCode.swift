import Foundation
import Security
import UIKit
import DeviceCheck
import CryptoKit

public class AuthsignalQRCode {
  private let api: QRCodeAPIClient
  private let cache = TokenCache.shared
  private let keyManager = KeyManager(keySuffix: "qr_code")

  public init(tenantID: String, baseURL: String) {
    api = QRCodeAPIClient(tenantID: tenantID, baseURL: baseURL)
  }

  public func getCredential() async -> AuthsignalResponse<AppCredential> {
    guard let publicKey = keyManager.getPublicKey() else {
      return AuthsignalResponse(errorCode: SdkErrorCodes.credentialNotFound)
    }

    let response = await api.getCredential(publicKey: publicKey)

    if let error = response.error {
      return AuthsignalResponse(error: error, errorCode: response.errorCode)
    }
    
    guard let data = response.data else {
      return AuthsignalResponse(error: nil)
    }

    let credential = AppCredential(
      credentialId: data.userAuthenticatorId,
      createdAt: data.verifiedAt,
      userId: data.userId,
      lastAuthenticatedAt: data.lastVerifiedAt
    )

    return AuthsignalResponse(data: credential)
  }

  public func addCredential(
    token: String? = nil,
    keychainAccess: KeychainAccess = .whenUnlockedThisDeviceOnly,
    userPresenceRequired: Bool = false,
    performAttestation: Bool = false
  ) async -> AuthsignalResponse<AppCredential> {
    guard let userToken = token ?? cache.token else { return cache.handleTokenNotSetError() }

    guard let publicKey = keyManager.getOrCreatePublicKey(
      keychainAccess: keychainAccess,
      userPresenceRequired: userPresenceRequired
    ) else {
      return AuthsignalResponse(errorCode: SdkErrorCodes.createKeyPairFailed)
    }

    var resolvedIntegrity: DeviceIntegrity? = nil
    if performAttestation {
      if #available(iOS 14.0, *), DCAppAttestService.shared.isSupported {
        do {
          guard let idempotencyKey = Self.extractIdempotencyKey(from: userToken) else {
            return AuthsignalResponse(error: "Failed to extract idempotencyKey from token", errorCode: "invalid_token")
          }

          let nonce = idempotencyKey
          let nonceData = Data(nonce.utf8)
          let nonceHash = Data(SHA256.hash(data: nonceData))

          let keyId = try await DCAppAttestService.shared.generateKey()
          let integrityData = try await DCAppAttestService.shared.attestKey(keyId, clientDataHash: nonceHash)
          let integrityToken = integrityData.base64EncodedString()

          resolvedIntegrity = DeviceIntegrity(integrityToken: integrityToken, keyId: keyId)
        } catch {
          Logger.error("App Attest failed: \(error.localizedDescription)")
        }
      }
    }

    let deviceName = await UIDevice.current.name

    let response = await api.addCredential(
      token: userToken,
      publicKey: publicKey,
      deviceName: deviceName,
      performAttestation: resolvedIntegrity
    )
    
    guard let data = response.data else {
      return AuthsignalResponse(error: response.error, errorCode: response.errorCode)
    }
    
    let credential = AppCredential(
      credentialId: data.userAuthenticatorId,
      createdAt: data.verifiedAt,
      userId: data.userId,
      lastAuthenticatedAt: data.verifiedAt
    )

    return AuthsignalResponse(data: credential)
  }

  public func removeCredential() async -> AuthsignalResponse<Bool> {
    let secKey = keyManager.getKey()
    let publicKey = keyManager.getPublicKey()

    guard let secKey = secKey, let publicKey = publicKey else {
      return AuthsignalResponse(data: false)
    }

    let signatureResponse = Signature.signWithTimeBasedMessage(privateKey: secKey)
    
    guard let signature = signatureResponse.data else {
      return AuthsignalResponse(error: signatureResponse.error)
    }

    let response = await api.removeCredential(publicKey: publicKey, signature: signature)

    return AuthsignalResponse(
      data: keyManager.deleteKeyPair(),
      error: response.error,
      errorCode: response.errorCode
    )
  }

  public func claimChallenge(
    challengeId: String
  ) async -> AuthsignalResponse<ClaimChallengeResponse> {
    let secKey = keyManager.getKey()
    let publicKey = keyManager.getPublicKey()

    guard let secKey = secKey, let publicKey = publicKey else {
      return AuthsignalResponse(errorCode: SdkErrorCodes.credentialNotFound)
    }

    let signatureResponse = Signature.sign(message: challengeId, privateKey: secKey)
    
    guard let signature = signatureResponse.data else {
      return AuthsignalResponse(error: signatureResponse.error)
    }

    let response = await api.claimChallenge(
      challengeId: challengeId,
      publicKey: publicKey,
      signature: signature
    )
    
    if let data = response.data {
      return AuthsignalResponse(data: data)
    } else {
      return AuthsignalResponse(
        error: response.error,
        errorCode: response.errorCode
      )
    }
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

  public func updateChallenge(
    challengeId: String,
    approved: Bool,
    verificationCode: String? = nil
  ) async -> AuthsignalResponse<Bool> {
    let secKey = keyManager.getKey()
    let publicKey = keyManager.getPublicKey()

    guard let secKey = secKey, let publicKey = publicKey else {
      return AuthsignalResponse(errorCode: SdkErrorCodes.credentialNotFound)
    }

    let signatureResponse = Signature.sign(message: challengeId, privateKey: secKey)
    
    guard let signature = signatureResponse.data else {
      return AuthsignalResponse(error: signatureResponse.error)
    }

    let response = await api.updateChallenge(
      challengeId: challengeId,
      publicKey: publicKey,
      signature: signature,
      approved: approved,
      verificationCode: verificationCode
    )
    
    if let error = response.error {
      return AuthsignalResponse(
        error: error,
        errorCode: response.errorCode
      )
    } else {
      return AuthsignalResponse(data: response.data != nil)
    }
  }
} 
