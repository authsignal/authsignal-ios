import Foundation
import Security
import UIKit

public class AuthsignalPush {
  private let api: PushAPIClient
  private let cache = TokenCache.shared

  public init(tenantID: String, baseURL: String) {
    api = PushAPIClient(tenantID: tenantID, baseURL: baseURL)
  }

  public func getCredential() async -> AuthsignalResponse<PushCredential> {
    let secKey = KeyManager.getKey()

    guard let secKey = secKey else {
      return AuthsignalResponse(error: nil)
    }

    let publicKey = KeyManager.derivePublicKey(secKey: secKey)

    guard let publicKey = publicKey else {
      return AuthsignalResponse(error: "Error deriving public key")
    }

    let response = await api.getCredential(publicKey: publicKey)

    if let error = response.error {
      return AuthsignalResponse(error: error)
    }
    
    guard let data = response.data else {
      return AuthsignalResponse(error: nil)
    }

    let credential = PushCredential(
      credentialId: data.userAuthenticatorId,
      createdAt: data.verifiedAt,
      lastAuthenticatedAt: data.lastVerifiedAt
    )

    return AuthsignalResponse(data: credential)
  }

  public func addCredential(token: String? = nil) async -> AuthsignalResponse<Bool> {
    guard let userToken = token ?? cache.token else { return cache.handleTokenNotSetError() }
    
    guard let publicKey = KeyManager.getOrCreatePublicKey() else {
      return AuthsignalResponse(error: "Unable to generate key pair")
    }

    let deviceName = await UIDevice.current.name

    let response = await api.addCredential(
      token: userToken,
      publicKey: publicKey,
      deviceName: deviceName
    )
    
    guard let data = response.data else {
      return AuthsignalResponse(error: response.error)
    }
    
    let success = data.userAuthenticatorId != nil

    return AuthsignalResponse(data: success)
  }

  public func removeCredential() async -> AuthsignalResponse<Bool> {
    let secKey = KeyManager.getKey()

    guard let secKey = secKey else {
      return AuthsignalResponse(error: "Key pair not found")
    }

    let publicKey = KeyManager.derivePublicKey(secKey: secKey)

    guard let publicKey = publicKey else {
      return AuthsignalResponse(error: "Error deriving public key")
    }

    var signature: String? = nil

    let message = getTimeBasedDataToSign()

    do {
      signature = try Signature.sign(message: message, privateKey: secKey)
    } catch {
      return AuthsignalResponse(error: "Error generating signature. \(error)")
    }

    let response = await api.removeCredential(publicKey: publicKey, signature: signature!)

    guard let data = response.data else {
      return AuthsignalResponse(error: response.error)
    }
    
    let success = data.removedAuthenticatorId != nil

    if success {
      return AuthsignalResponse(data: KeyManager.deleteKeyPair())
    }

    return AuthsignalResponse(error: "Error removing authenticator")
  }

  public func getChallenge() async -> AuthsignalResponse<PushChallenge?> {
    guard let publicKey = KeyManager.getPublicKey() else {
      return AuthsignalResponse(error: "Key pair not found")
    }

    let response = await api.getChallenge(publicKey: publicKey)

    if let error = response.error {
      return AuthsignalResponse(error: error)
    }
    
    guard let data = response.data else {
      return AuthsignalResponse(error: response.error)
    }
    
    guard let challengeId = data.challengeId else {
      return AuthsignalResponse(data: nil)
    }
    
    let pushChallenge = PushChallenge(
      challengeId: challengeId,
      actionCode: data.actionCode,
      idempotencyKey: data.idempotencyKey,
      deviceId: data.deviceId,
      userAgent:data.userAgent,
      ipAddress: data.ipAddress
    )
    
    return AuthsignalResponse(data: pushChallenge)
  }

  public func updateChallenge(
    challengeId: String,
    approved: Bool,
    verificationCode: String? = nil
  ) async -> AuthsignalResponse<Bool> {
    let secKey = KeyManager.getKey()

    guard let secKey = secKey else {
      return AuthsignalResponse(error: "Key pair not found")
    }

    let publicKey = KeyManager.derivePublicKey(secKey: secKey)

    guard let publicKey = publicKey else {
      return AuthsignalResponse(error: "Error deriving public key")
    }

    var signature: String? = nil

    do {
      signature = try Signature.sign(message: challengeId, privateKey: secKey)
    } catch {
      return AuthsignalResponse(error: "Error generating signature. \(error)")
    }

    let response = await api.updateChallenge(
      challengeId: challengeId,
      publicKey: publicKey,
      signature: signature!,
      approved: approved,
      verificationCode: verificationCode
    )
    
    return AuthsignalResponse(data: response.data != nil, error: response.error)
  }

  private func getTimeBasedDataToSign() -> String {
    let secondsSinceEpoch = Double(Date().timeIntervalSince1970)

    return String(floor(secondsSinceEpoch / (60 * 10)))
  }
}
