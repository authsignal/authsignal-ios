import Foundation
import Security
import UIKit

public class AuthsignalDevice {
  private let api: DeviceAPIClient
  private let cache = TokenCache.shared

  public init(tenantID: String, baseURL: String) {
    api = DeviceAPIClient(tenantID: tenantID, baseURL: baseURL)
  }

  public func getCredential() async -> AuthsignalResponse<DeviceCredential> {
    let secKey = KeyManager.getKey()

    guard let secKey = secKey else {
      return AuthsignalResponse(error: nil)
    }

    let publicKey = KeyManager.derivePublicKey(secKey: secKey)

    guard let publicKey = publicKey else {
      return AuthsignalResponse(error: "Error deriving public key.")
    }

    let response = await api.getCredential(publicKey: publicKey)

    if let error = response.error {
      return AuthsignalResponse(error: error, errorCode: response.errorCode)
    }
    
    guard let data = response.data else {
      return AuthsignalResponse(error: nil)
    }

    let credential = DeviceCredential(
      credentialId: data.userAuthenticatorId,
      createdAt: data.verifiedAt,
      lastAuthenticatedAt: data.lastVerifiedAt
    )

    return AuthsignalResponse(data: credential)
  }

  public func addCredential(
    token: String? = nil,
    keychainAccess: KeychainAccess = .whenUnlockedThisDeviceOnly
  ) async -> AuthsignalResponse<Bool> {
    guard let userToken = token ?? cache.token else { return cache.handleTokenNotSetError() }
    
    guard let publicKey = KeyManager.getOrCreatePublicKey(keychainAccess: keychainAccess) else {
      return AuthsignalResponse(error: "Unable to generate key pair.")
    }

    let deviceName = await UIDevice.current.name

    let response = await api.addCredential(
      token: userToken,
      publicKey: publicKey,
      deviceName: deviceName
    )
    
    guard let data = response.data else {
      return AuthsignalResponse(error: response.error, errorCode: response.errorCode)
    }
    
    let success = data.userAuthenticatorId != nil

    return AuthsignalResponse(data: success)
  }

  public func removeCredential() async -> AuthsignalResponse<Bool> {
    let secKey = KeyManager.getKey()

    guard let secKey = secKey else {
      return AuthsignalResponse(error: "Key pair not found.")
    }

    let publicKey = KeyManager.derivePublicKey(secKey: secKey)

    guard let publicKey = publicKey else {
      return AuthsignalResponse(error: "Error deriving public key.")
    }

    var signature: String? = nil

    let message = getTimeBasedDataToSign()

    do {
      signature = try Signature.sign(message: message, privateKey: secKey)
    } catch {
      return AuthsignalResponse(error: "Error generating signature. \(error)")
    }

    let response = await api.removeCredential(publicKey: publicKey, signature: signature!)

    return AuthsignalResponse(
      data: KeyManager.deleteKeyPair(),
      error: response.error,
      errorCode: response.errorCode
    )
  }

  public func getChallenge() async -> AuthsignalResponse<DeviceChallenge?> {
    guard let publicKey = KeyManager.getPublicKey() else {
      return AuthsignalResponse(error: "Key pair not found.")
    }

    let response = await api.getChallenge(publicKey: publicKey)

    if let error = response.error {
      return AuthsignalResponse(error: error, errorCode: response.errorCode)
    }
    
    guard let data = response.data else {
      return AuthsignalResponse(error: response.error, errorCode: response.errorCode)
    }
    
    guard let challengeId = data.challengeId, let userId = data.userId else {
      return AuthsignalResponse(data: nil)
    }
    
    let deviceChallenge = DeviceChallenge(
      challengeId: challengeId,
      userId: userId,
      actionCode: data.actionCode,
      idempotencyKey: data.idempotencyKey,
      deviceId: data.deviceId,
      userAgent:data.userAgent,
      ipAddress: data.ipAddress
    )
    
    return AuthsignalResponse(data: deviceChallenge)
  }

  public func updateChallenge(
    challengeId: String,
    approved: Bool,
    verificationCode: String? = nil
  ) async -> AuthsignalResponse<Bool> {
    let secKey = KeyManager.getKey()

    guard let secKey = secKey else {
      return AuthsignalResponse(error: "Key pair not found.")
    }

    let publicKey = KeyManager.derivePublicKey(secKey: secKey)

    guard let publicKey = publicKey else {
      return AuthsignalResponse(error: "Error deriving public key.")
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
    
    if let error = response.error {
      return AuthsignalResponse(
        error: error,
        errorCode: response.errorCode
      )
    } else {
      return AuthsignalResponse(data: response.data != nil)
    }
  }

  private func getTimeBasedDataToSign() -> String {
    let secondsSinceEpoch = Double(Date().timeIntervalSince1970)

    return String(floor(secondsSinceEpoch / (60 * 10)))
  }
} 