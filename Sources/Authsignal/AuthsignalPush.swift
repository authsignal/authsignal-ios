import Foundation
import Security
import UIKit

public class AuthsignalPush {
  private let api: PushAPIClient
  private let cache = TokenCache.shared
  private let keyManager = KeyManager(keySuffix: "push")

  public init(tenantID: String, baseURL: String) {
    api = PushAPIClient(tenantID: tenantID, baseURL: baseURL)
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
      lastAuthenticatedAt: data.lastVerifiedAt,
      expiresAt: data.expiresAt
    )

    return AuthsignalResponse(data: credential)
  }

  public func addCredential(
    token: String? = nil,
    keychainAccess: KeychainAccess = .whenUnlockedThisDeviceOnly,
    userPresenceRequired: Bool = false,
    performAttestation: Bool = false,
    pushToken: String? = nil
  ) async -> AuthsignalResponse<AppCredential> {
    guard let userToken = token ?? cache.token else { return cache.handleTokenNotSetError() }

    guard let publicKey = keyManager.getOrCreatePublicKey(
      keychainAccess: keychainAccess,
      userPresenceRequired: userPresenceRequired
    ) else {
      return AuthsignalResponse(errorCode: SdkErrorCodes.createKeyPairFailed)
    }

    let attestationResponse = await AppAttestation.resolve(api: api, token: userToken, performAttestation: performAttestation)

    if let error = attestationResponse.error {
      return AuthsignalResponse(error: error, errorCode: attestationResponse.errorCode)
    }

    let attestationResult = attestationResponse.data ?? nil

    let deviceName = await UIDevice.current.name

    let response = await api.addCredential(
      token: userToken,
      publicKey: publicKey,
      deviceName: deviceName,
      pushToken: pushToken,
      performAttestation: attestationResult
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

  public func getChallenge() async -> AuthsignalResponse<AppChallenge?> {
    guard let publicKey = keyManager.getPublicKey() else {
      return AuthsignalResponse(errorCode: SdkErrorCodes.credentialNotFound)
    }

    var signature: String? = nil

    if let secKey = keyManager.getKey() {
      let nonceResponse = await api.getChallengeNonce(publicKey: publicKey)

      if let nonce = nonceResponse.data?.message {
        signature = Signature.sign(message: nonce, privateKey: secKey).data
      }
    }

    let response = await api.getChallenge(publicKey: publicKey, signature: signature)

    if let error = response.error {
      return AuthsignalResponse(error: error, errorCode: response.errorCode)
    }
    
    guard let data = response.data else {
      return AuthsignalResponse(error: response.error, errorCode: response.errorCode)
    }
    
    guard let challengeId = data.challengeId, let userId = data.userId else {
      return AuthsignalResponse(data: nil)
    }
    
    let pushChallenge = AppChallenge(
      challengeId: challengeId,
      userId: userId,
      actionCode: data.actionCode,
      idempotencyKey: data.idempotencyKey,
      deviceId: data.deviceId,
      userAgent:data.userAgent,
      ipAddress: data.ipAddress,
      expiresAt: data.expiresAt,
      custom: data.custom,
      user: data.user
    )
    
    return AuthsignalResponse(data: pushChallenge)
  }

  public func updateCredential(
    pushToken: String? = nil,
    resetExpiry: Bool = false
  ) async -> AuthsignalResponse<UpdateCredentialResponse> {
    let secKey = keyManager.getKey()
    let publicKey = keyManager.getPublicKey()

    guard let secKey = secKey, let publicKey = publicKey else {
      return AuthsignalResponse(errorCode: SdkErrorCodes.credentialNotFound)
    }

    let signingMessageResponse = await api.getSigningMessage(publicKey: publicKey)

    if let error = signingMessageResponse.error {
      return AuthsignalResponse(error: error, errorCode: signingMessageResponse.errorCode)
    }

    // A 200 with missing fields is a protocol error, not a silent no-op.
    guard let challengeId = signingMessageResponse.data?.challengeId,
          let messageToSign = signingMessageResponse.data?.message
    else {
      return AuthsignalResponse(error: "Invalid signing message response.")
    }

    let signatureResponse = Signature.sign(message: messageToSign, privateKey: secKey)

    guard let signature = signatureResponse.data else {
      return AuthsignalResponse(error: signatureResponse.error)
    }

    let response = await api.updateCredential(
      challengeId: challengeId,
      publicKey: publicKey,
      signature: signature,
      pushToken: pushToken,
      resetExpiry: resetExpiry ? true : nil
    )

    if let error = response.error {
      return AuthsignalResponse(error: error, errorCode: response.errorCode)
    }

    guard let data = response.data else {
      return AuthsignalResponse(error: "Invalid update credential response.")
    }

    return AuthsignalResponse(data: data)
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
