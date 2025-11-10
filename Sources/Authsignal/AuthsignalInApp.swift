import Foundation
import Security
import UIKit

public class AuthsignalInApp {
  private let api: InAppAPIClient
  private let cache = TokenCache.shared
  private let keyManager = KeyManager(keySuffix: "in_app")

  public init(tenantID: String, baseURL: String) {
    api = InAppAPIClient(tenantID: tenantID, baseURL: baseURL)
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
    userPresenceRequired: Bool = false
  ) async -> AuthsignalResponse<AppCredential> {
    guard let userToken = token ?? cache.token else { return cache.handleTokenNotSetError() }
    
    guard let publicKey = keyManager.getOrCreatePublicKey(
      keychainAccess: keychainAccess,
      userPresenceRequired: userPresenceRequired
    ) else {
      return AuthsignalResponse(errorCode: SdkErrorCodes.createKeyPairFailed)
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
  
  public func verify(action: String? = nil) async -> AuthsignalResponse<InAppVerifyResponse> {
    let challengeResponse = await api.challenge(action: action)
    
    guard let challengeId = challengeResponse.data?.challengeId else {
      return AuthsignalResponse(error: challengeResponse.error ?? "Error generating challenge.")
    }
    
    let secKey = keyManager.getKey()
    let publicKey = keyManager.getPublicKey()

    guard let secKey = secKey, let publicKey = publicKey else {
      return AuthsignalResponse(errorCode: SdkErrorCodes.credentialNotFound)
    }
    
    let signatureResponse = Signature.sign(message: challengeId, privateKey: secKey)
    
    guard let signature = signatureResponse.data else {
      return AuthsignalResponse(error: signatureResponse.error)
    }
    
    // Only set a user token if an action is not provided
    let userToken = action == nil ? cache.token : nil

    let response = await api.verify(
      challengeId: challengeId,
      publicKey: publicKey,
      signature: signature,
      token: userToken
    )
    
    if let error = response.error {
      return AuthsignalResponse(
        error: error,
        errorCode: response.errorCode
      )
    } else {
      return AuthsignalResponse(data: response.data!)
    }
  }
} 
