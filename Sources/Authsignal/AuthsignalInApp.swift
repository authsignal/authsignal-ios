import Foundation
import Security
import UIKit

public class AuthsignalInApp {
  private let api: InAppAPIClient
  private let cache = TokenCache.shared
  private let keyManager = KeyManager(keySuffix: "in_app")
  private let pinManager = PinManager()
  private let tenantID: String

  public init(tenantID: String, baseURL: String) {
    self.tenantID = tenantID
    api = InAppAPIClient(tenantID: tenantID, baseURL: baseURL)
  }

  public func getCredential(username: String? = nil) async -> AuthsignalResponse<AppCredential> {
    guard let publicKey = keyManager.getPublicKey(username: username) else {
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
    username: String? = nil,
    performAttestation: Bool = false
  ) async -> AuthsignalResponse<AppCredential> {
    guard let userToken = token ?? cache.token else { return cache.handleTokenNotSetError() }

    guard let publicKey = keyManager.getOrCreatePublicKey(
      keychainAccess: keychainAccess,
      userPresenceRequired: userPresenceRequired,
      username: username
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

  public func removeCredential(username: String? = nil) async -> AuthsignalResponse<Bool> {
    let secKey = keyManager.getKey(username: username)
    let publicKey = keyManager.getPublicKey(username: username)

    guard let secKey = secKey, let publicKey = publicKey else {
      return AuthsignalResponse(
        error: "No credential found on this device.",
        errorCode: SdkErrorCodes.credentialNotFound
      )
    }

    let signatureResponse = Signature.signWithTimeBasedMessage(privateKey: secKey)
    
    guard let signature = signatureResponse.data else {
      return AuthsignalResponse(error: signatureResponse.error)
    }

    let response = await api.removeCredential(publicKey: publicKey, signature: signature)

    if let error = response.error {
      return AuthsignalResponse(error: error, errorCode: response.errorCode)
    }

    return AuthsignalResponse(data: keyManager.deleteKeyPair(username: username))
  }
  
  public func verify(action: String? = nil, username: String? = nil) async -> AuthsignalResponse<InAppVerifyResponse> {
    let challengeResponse = await api.challenge(action: action)
    
    guard let challengeId = challengeResponse.data?.challengeId else {
      return AuthsignalResponse(error: challengeResponse.error ?? "Error generating challenge.")
    }
    
    let secKey = keyManager.getKey(username: username)
    let publicKey = keyManager.getPublicKey(username: username)

    guard let secKey = secKey, let publicKey = publicKey else {
      return AuthsignalResponse(
        error: "No credential found on this device.",
        errorCode: SdkErrorCodes.credentialNotFound
      )
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
  
  public func createPin(pin: String, username: String, token: String? = nil) async -> AuthsignalResponse<AppCredential> {
    guard pinManager.validateFormat(pin: pin) else {
      return AuthsignalResponse(
        error: "Invalid PIN format.",
        errorCode: SdkErrorCodes.invalidPinFormat
      )
    }
    
    pinManager.createPin(pin: pin, username: username)
    
    return await addCredential(token: token, username: username)
  }
  
  public func verifyPin(pin: String, username: String, action: String? = nil) async -> AuthsignalResponse<VerifyPinResponse> {
    let isPinValid = pinManager.validatePin(pin: pin, username: username)
    
    if (isPinValid) {
      let verifyResponse = await verify(action: action, username: username)
      
      if let error = verifyResponse.error {
        return AuthsignalResponse(
          error: error,
          errorCode: verifyResponse.errorCode
        )
      }
      
      if let verifyResponseData = verifyResponse.data {
        let data = VerifyPinResponse(
          isVerified: true,
          token: verifyResponseData.token,
          userId: verifyResponseData.userId
        )
        
        return AuthsignalResponse(data: data)
      }
    }
    
    return AuthsignalResponse(
      data: VerifyPinResponse(isVerified: false)
    )
  }
  
  public func deletePin(username: String) async -> AuthsignalResponse<Bool> {
    let removeCredentialResponse = await removeCredential(username: username)

    let credentialAlreadyRemoved = removeCredentialResponse.errorCode == SdkErrorCodes.invalidCredential ||
      removeCredentialResponse.errorCode == SdkErrorCodes.credentialNotFound

    if removeCredentialResponse.data != true && !credentialAlreadyRemoved {
      return removeCredentialResponse
    }

    if credentialAlreadyRemoved {
      _ = keyManager.deleteKeyPair(username: username)
    }

    pinManager.deletePin(username: username)

    return AuthsignalResponse(data: true)
  }

  public func getAllPinUsernames() async -> AuthsignalResponse<[String]> {
    let usernames = pinManager.getAllUsernames()

    return AuthsignalResponse(data: usernames)
  }

}
