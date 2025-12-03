import Foundation
import Security
import UIKit

public class AuthsignalPasskey {
  private let api: PasskeyAPIClient
  private let passkeyManager: PasskeyManager
  private let passkeyLocalKey = "@as_passkey_credential_id"
  private let cache = TokenCache.shared

  public init(tenantID: String, baseURL: String, deviceID: String? = nil) {
    api = PasskeyAPIClient(tenantID: tenantID, baseURL: baseURL, deviceID: deviceID)
    passkeyManager = PasskeyManager()
  }

  public func signUp(
    token: String? = nil,
    username: String? = nil,
    displayName: String? = nil,
    ignorePasskeyAlreadyExistsError: Bool = false
  ) async -> AuthsignalResponse<SignUpResponse> {
    guard let userToken = token ?? cache.token else { return cache.handleTokenNotSetError() }
    
    let optsResponse = await api.registrationOptions(token: userToken, username: username, displayName: displayName)

    guard let optsData = optsResponse.data else {
      return AuthsignalResponse(
        error: optsResponse.error ?? "Registration options error.",
        errorCode: optsResponse.errorCode
      )
    }

    let credentialResponse = await passkeyManager.register(
      relyingPartyId: optsData.options.rp.id,
      challenge: optsData.options.challenge,
      userId: optsData.options.user.id,
      displayName: optsData.options.user.displayName,
      existingCredentialIds: optsData.options.excludeCredentials.map { $0.id }
    )
    
    if ignorePasskeyAlreadyExistsError && credentialResponse.errorCode == SdkErrorCodes.matchedExcludedCredential {
      return AuthsignalResponse(error: nil)
    }
    
    if let error = credentialResponse.error {
      return AuthsignalResponse(error: error, errorCode: credentialResponse.errorCode)
    }

    guard let credential = credentialResponse.data else {
      return AuthsignalResponse(error: nil)
    }

    let addAuthenticatorResponse = await api.addAuthenticator(
      challengeId: optsData.challengeId,
      credential: credential,
      token: userToken
    )
    
    guard let responseToken = addAuthenticatorResponse.data?.accessToken else {
      return AuthsignalResponse(
        error: addAuthenticatorResponse.error ?? "Add authenticator error.",
        errorCode: addAuthenticatorResponse.errorCode
      )
    }
    
    storeCredentialId(credentialId: credential.rawId, username: optsResponse.data?.options.user.name)

    cache.token = responseToken
  
    let signUpResponse = SignUpResponse(token: responseToken)
    
    return AuthsignalResponse(data: signUpResponse)
  }

  public func signIn(
    token: String? = nil,
    action: String? = nil,
    autofill: Bool = false,
    preferImmediatelyAvailableCredentials: Bool = true
  ) async -> AuthsignalResponse<SignInResponse> {
    // Only use token if an action is not provided
    let userToken = action == nil ? token ?? cache.token : nil
    
    let challengeResponse = action != nil ? await api.challenge(action: action!) : nil
    
    let challengeId = challengeResponse?.data?.challengeId
    
    let optsResponse = await api.authenticationOptions(challengeId: challengeId, token: userToken)

    guard let optsData = optsResponse.data else {
      return AuthsignalResponse(
        error: optsResponse.error ?? "Authentication options error.",
        errorCode: optsResponse.errorCode
      )
    }

    let credentialResponse = await passkeyManager.auth(
      relyingPartyId: optsData.options.rpId,
      challenge: optsData.options.challenge,
      autofill: autofill,
      preferImmediatelyAvailableCredentials: preferImmediatelyAvailableCredentials
    )
    
    if let errorCode = credentialResponse.errorCode {
      return AuthsignalResponse(error: "Credential response error.", errorCode: errorCode)
    }
    
    if let error = credentialResponse.error {
      return AuthsignalResponse(error: error)
    }

    guard let credential = credentialResponse.data else {
      return AuthsignalResponse(error: nil)
    }

    let verifyResponse = await api.verify(
      challengeId: optsData.challengeId,
      credential: credential,
      token: userToken
    )
    
    guard let data = verifyResponse.data else {
      return AuthsignalResponse(
        error: verifyResponse.error ?? "Verify error.",
        errorCode: verifyResponse.errorCode
      )
    }
    
    let signInResponse = SignInResponse(
      isVerified: data.isVerified,
      token: data.accessToken,
      userId: data.userId,
      userAuthenticatorId: data.userAuthenticatorId,
      username: data.username,
      displayName: data.userDisplayName
    )
    
    if (data.isVerified) {
      storeCredentialId(credentialId: credential.rawId, username: data.username)
    }
    
    if let responseToken = data.accessToken {
      cache.token = responseToken
    }
    
    return AuthsignalResponse(data: signInResponse)
  }

  public func cancel() {
    passkeyManager.cancelRequest()
  }
  
  public func isSupported() -> Bool {
    if #available(iOS 15.0, *) {
      return true
    } else {
      return false
    }
  }
  
  public func shouldPromptToCreatePasskey(username: String? = nil) async -> AuthsignalResponse<Bool> {
    guard let credentialId = getStoredCredentialId(username: username) else {
      return AuthsignalResponse(data: true)
    }
    
    let passkeyAuthenticatorResponse = await api.getPasskeyAuthenticator(credentialId: credentialId)
    
    if passkeyAuthenticatorResponse.errorCode == SdkErrorCodes.invalidCredential  {
      return AuthsignalResponse(data: true)
    }
    
    return AuthsignalResponse(
      data: false,
      error: passkeyAuthenticatorResponse.error,
      errorCode: passkeyAuthenticatorResponse.errorCode
    )
  }
  
  @available(*, deprecated, message: "Use 'preferImmediatelyAvailableCredentials' to control what happens when a passkey isn't available.")
  public func isAvailableOnDevice() async -> AuthsignalResponse<Bool> {
    guard let credentialId = getStoredCredentialId(username: nil) else {
      return AuthsignalResponse(data: false)
    }
    
    let passkeyAuthenticatorResponse = await api.getPasskeyAuthenticator(credentialId: credentialId)
    
    if let error = passkeyAuthenticatorResponse.error {
      return AuthsignalResponse(
        data: false,
        error: error,
        errorCode: passkeyAuthenticatorResponse.errorCode
      )
    } else {
      return AuthsignalResponse(data: true)
    }
  }

  private func storeCredentialId(credentialId: String, username: String?) {
    UserDefaults.standard.set(credentialId, forKey: passkeyLocalKey)
    
    if let username = username {
      UserDefaults.standard.set(credentialId, forKey: "\(passkeyLocalKey)_\(username)")
    }
  }
  
  private func getStoredCredentialId(username: String?) -> String? {
    let key = username.map { "\(passkeyLocalKey)_\($0)" } ?? passkeyLocalKey
    
    return UserDefaults.standard.string(forKey: key)
  }
}
