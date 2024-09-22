import Foundation
import Security
import UIKit

public class AuthsignalPasskey {
  private let api: PasskeyAPIClient
  private let passkeyManager: PasskeyManager
  private let passkeyLocalKey = "@as_passkey_credential_id"
  private let cache = TokenCache.shared

  public init(tenantID: String, baseURL: String) {
    api = PasskeyAPIClient(tenantID: tenantID, baseURL: baseURL)
    passkeyManager = PasskeyManager()
  }

  public func signUp(token: String? = nil, username: String? = nil, displayName: String? = nil) async -> AuthsignalResponse<SignUpResponse> {
    guard let userToken = token ?? cache.token else { return cache.handleTokenNotSetError() }
    
    let optsResponse = await api.registrationOptions(token: userToken, username: username, displayName: displayName)

    guard let optsData = optsResponse.data else {
      return AuthsignalResponse(
        error: optsResponse.error ?? "Registration options error.",
        errorCode: optsResponse.errorCode
      )
    }

    let credentialResponse = await passkeyManager.register(
      relyingPartyID: optsData.options.rp.id,
      challenge: optsData.options.challenge,
      userID: optsData.options.user.id,
      displayName: optsData.options.user.displayName
    )
    
    if let error = credentialResponse.error {
      return AuthsignalResponse(error: error)
    }

    guard let credential = credentialResponse.data else {
      return AuthsignalResponse(error: nil)
    }

    let addAuthenticatorResponse = await api.addAuthenticator(
      challengeID: optsData.challengeId,
      credential: credential,
      token: userToken
    )
    
    guard let responseToken = addAuthenticatorResponse.data?.accessToken else {
      return AuthsignalResponse(
        error: addAuthenticatorResponse.error ?? "Add authenticator error.",
        errorCode: addAuthenticatorResponse.errorCode
      )
    }
    
    UserDefaults.standard.set(credential.rawId, forKey: passkeyLocalKey)

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
    if (token != nil && autofill) {
      let error = "Autofill is not supported when providing a token."
      
      Logger.error("Error: \(error)")
      
      return AuthsignalResponse(error: error)
    }
    
    if (token != nil && action != nil) {
      let error = "Action is not supported when providing a token."
      
      Logger.error("Error: \(error)")
      
      return AuthsignalResponse(error: error)
    }
    
    let challengeResponse = action != nil ? await api.challenge(action: action!) : nil
    
    let challengeID = challengeResponse?.data?.challengeId
    
    let optsResponse = await api.authenticationOptions(challengeID: challengeID, token: token)

    guard let optsData = optsResponse.data else {
      return AuthsignalResponse(
        error: optsResponse.error ?? "Authentication options error.",
        errorCode: optsResponse.errorCode
      )
    }

    let credentialResponse = await passkeyManager.auth(
      relyingPartyID: optsData.options.rpId,
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
      challengeID: optsData.challengeId,
      credential: credential
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
      UserDefaults.standard.set(credential.rawId, forKey: passkeyLocalKey)
    }
    
    if let responseToken = data.accessToken {
      cache.token = responseToken
    }
    
    return AuthsignalResponse(data: signInResponse)
  }

  public func cancel() {
    passkeyManager.cancelRequest()
  }
  
  public func isAvailableOnDevice() async -> AuthsignalResponse<Bool> {
    guard let credentialId = UserDefaults.standard.string(forKey: passkeyLocalKey) else {
      return AuthsignalResponse(data: false)
    }
    
    let passkeyAuthenticatorResponse = await api.getPasskeyAuthenticator(credentialID: credentialId)
    
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
}
