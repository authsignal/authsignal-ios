import Foundation
import Security
import UIKit

public class AuthsignalPasskey {
  private let api: PasskeyAPIClient
  private let passkeyManager: PasskeyManager
  private let passkeyLocalKey = "@as_passkey_credential_id"

  public init(tenantID: String, baseURL: String) {
    api = PasskeyAPIClient(tenantID: tenantID, baseURL: baseURL)
    passkeyManager = PasskeyManager()
  }

  public func signUp(token: String, username: String? = nil, displayName: String? = nil) async -> AuthsignalResponse<SignUpResponse> {
    let optsResponse = await api.registrationOptions(token: token, username: username, displayName: displayName)

    guard let optsData = optsResponse.data else {
      return AuthsignalResponse(error: optsResponse.error ?? "registration options error")
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
      token: token
    )
    
    guard let resultToken = addAuthenticatorResponse.data?.accessToken else {
      return AuthsignalResponse(error: addAuthenticatorResponse.error ?? "add authenticator error")
    }
    
    UserDefaults.standard.set(credential.rawId, forKey: passkeyLocalKey)

    let signUpResponse = SignUpResponse(token: resultToken)
    
    return AuthsignalResponse(data: signUpResponse)
  }

  public func signIn(
    token: String? = nil,
    action: String? = nil,
    autofill: Bool = false,
    preferImmediatelyAvailableCredentials: Bool = true
  ) async -> AuthsignalResponse<SignInResponse> {
    if (token != nil && autofill) {
      let error = "autofill is not supported when providing a token"
      
      Logger.error("Error: \(error)")
      
      return AuthsignalResponse(error: error)
    }
    
    if (token != nil && action != nil) {
      let error = "action is not supported when providing a token"
      
      Logger.error("Error: \(error)")
      
      return AuthsignalResponse(error: error)
    }
    
    let challengeResponse = action != nil ? await api.challenge(action: action!) : nil
    
    let challengeID = challengeResponse?.data?.challengeId
    
    let optsResponse = await api.authenticationOptions(challengeID: challengeID, token: token)

    guard let optsData = optsResponse.data else {
      return AuthsignalResponse(error: optsResponse.error ?? "authentication options error")
    }

    let credentialResponse = await passkeyManager.auth(
      relyingPartyID: optsData.options.rpId,
      challenge: optsData.options.challenge,
      autofill: autofill,
      preferImmediatelyAvailableCredentials: preferImmediatelyAvailableCredentials
    )
    
    if let errorCode = credentialResponse.errorCode {
      return AuthsignalResponse(errorCode: errorCode)
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
      return AuthsignalResponse(error: verifyResponse.error ?? "verify error")
    }
    
    let signInResponse = SignInResponse(
      isVerified: data.isVerified,
      token: data.accessToken,
      userId: data.userId,
      userAuthenticatorId: data.userAuthenticatorId,
      username: data.username,
      userDisplayName: data.userDisplayName
    )
    
    if (data.isVerified) {
      UserDefaults.standard.set(credential.rawId, forKey: passkeyLocalKey)
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
      return AuthsignalResponse(data: false, error: error)
    } else {
      return AuthsignalResponse(data: true)
    }
  }
}
