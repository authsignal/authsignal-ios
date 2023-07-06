import Foundation
import Security
import UIKit

public class AuthsignalPasskey {
  private let api: PasskeyAPIClient
  private let passkeyManager: PasskeyManager

  public init(tenantID: String, baseURL: String) {
    api = PasskeyAPIClient(tenantID: tenantID, baseURL: baseURL)
    passkeyManager = PasskeyManager()
  }

  public func signUp(token: String, userName: String? = nil) async -> AuthsignalResponse<String> {
    let optsResponse = await api.registrationOptions(userName: userName, token: token)

    guard let optsData = optsResponse.data else {
      return AuthsignalResponse(error: optsResponse.error ?? "registration options error")
    }

    let credentialResponse = await passkeyManager.register(
      relyingPartyID: optsData.options.rp.id,
      challenge: optsData.options.challenge,
      userID: optsData.options.user.id,
      displayName: optsData.options.user.displayName
    )

    guard let credential = credentialResponse.data else {
      return AuthsignalResponse(error: optsResponse.error ?? "passkey registration error")
    }

    let addAuthenticatorResponse = await api.addAuthenticator(
      challengeID: optsData.challengeId,
      credential: credential,
      token: token
    )
    
    guard let resultToken = addAuthenticatorResponse.data?.accessToken else {
      return AuthsignalResponse(error: addAuthenticatorResponse.error ?? "add authenticator error")
    }

    return AuthsignalResponse(data: resultToken)
  }

  public func signIn(token: String? = nil, autofill: Bool = false) async -> AuthsignalResponse<String> {
    if (token != nil && autofill) {
      let error = "autofill is not supported when providing a token"
      
      Logger.error("Error: \(error)")
      
      return AuthsignalResponse(error: error)
    }
    
    let optsResponse = await api.authenticationOptions(token: token)

    guard let optsData = optsResponse.data else {
      return AuthsignalResponse(error: optsResponse.error ?? "authentication options error")
    }

    let credentialResponse = await passkeyManager.auth(
      relyingPartyID: optsData.options.rpId,
      challenge: optsData.options.challenge,
      autofill: autofill
    )

    guard let credential = credentialResponse.data else {
      return AuthsignalResponse(error: optsResponse.error ?? "passkey authentication error")
    }

    let verifyResponse = await api.verify(
      challengeID: optsData.challengeId,
      credential: credential
    )
    
    guard let resultToken = verifyResponse.data?.accessToken else {
      return AuthsignalResponse(error: verifyResponse.error ?? "verify error")
    }

    return AuthsignalResponse(data: resultToken)
  }

  public func cancel() {
    passkeyManager.cancelRequest()
  }
}
