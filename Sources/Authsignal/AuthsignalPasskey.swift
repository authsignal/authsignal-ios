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

  public func signUp(token: String, userName: String? = nil) async -> String? {
    let optsResponse = await api.registrationOptions(userName: userName, token: token)

    guard let optsResponse = optsResponse else {
      return nil
    }

    let credential = await passkeyManager.register(
      relyingPartyID: optsResponse.options.rp.id,
      challenge: optsResponse.options.challenge,
      userID: optsResponse.options.user.id,
      displayName: optsResponse.options.user.displayName
    )

    guard let credential = credential else {
      return nil
    }

    let addAuthenticatorResponse = await api.addAuthenticator(
      challengeID: optsResponse.challengeId,
      credential: credential,
      token: token
    )

    return addAuthenticatorResponse?.accessToken
  }

  public func signIn(token: String? = nil, autofill: Bool = false) async -> String? {
    if (token != nil && autofill) {
      Logger.error("Autofill is not supported when providing a token.")
      
      return nil
    }
    
    let optsResponse = await api.authenticationOptions(token: token)

    guard let optsResponse = optsResponse else {
      return nil
    }

    let credential = await passkeyManager.auth(
      relyingPartyID: optsResponse.options.rpId,
      challenge: optsResponse.options.challenge,
      autofill: autofill
    )

    guard let credential = credential else {
      return nil
    }

    let verifyResponse = await api.verify(
      challengeID: optsResponse.challengeId,
      credential: credential
    )

    return verifyResponse?.accessToken
  }

  public func cancel() {
    passkeyManager.cancelRequest()
  }
}
