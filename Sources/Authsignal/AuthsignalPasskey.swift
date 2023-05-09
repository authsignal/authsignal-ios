import Foundation
import Security
import UIKit

public class AuthsignalPasskey {
  private let api: PasskeyAPIClient
  private let passkeyManager: PasskeyManager

  public init(clientID: String, baseURL: String) {
    api = PasskeyAPIClient(clientID: clientID, baseURL: baseURL)
    passkeyManager = PasskeyManager()
  }
  
  public func enroll(token: String, userName: String) async -> AddAuthenticatorResponse? {
    let optsResponse = await api.registrationOptions(token: token, userName: userName)
    
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
      token: token,
      challengeID: optsResponse.challengeId,
      credential: credential
    )
    
    return addAuthenticatorResponse
  }
  
  public func challenge(userName: String? = nil, autofill: Bool = false) async -> VerifyResponse? {
    let optsResponse = await api.authenticationOptions(userName: userName)
    
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
    
    return verifyResponse
  }
  
  public func cancel() {
    passkeyManager.cancelRequest()
  }
}
