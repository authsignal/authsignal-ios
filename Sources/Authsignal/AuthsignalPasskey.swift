import Foundation
import Security
import UIKit

public class AuthsignalPasskey {
  private let api: PasskeyAPIClient
  private let passkeyManager: PasskeyManager
  private let passkeySignalManager = PasskeySignalManager()
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
    ignorePasskeyAlreadyExistsError: Bool = false,
    syncCredentials: Bool = true
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
    
    guard let data = addAuthenticatorResponse.data, let responseToken = data.accessToken else {
      return AuthsignalResponse(
        error: addAuthenticatorResponse.error ?? "Add authenticator error.",
        errorCode: addAuthenticatorResponse.errorCode
      )
    }

    if data.isVerified {
      storeCredentialId(credentialId: credential.rawId, username: optsResponse.data?.options.user.name)
    }

    cache.token = responseToken

    if syncCredentials && data.isVerified {
      let rpId = optsData.options.rp.id
      let userHandle = optsData.options.user.id
      let credentialId = credential.rawId

      Task {
        await self.syncPasskeysWithCredentialManager(
          rpId: rpId,
          userHandle: userHandle,
          credentialId: credentialId,
          token: responseToken
        )
      }
    }

    let signUpResponse = SignUpResponse(token: responseToken)

    return AuthsignalResponse(data: signUpResponse)
  }

  public func signIn(
    token: String? = nil,
    action: String? = nil,
    autofill: Bool = false,
    preferImmediatelyAvailableCredentials: Bool = true,
    syncCredentials: Bool = true
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
      // The credential is no longer known to the server (e.g. the passkey was
      // deleted from the Authsignal portal). Signal this to the system so it can
      // remove or hide the stale passkey.
      if syncCredentials && verifyResponse.errorCode == SdkErrorCodes.unknownCredential {
        Logger.info("Passkey sync: signaling unknown credential to the system.")

        await passkeySignalManager.signalUnknownCredential(
          rpId: optsData.options.rpId,
          credentialId: credential.rawId
        )

        removeStoredCredentialId(credentialId: credential.rawId)
      }

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

    if syncCredentials, data.isVerified, let responseToken = data.accessToken {
      let rpId = optsData.options.rpId
      let userHandle = credential.response.userHandle
      let credentialId = credential.rawId

      Task {
        await self.syncPasskeysWithCredentialManager(
          rpId: rpId,
          userHandle: userHandle,
          credentialId: credentialId,
          token: responseToken
        )
      }
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

  private func syncPasskeysWithCredentialManager(
    rpId: String,
    userHandle: String,
    credentialId: String,
    token: String
  ) async {
    let authenticatorsResponse = await api.getAuthenticators(token: token)

    guard let authenticators = authenticatorsResponse.data else {
      Logger.error(
        "Could not fetch authenticators for passkey sync: \(authenticatorsResponse.error ?? "Unknown error.")"
      )

      return
    }

    let credentialIds = buildAcceptedCredentialIds(
      authenticators: authenticators,
      currentCredentialId: credentialId
    )

    Logger.info("Passkey sync: reporting \(credentialIds.count) accepted credential(s) to the system.")

    // The user handle stored against the passkey on the device is the UTF-8
    // bytes of the WebAuthn user id (see PasskeyManager.register, which passes
    // `Data(userId.utf8)` as the userID), so reconstruct those raw bytes here.
    let userHandleData = Data(userHandle.utf8)

    await passkeySignalManager.signalAllAcceptedCredentials(
      rpId: rpId,
      userHandle: userHandleData,
      credentialIds: credentialIds
    )
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

  private func removeStoredCredentialId(credentialId: String) {
    let defaults = UserDefaults.standard

    for (key, value) in defaults.dictionaryRepresentation() {
      if key.hasPrefix(passkeyLocalKey), value as? String == credentialId {
        defaults.removeObject(forKey: key)
      }
    }
  }
}
