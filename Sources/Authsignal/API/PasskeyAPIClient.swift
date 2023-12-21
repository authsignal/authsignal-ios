import Foundation

class PasskeyAPIClient: BaseAPIClient {
  func registrationOptions(
    token: String,
    userName: String? = nil,
    displayName: String? = nil
  ) async -> AuthsignalResponse<RegistrationOptsResponse> {
    let url = "\(baseURL)/client/user-authenticators/passkey/registration-options"

    let body = RegistrationOptsRequest(username: userName, displayName: displayName)

    return await postRequest(url: url, body: body, token: token)
  }

  func authenticationOptions(
    userName: String? = nil,
    token: String? = nil
  ) async -> AuthsignalResponse<AuthenticationOptsResponse> {
    let url = "\(baseURL)/client/user-authenticators/passkey/authentication-options"
  
    let body = AuthenticationOptsRequest(username: userName)

    return await postRequest(url: url, body: body, token: token)
  }

  func addAuthenticator(
    challengeID: String,
    credential: PasskeyRegistrationCredential,
    token: String
  ) async -> AuthsignalResponse<AddAuthenticatorResponse> {
    let url = "\(baseURL)/client/user-authenticators/passkey"

    let body = AddAuthenticatorRequest(
      challengeId: challengeID,
      registrationCredential: credential
    )

    return await postRequest(url: url, body: body, token: token)
  }

  func verify(
    challengeID: String,
    credential: PasskeyAuthenticationCredential,
    token: String? = nil
  ) async -> AuthsignalResponse<VerifyResponse> {
    let url = "\(baseURL)/client/verify/passkey"

    let body = VerifyRequest(
      challengeId: challengeID,
      authenticationCredential: credential
    )

    return await postRequest(url: url, body: body, token: token)
  }
}
