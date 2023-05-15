import Foundation

class PasskeyAPIClient: BaseAPIClient {
  func registrationOptions(userName: String, token: String) async -> RegistrationOptsResponse? {
    let url = "\(baseURL)/user-authenticators/passkey/registration-options"

    let body = RegistrationOptsRequest(username: userName)

    return await postRequest(url: url, body: body, token: token)
  }

  func authenticationOptions(userName: String? = nil, token: String? = nil) async -> AuthenticationOptsResponse? {
    let url = "\(baseURL)/user-authenticators/passkey/authentication-options"
  
    let body = AuthenticationOptsRequest(username: userName)

    return await postRequest(url: url, body: body, token: token)
  }

  func addAuthenticator(
    challengeID: String,
    credential: PasskeyRegistrationCredential,
    token: String
  ) async -> AddAuthenticatorResponse? {
    let url = "\(baseURL)/user-authenticators/passkey"

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
  ) async -> VerifyResponse? {
    let url = "\(baseURL)/verify/passkey"

    let body = VerifyRequest(
      challengeId: challengeID,
      authenticationCredential: credential
    )

    return await postRequest(url: url, body: body, token: token)
  }
}
