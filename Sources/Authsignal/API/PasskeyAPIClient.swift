import Foundation

class PasskeyAPIClient: BaseAPIClient {
  func registrationOptions(token: String, userName: String) async -> RegistrationOptsResponse? {
    let url = "\(baseURL)/user-authenticators/passkey/registration-options"
    let auth = "Bearer \(token)"

    let body = RegistrationOptsRequest(username: userName)

    return await postRequest(url: url, body: body, auth: auth)
  }

  func authenticationOptions(userName: String?) async -> AuthenticationOptsResponse? {
    let url = "\(baseURL)/device/passkey/authentication-options"

    let body = AuthenticationOptsRequest(username: userName)

    return await postRequest(url: url, body: body)
  }

  func addAuthenticator(
    token: String,
    challengeID: String,
    credential: PasskeyRegistrationCredential
  ) async -> AddAuthenticatorResponse? {
    let url = "\(baseURL)/user-authenticators/passkey"
    let auth = "Bearer \(token)"

    let body = AddAuthenticatorRequest(
      challengeId: challengeID,
      registrationCredential: credential
    )

    return await postRequest(url: url, body: body, auth: auth)
  }

  func verify(challengeID: String, credential: PasskeyAuthenticationCredential) async
    -> VerifyResponse?
  {
    let url = "\(baseURL)/device/passkey/verify"

    let body = VerifyRequest(
      challengeId: challengeID,
      authenticationCredential: credential
    )

    return await postRequest(url: url, body: body)
  }
}
