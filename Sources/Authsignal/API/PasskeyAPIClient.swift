import Foundation

class PasskeyAPIClient: BaseAPIClient {
  func registrationOptions(
    token: String,
    username: String? = nil,
    displayName: String? = nil
  ) async -> AuthsignalResponse<RegistrationOptsResponse> {
    let url = "\(baseURL)/client/user-authenticators/passkey/registration-options"

    let body = RegistrationOptsRequest(username: username, displayName: displayName)

    return await postRequest(url: url, body: body, token: token)
  }

  func authenticationOptions(
    challengeId: String? = nil,
    token: String? = nil
  ) async -> AuthsignalResponse<AuthenticationOptsResponse> {
    let url = "\(baseURL)/client/user-authenticators/passkey/authentication-options"
  
    let body = AuthenticationOptsRequest(challengeId: challengeId)

    return await postRequest(url: url, body: body, token: token)
  }

  func addAuthenticator(
    challengeId: String,
    credential: PasskeyRegistrationCredential,
    token: String
  ) async -> AuthsignalResponse<AddPasskeyAuthenticatorResponse> {
    let url = "\(baseURL)/client/user-authenticators/passkey"

    let body = AddPasskeyAuthenticatorRequest(
      challengeId: challengeId,
      registrationCredential: credential,
      deviceId: defaultDeviceID()
    )

    return await postRequest(url: url, body: body, token: token)
  }

  func verify(
    challengeId: String,
    credential: PasskeyAuthenticationCredential,
    token: String? = nil
  ) async -> AuthsignalResponse<VerifyPasskeyResponse> {
    let url = "\(baseURL)/client/verify/passkey"

    let body = VerifyPasskeyRequest(
      challengeId: challengeId,
      authenticationCredential: credential,
      deviceId: defaultDeviceID()
    )

    return await postRequest(url: url, body: body, token: token)
  }
  
  func getPasskeyAuthenticator(
    credentialId: String
  ) async -> AuthsignalResponse<PasskeyAuthenticatorResponse> {
    let url = "\(baseURL)/client/user-authenticators/passkey?credentialId=\(credentialId)"

    return await getRequest(url: url)
  }
}
