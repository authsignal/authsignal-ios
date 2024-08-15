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
    challengeID: String? = nil,
    token: String? = nil
  ) async -> AuthsignalResponse<AuthenticationOptsResponse> {
    let url = "\(baseURL)/client/user-authenticators/passkey/authentication-options"
  
    let body = AuthenticationOptsRequest(challengeId: challengeID)

    return await postRequest(url: url, body: body, token: token)
  }

  func addAuthenticator(
    challengeID: String,
    credential: PasskeyRegistrationCredential,
    token: String
  ) async -> AuthsignalResponse<AddPasskeyAuthenticatorResponse> {
    let url = "\(baseURL)/client/user-authenticators/passkey"

    let body = AddPasskeyAuthenticatorRequest(
      challengeId: challengeID,
      registrationCredential: credential
    )

    return await postRequest(url: url, body: body, token: token)
  }

  func verify(
    challengeID: String,
    credential: PasskeyAuthenticationCredential,
    token: String? = nil
  ) async -> AuthsignalResponse<VerifyPasskeyResponse> {
    let url = "\(baseURL)/client/verify/passkey"

    let body = VerifyPasskeyRequest(
      challengeId: challengeID,
      authenticationCredential: credential,
      deviceId: defaultDeviceID()
    )

    return await postRequest(url: url, body: body, token: token)
  }
  
  func getPasskeyAuthenticator(
    credentialID: String
  ) async -> AuthsignalResponse<PasskeyAuthenticatorResponse> {
    let url = "\(baseURL)/client/user-authenticators/passkey?credentialId=\(credentialID)"

    return await getRequest(url: url)
  }
}
