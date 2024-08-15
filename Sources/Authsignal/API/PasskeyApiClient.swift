import Foundation

class PasskeyApiClient: BaseApiClient {
  func registrationOptions(
    token: String,
    userName: String? = nil,
    displayName: String? = nil
  ) async -> AuthsignalResponse<RegistrationOptsResponse> {
    let url = "\(baseUrl)/client/user-authenticators/passkey/registration-options"

    let body = RegistrationOptsRequest(username: userName, displayName: displayName)

    return await postRequest(url: url, body: body, token: token)
  }

  func authenticationOptions(
    challengeId: String? = nil,
    token: String? = nil
  ) async -> AuthsignalResponse<AuthenticationOptsResponse> {
    let url = "\(baseUrl)/client/user-authenticators/passkey/authentication-options"
  
    let body = AuthenticationOptsRequest(challengeId: challengeId)

    return await postRequest(url: url, body: body, token: token)
  }

  func addAuthenticator(
    challengeId: String,
    credential: PasskeyRegistrationCredential,
    token: String
  ) async -> AuthsignalResponse<AddPasskeyAuthenticatorResponse> {
    let url = "\(baseUrl)/client/user-authenticators/passkey"

    let body = AddPasskeyAuthenticatorRequest(
      challengeId: challengeId,
      registrationCredential: credential
    )

    return await postRequest(url: url, body: body, token: token)
  }

  func verify(
    challengeId: String,
    credential: PasskeyAuthenticationCredential,
    token: String? = nil
  ) async -> AuthsignalResponse<VerifyPasskeyResponse> {
    let url = "\(baseUrl)/client/verify/passkey"

    let body = VerifyPasskeyRequest(
      challengeId: challengeId,
      authenticationCredential: credential,
      deviceId: defaultDeviceId()
    )

    return await postRequest(url: url, body: body, token: token)
  }
  
  func getPasskeyAuthenticator(
    credentialId: String
  ) async -> AuthsignalResponse<PasskeyAuthenticatorResponse> {
    let url = "\(baseUrl)/client/user-authenticators/passkey?credentialId=\(credentialId)"

    return await getRequest(url: url)
  }
}
