import Foundation

class PushApiClient: BaseApiClient {
  func getCredential(publicKey: String) async -> AuthsignalResponse<CredentialResponse> {
    let encodedKey = Data(publicKey.utf8).base64URLEncodedString()

    let url = "\(baseUrl)/client/user-authenticators/push?publicKey=\(encodedKey)"

    return await getRequest(url: url)
  }

  func addCredential(
    token: String,
    publicKey: String,
    deviceName: String
  ) async -> AuthsignalResponse<AddCredentialResponse>
  {
    let url = "\(baseUrl)/client/user-authenticators/push"

    let body = AddCredentialRequest(
      publicKey: publicKey,
      deviceName: deviceName,
      devicePlatform: "ios"
    )

    return await postRequest(url: url, body: body, token: token)
  }

  func removeCredential(
    publicKey: String,
    signature: String
  ) async -> AuthsignalResponse<RemoveCredentialResponse> {
    let url = "\(baseUrl)/client/user-authenticators/push/remove"

    let body = RemoveCredentialRequest(
      publicKey: publicKey,
      signature: signature
    )

    return await postRequest(url: url, body: body)
  }

  public func getChallenge(publicKey: String) async -> AuthsignalResponse<PushChallengeResponse> {
    let encodedKey = Data(publicKey.utf8).base64URLEncodedString()

    let url = "\(baseUrl)/client/user-authenticators/push/challenge?publicKey=\(encodedKey)"

    return await getRequest(url: url)
  }

  public func updateChallenge(
    challengeId: String,
    publicKey: String,
    signature: String,
    approved: Bool,
    verificationCode: String?
  ) async -> AuthsignalResponse<UpdateChallengeResponse> {
    let url = "\(baseUrl)/client/user-authenticators/push/challenge"

    let body = UpdateChallengeRequest(
      challengeId: challengeId,
      publicKey: publicKey,
      approved: approved,
      signature: signature,
      verificationCode: verificationCode
    )

    return await postRequest(url: url, body: body)
  }
}
