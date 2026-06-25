import Foundation

class PushAPIClient: BaseAPIClient {
  func getCredential(publicKey: String) async -> AuthsignalResponse<CredentialResponse> {
    let encodedKey = Data(publicKey.utf8).base64URLEncodedString()

    let url = "\(baseURL)/client/user-authenticators/push?publicKey=\(encodedKey)"

    return await getRequest(url: url)
  }

  func addCredential(
    token: String,
    publicKey: String,
    deviceName: String,
    pushToken: String? = nil,
    performAttestation: AppAttestationResult? = nil
  ) async -> AuthsignalResponse<AddCredentialResponse>
  {
    let url = "\(baseURL)/client/user-authenticators/push"

    let body = AddCredentialRequest(
      publicKey: publicKey,
      deviceName: deviceName,
      devicePlatform: "ios",
      pushToken: pushToken,
      performAttestation: performAttestation
    )

    return await postRequest(url: url, body: body, token: token)
  }

  func removeCredential(
    publicKey: String,
    signature: String
  ) async -> AuthsignalResponse<RemoveCredentialResponse> {
    let url = "\(baseURL)/client/user-authenticators/push/remove"

    let body = RemoveCredentialRequest(
      publicKey: publicKey,
      signature: signature
    )

    return await postRequest(url: url, body: body)
  }

  public func getChallenge(
    publicKey: String,
    signature: String? = nil
  ) async -> AuthsignalResponse<PushChallengeResponse> {
    let encodedKey = Data(publicKey.utf8).base64URLEncodedString()

    let url = "\(baseURL)/client/user-authenticators/push/challenge?publicKey=\(encodedKey)"

    var headers: [String: String] = [:]

    if let signature = signature {
      headers["X-Authsignal-Signature"] = signature
    }

    return await getRequest(url: url, headers: headers)
  }

  public func getChallengeNonce(publicKey: String) async -> AuthsignalResponse<PushChallengeNonceResponse> {
    let encodedKey = Data(publicKey.utf8).base64URLEncodedString()

    let url = "\(baseURL)/client/user-authenticators/push/challenge/sign?publicKey=\(encodedKey)"

    return await postRequest(url: url)
  }

  public func getSigningMessage(publicKey: String) async -> AuthsignalResponse<SigningMessageResponse> {
    let encodedKey = Data(publicKey.utf8).base64URLEncodedString()

    let url = "\(baseURL)/client/user-authenticators/push/sign?publicKey=\(encodedKey)"

    return await postRequest(url: url)
  }

  public func updateCredential(
    challengeId: String,
    publicKey: String,
    signature: String,
    pushToken: String
  ) async -> AuthsignalResponse<UpdateCredentialResponse> {
    let url = "\(baseURL)/client/user-authenticators/push"

    let body = UpdateCredentialRequest(
      challengeId: challengeId,
      publicKey: publicKey,
      signature: signature,
      pushToken: pushToken
    )

    return await patchRequest(url: url, body: body)
  }

  public func updateChallenge(
    challengeId: String,
    publicKey: String,
    signature: String,
    approved: Bool,
    verificationCode: String?
  ) async -> AuthsignalResponse<UpdateChallengeResponse> {
    let url = "\(baseURL)/client/user-authenticators/push/challenge"

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
