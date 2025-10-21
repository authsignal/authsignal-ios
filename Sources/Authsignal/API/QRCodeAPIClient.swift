import Foundation

class QRCodeAPIClient: BaseAPIClient {
  func getCredential(publicKey: String) async -> AuthsignalResponse<CredentialResponse> {
    let encodedKey = Data(publicKey.utf8).base64URLEncodedString()

    let url = "\(baseURL)/client/user-authenticators/qr-code?publicKey=\(encodedKey)"

    return await getRequest(url: url)
  }

  func addCredential(
    token: String,
    publicKey: String,
    deviceName: String
  ) async -> AuthsignalResponse<AddCredentialResponse>
  {
    let url = "\(baseURL)/client/user-authenticators/qr-code"

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
    let url = "\(baseURL)/client/user-authenticators/qr-code/remove"

    let body = RemoveCredentialRequest(
      publicKey: publicKey,
      signature: signature
    )

    return await postRequest(url: url, body: body)
  }

  public func claimChallenge(
    challengeId: String,
    publicKey: String,
    signature: String
  ) async -> AuthsignalResponse<ClaimChallengeResponse> {
    let url = "\(baseURL)/client/user-authenticators/qr-code/challenge/claim"

    let body = ClaimChallengeRequest(
      challengeId: challengeId,
      publicKey: publicKey,
      signature: signature
    )

    return await postRequest(url: url, body: body)
  }

  public func updateChallenge(
    challengeId: String,
    publicKey: String,
    signature: String,
    approved: Bool,
    verificationCode: String?
  ) async -> AuthsignalResponse<UpdateChallengeResponse> {
    let url = "\(baseURL)/client/user-authenticators/qr-code/challenge"

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
