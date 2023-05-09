import Foundation

class PushAPIClient: BaseAPIClient {
  func getCredential(publicKey: String) async -> CredentialResponse? {
    let encodedKey = Data(publicKey.utf8).base64URLEncodedString()

    let url = "\(baseURL)/device/push/credential?publicKey=\(encodedKey)"

    return await getRequest(url: url)
  }

  func addCredential(accessToken: String, publicKey: String, deviceName: String) async
    -> AddCredentialResponse?
  {
    let url = "\(baseURL)/device/push/add-credential"
    let auth = "Bearer \(accessToken)"

    let body = AddCredentialRequest(
      publicKey: publicKey,
      deviceName: deviceName,
      devicePlatform: "ios"
    )

    return await postRequest(url: url, body: body, auth: auth)
  }

  func removeCredential(publicKey: String, signature: String) async -> RemoveCredentialResponse? {
    let url = "\(baseURL)/device/push/remove-credential"

    let body = RemoveCredentialRequest(
      publicKey: publicKey,
      signature: signature
    )

    return await postRequest(url: url, body: body)
  }

  public func getChallenge(publicKey: String) async -> ChallengeResponse? {
    let encodedKey = Data(publicKey.utf8).base64URLEncodedString()

    let url = "\(baseURL)/device/push/challenge?publicKey=\(encodedKey)"

    return await getRequest(url: url)
  }

  public func updateChallenge(
    challengeID: String,
    publicKey: String,
    signature: String,
    approved: Bool,
    verificationCode: String?
  ) async {
    let url = "\(baseURL)/device/push/update-challenge"

    let body = UpdateChallengeRequest(
      challengeId: challengeID,
      publicKey: publicKey,
      approved: approved,
      signature: signature,
      verificationCode: verificationCode
    )

    let _: UpdateChallengeResponse? = await postRequest(url: url, body: body)
  }
}
