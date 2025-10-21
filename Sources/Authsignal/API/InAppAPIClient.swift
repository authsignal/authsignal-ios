import Foundation

class InAppAPIClient: BaseAPIClient {
  func getCredential(publicKey: String) async -> AuthsignalResponse<CredentialResponse> {
    let encodedKey = Data(publicKey.utf8).base64URLEncodedString()

    let url = "\(baseURL)/client/user-authenticators/in-app?publicKey=\(encodedKey)"

    return await getRequest(url: url)
  }

  func addCredential(
    token: String,
    publicKey: String,
    deviceName: String
  ) async -> AuthsignalResponse<AddCredentialResponse>
  {
    let url = "\(baseURL)/client/user-authenticators/in-app"

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
    let url = "\(baseURL)/client/user-authenticators/in-app/remove"

    let body = RemoveCredentialRequest(
      publicKey: publicKey,
      signature: signature
    )

    return await postRequest(url: url, body: body)
  }

  public func verify(
    challengeId: String,
    publicKey: String,
    signature: String,
    token: String?
  ) async -> AuthsignalResponse<InAppVerifyResponse> {
    let url = "\(baseURL)/client/verify/in-app"

    let body = InAppVerifyRequest(
      challengeId: challengeId,
      publicKey: publicKey,
      signature: signature
    )

    return await postRequest(url: url, body: body, token: token)
  }
} 
