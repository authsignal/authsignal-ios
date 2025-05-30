import Foundation

class DeviceAPIClient: BaseAPIClient {
  func getCredential(publicKey: String) async -> AuthsignalResponse<DeviceCredentialResponse> {
    let encodedKey = Data(publicKey.utf8).base64URLEncodedString()

    let url = "\(baseURL)/client/user-authenticators/device?publicKey=\(encodedKey)"

    return await getRequest(url: url)
  }

  func addCredential(
    token: String,
    publicKey: String,
    deviceName: String
  ) async -> AuthsignalResponse<AddDeviceCredentialResponse>
  {
    let url = "\(baseURL)/client/user-authenticators/device"

    let body = AddDeviceCredentialRequest(
      publicKey: publicKey,
      deviceName: deviceName,
      devicePlatform: "ios"
    )

    return await postRequest(url: url, body: body, token: token)
  }

  func removeCredential(
    publicKey: String,
    signature: String
  ) async -> AuthsignalResponse<RemoveDeviceCredentialResponse> {
    let url = "\(baseURL)/client/user-authenticators/device/remove"

    let body = RemoveDeviceCredentialRequest(
      publicKey: publicKey,
      signature: signature
    )

    return await postRequest(url: url, body: body)
  }

  public func getChallenge(publicKey: String) async -> AuthsignalResponse<DeviceChallengeResponse> {
    let encodedKey = Data(publicKey.utf8).base64URLEncodedString()

    let url = "\(baseURL)/client/user-authenticators/device/challenge?publicKey=\(encodedKey)"

    return await getRequest(url: url)
  }

  public func claimChallenge(
    challengeId: String,
    publicKey: String,
    signature: String
  ) async -> AuthsignalResponse<ClaimDeviceChallengeResponse> {
    let url = "\(baseURL)/client/user-authenticators/device/challenge/claim"

    let body = ClaimDeviceChallengeRequest(
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
  ) async -> AuthsignalResponse<UpdateDeviceChallengeResponse> {
    let url = "\(baseURL)/client/user-authenticators/device/challenge"

    let body = UpdateDeviceChallengeRequest(
      challengeId: challengeId,
      publicKey: publicKey,
      approved: approved,
      signature: signature,
      verificationCode: verificationCode
    )

    return await postRequest(url: url, body: body)
  }
} 