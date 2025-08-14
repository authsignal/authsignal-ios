import Foundation

class WhatsAppAPIClient: BaseAPIClient {
  func challengeWhatsApp(
    token: String
  ) async -> AuthsignalResponse<ChallengeResponse> {
    let url = "\(baseURL)/client/challenge/whatsapp"

    return await postRequest(url: url, token: token)
  }

  func verifyWhatsApp(
    token: String,
    code: String
  ) async -> AuthsignalResponse<VerifyResponse> {
    let url = "\(baseURL)/client/verify/whatsapp"

    let body = VerifyRequest(verificationCode: code)

    return await postRequest(url: url, body: body, token: token)
  }
}
