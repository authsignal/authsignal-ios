import Foundation

class TotpApiClient: BaseApiClient {
  func enrollTotp(token: String) async -> AuthsignalResponse<EnrollTotpResponse> {
    let url = "\(baseUrl)/client/user-authenticators/totp"

    return await postRequest(url: url, token: token)
  }
  
  func verifyTotp(
    token: String,
    code: String
  ) async -> AuthsignalResponse<VerifyResponse> {
    let url = "\(baseUrl)/client/verify/totp"

    let body = VerifyRequest(verificationCode: code)

    return await postRequest(url: url, body: body, token: token)
  }
}
