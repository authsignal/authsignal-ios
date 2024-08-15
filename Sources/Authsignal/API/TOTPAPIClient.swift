import Foundation

class TOTPAPIClient: BaseAPIClient {
  func enrollTOTP(token: String) async -> AuthsignalResponse<EnrollTOTPResponse> {
    let url = "\(baseURL)/client/user-authenticators/totp"

    return await postRequest(url: url, token: token)
  }
  
  func verifyTOTP(
    token: String,
    code: String
  ) async -> AuthsignalResponse<VerifyResponse> {
    let url = "\(baseURL)/client/verify/totp"

    let body = VerifyRequest(verificationCode: code)

    return await postRequest(url: url, body: body, token: token)
  }
}
